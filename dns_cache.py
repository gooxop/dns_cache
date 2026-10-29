import argparse
import json
import logging
import os
import random
import secrets
import signal
import socket
import socketserver
import struct
import sys
import threading
import time
from dataclasses import dataclass, field, replace

log = logging.getLogger("dns-cache")

#  Константы
T_A, T_NS, T_CNAME, T_SOA, T_PTR, T_MX, T_TXT, T_AAAA, T_OPT = 1, 2, 5, 6, 12, 15, 16, 28, 41
T_IXFR, T_AXFR, T_ANY = 251, 252, 255
C_IN = 1
NOERROR, FORMERR, SERVFAIL, NXDOMAIN, NOTIMP, REFUSED = 0, 1, 2, 3, 4, 5

TYPE_NAMES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
              28: "AAAA", 33: "SRV", 41: "OPT", 255: "ANY"}
RCODE_NAMES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}

# Корневые серверы (IPv4), https://root-servers.org/
ROOT_SERVERS = [
    "198.41.0.4",      # a.root-servers.net
    "170.247.170.2",   # b
    "192.33.4.12",     # c
    "199.7.91.13",     # d
    "192.203.230.10",  # e
    "192.5.5.241",     # f
    "192.112.36.4",    # g
    "198.97.190.53",   # h
    "192.36.148.17",   # i
    "192.58.128.30",   # j
    "193.0.14.129",    # k
    "199.7.83.42",     # l
    "202.12.27.33",    # m
]

MAX_UDP_PAYLOAD = 1232        # размер, который мы объявляем и не превышаем в UDP-ответах
UPSTREAM_TIMEOUT = 2.0        # таймаут одного обращения к вышестоящему серверу, сек
RESOLVE_DEADLINE = 10.0       # общий лимит времени на один клиентский запрос, сек
MAX_UPSTREAM_QUERIES = 60     # лимит запросов "наверх" на один клиентский запрос
MAX_REFERRALS = 16            # максимум переходов по делегированиям
MAX_DEPTH = 8                 # вложенность (CNAME / поиск адресов NS без glue)
SERVERS_PER_STEP = 4          # сколько серверов зоны пробуем на одном шаге
MAX_CACHE_TTL = 24 * 3600
NEGATIVE_DEFAULT_TTL = 30     # если в отрицательном ответе нет SOA
MAX_CACHE_ENTRIES = 50000
SAVE_INTERVAL = 30            # как часто (сек) сбрасывать кеш на диск
TCP_IDLE_TIMEOUT = 10.0

# Типы, чьё RDATA состоит из одного доменного имени / начинается с имён.
SINGLE_NAME_TYPES = {2, 3, 4, 5, 7, 8, 9, 12}   # NS, MD, MF, CNAME, MB, MG, MR, PTR


#  Имена: кортеж меток (bytes). Регистр сохраняем, сравниваем через lower().
def lower(name):
    return tuple(l.lower() for l in name)


def name_to_str(name):
    return ".".join(l.decode("latin-1") for l in name) or "."


def name_from_str(s):
    s = s.strip(".")
    return tuple(s.encode("utf-8").split(b".")) if s else ()


def is_under(name, zone):
    """name лежит в зоне zone (или равен ей)."""
    return len(name) >= len(zone) and name[len(name) - len(zone):] == zone


#  Разбор сообщений
class ParseError(Exception):
    pass


@dataclass
class RR:
    name: tuple
    type: int
    cls: int
    ttl: int
    rdata: bytes          # RDATA, в котором имена развёрнуты (без сжатия)


@dataclass
class Message:
    id: int = 0
    flags: int = 0
    questions: list = field(default_factory=list)   # (name, type, class), регистр как в запросе
    answers: list = field(default_factory=list)
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)

    qr = property(lambda s: (s.flags >> 15) & 1)
    opcode = property(lambda s: (s.flags >> 11) & 0xF)
    aa = property(lambda s: (s.flags >> 10) & 1)
    tc = property(lambda s: (s.flags >> 9) & 1)
    rd = property(lambda s: (s.flags >> 8) & 1)
    rcode = property(lambda s: s.flags & 0xF)


@dataclass
class Result:
    rcode: int
    answers: list
    authority: list
    cached: bool = False


def read_name(data, off):
    """Читает имя (с поддержкой сжатия). Возвращает (метки, смещение_после_имени)."""
    labels, end, hops, total = [], None, 0, 0
    while True:
        if off >= len(data):
            raise ParseError("имя выходит за границы пакета")
        n = data[off]
        if n == 0:
            off += 1
            break
        kind = n & 0xC0
        if kind == 0xC0:
            if off + 1 >= len(data):
                raise ParseError("обрезанный указатель")
            if end is None:
                end = off + 2
            off = ((n & 0x3F) << 8) | data[off + 1]
            hops += 1
            if hops > 64:
                raise ParseError("петля в указателях сжатия")
        elif kind == 0:
            off += 1
            if off + n > len(data):
                raise ParseError("метка выходит за границы пакета")
            labels.append(bytes(data[off:off + n]))
            off += n
            total += n + 1
            if total > 254:
                raise ParseError("слишком длинное имя")
        else:
            raise ParseError("неподдерживаемый тип метки")
    return tuple(labels), (end if end is not None else off)


def encode_name_plain(labels):
    return b"".join(bytes([len(l)]) + l for l in labels) + b"\x00"


def expand_rdata(data, off, end, rtype):
    """Возвращает RDATA, в котором сжатые имена заменены полными."""
    if rtype in SINGLE_NAME_TYPES:
        labels, p = read_name(data, off)
        if p != end:
            raise ParseError("неверная длина RDATA")
        return encode_name_plain(labels)
    if rtype == T_MX:
        if end - off < 3:
            raise ParseError("короткий MX")
        labels, p = read_name(data, off + 2)
        if p != end:
            raise ParseError("неверная длина RDATA")
        return bytes(data[off:off + 2]) + encode_name_plain(labels)
    if rtype == T_SOA:
        mname, p = read_name(data, off)
        rname, p = read_name(data, p)
        if end - p != 20:
            raise ParseError("неверная длина SOA")
        return encode_name_plain(mname) + encode_name_plain(rname) + bytes(data[p:end])
    return bytes(data[off:end])


def read_rr(data, off):
    name, off = read_name(data, off)
    if off + 10 > len(data):
        raise ParseError("обрезанная запись")
    rtype, rcls, ttl, rdlen = struct.unpack_from("!HHIH", data, off)
    off += 10
    end = off + rdlen
    if end > len(data):
        raise ParseError("RDATA выходит за границы пакета")
    if ttl & 0x80000000:          # RFC 2181: старший бит => TTL считаем нулевым
        ttl = 0
    return RR(lower(name), rtype, rcls, ttl, expand_rdata(data, off, end, rtype)), end


def parse_message(data):
    if len(data) < 12:
        raise ParseError("короткий заголовок")
    mid, flags, qd, an, ns, ar = struct.unpack_from("!6H", data, 0)
    msg = Message(mid, flags)
    off = 12
    try:
        for _ in range(qd):
            name, off = read_name(data, off)
            if off + 4 > len(data):
                raise ParseError("обрезанный вопрос")
            qtype, qcls = struct.unpack_from("!HH", data, off)
            off += 4
            msg.questions.append((name, qtype, qcls))
        for section, count in ((msg.answers, an), (msg.authority, ns), (msg.additional, ar)):
            for _ in range(count):
                rr, off = read_rr(data, off)
                section.append(rr)
    except ParseError:
        if not (flags & 0x0200):      # усечённый (TC) ответ разбираем "сколько получится"
            raise
    return msg


#  Формирование сообщений
class Writer:
    """Буфер с поддержкой сжатия имён (указатели на ранее записанные суффиксы)."""

    def __init__(self):
        self.buf = bytearray()
        self.ptrs = {}

    def name(self, labels):
        for i in range(len(labels)):
            key = lower(labels[i:])
            ptr = self.ptrs.get(key)
            if ptr is not None:
                self.buf += struct.pack("!H", 0xC000 | ptr)
                return
            if len(self.buf) < 0x3FFF:
                self.ptrs[key] = len(self.buf)
            self.buf.append(len(labels[i]))
            self.buf += labels[i]
        self.buf.append(0)


def write_rdata(w, rr):
    t, d = rr.type, rr.rdata
    if t in SINGLE_NAME_TYPES:
        w.name(read_name(d, 0)[0])
    elif t == T_MX:
        w.buf += d[:2]
        w.name(read_name(d, 2)[0])
    elif t == T_SOA:
        mname, p = read_name(d, 0)
        rname, p = read_name(d, p)
        w.name(mname)
        w.name(rname)
        w.buf += d[p:]
    else:
        w.buf += d


def write_rr(w, rr):
    w.name(rr.name)
    w.buf += struct.pack("!HHI", rr.type, rr.cls, rr.ttl)
    lenpos = len(w.buf)
    w.buf += b"\x00\x00"
    write_rdata(w, rr)
    struct.pack_into("!H", w.buf, lenpos, len(w.buf) - lenpos - 2)


def build_query(qid, name, qtype):
    """Итеративный запрос (RD=0) с EDNS0, чтобы ответы по UDP были до ~1232 байт."""
    w = Writer()
    w.buf += struct.pack("!6H", qid, 0, 1, 0, 0, 1)
    w.name(name)
    w.buf += struct.pack("!HH", qtype, C_IN)
    w.buf += b"\x00" + struct.pack("!HHIH", T_OPT, MAX_UDP_PAYLOAD, 0, 0)
    return bytes(w.buf)


def build_response(q, rcode, answers=(), authority=(), limit=None, edns=False):
    """Ответ клиенту. Если не влезает в limit байт - TC=1 и пустые секции."""
    def encode(ans, auth, tc):
        w = Writer()
        flags = 0x8000 | (q.opcode << 11) | (q.flags & 0x0110) | 0x0080 | (0x0200 if tc else 0) | rcode
        w.buf += struct.pack("!6H", q.id, flags, len(q.questions), len(ans), len(auth), 1 if edns else 0)
        for name, qtype, qcls in q.questions:
            w.name(name)
            w.buf += struct.pack("!HH", qtype, qcls)
        for rr in list(ans) + list(auth):
            write_rr(w, rr)
        if edns:
            w.buf += b"\x00" + struct.pack("!HHIH", T_OPT, MAX_UDP_PAYLOAD, 0, 0)
        return bytes(w.buf)

    wire = encode(answers, authority, False)
    if limit is not None and len(wire) > limit:
        wire = encode([], [], True)
    return wire


def build_formerr(data):
    if len(data) < 2:
        return None
    return data[:2] + struct.pack("!HHHHH", 0x8000 | FORMERR, 0, 0, 0, 0)


def soa_minimum(rr):
    _, p = read_name(rr.rdata, 0)
    _, p = read_name(rr.rdata, p)
    return struct.unpack_from("!I", rr.rdata, p + 16)[0]


def rdata_name(rr):
    return lower(read_name(rr.rdata, 0)[0])


#  Сетевой обмен с вышестоящими серверами
def recv_exact(sock, n):
    chunks = []
    while n:
        chunk = sock.recv(n)
        if not chunk:
            raise ConnectionError("соединение закрыто")
        chunks.append(chunk)
        n -= len(chunk)
    return b"".join(chunks)


def reply_matches(msg, qid, qkey):
    if not msg.qr or msg.id != qid:
        return False
    if msg.questions:
        name, qtype, qcls = msg.questions[0]
        return (lower(name), qtype, qcls) == qkey
    return True


def udp_exchange(ip, port, wire, qid, qkey, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(wire, (ip, port))
        end = time.monotonic() + timeout
        while True:
            left = end - time.monotonic()
            if left <= 0:
                return None
            sock.settimeout(left)
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                return None
            if addr[0] != ip or addr[1] != port:
                continue
            try:
                msg = parse_message(data)
            except ParseError:
                continue
            if reply_matches(msg, qid, qkey):
                return msg
    finally:
        sock.close()


def tcp_exchange(ip, port, wire, qid, qkey, timeout):
    with socket.create_connection((ip, port), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(struct.pack("!H", len(wire)) + wire)
        (n,) = struct.unpack("!H", recv_exact(sock, 2))
        msg = parse_message(recv_exact(sock, n))
    return msg if reply_matches(msg, qid, qkey) else None


class Budget:
    """Ограничение времени и числа запросов на один запрос."""

    def __init__(self):
        self.deadline = time.monotonic() + RESOLVE_DEADLINE
        self.left = MAX_UPSTREAM_QUERIES

    def remaining(self):
        return self.deadline - time.monotonic()

    def take(self):
        if self.left <= 0 or self.remaining() < 0.1:
            return False
        self.left -= 1
        return True


#  Кеш (ответы + делегирования) с сохранением на диск
@dataclass
class Entry:
    rcode: int
    answers: list
    authority: list
    stored: float
    expire: float


def result_ttl(res):
    ttls = [rr.ttl for rr in res.answers]
    if not res.answers or res.rcode == NXDOMAIN:
        soa = [rr.ttl for rr in res.authority if rr.type == T_SOA]
        ttls += soa or [NEGATIVE_DEFAULT_TTL]
    return min(ttls) if ttls else 0


def _rr_dump(rr):
    return [[l.hex() for l in rr.name], rr.type, rr.cls, rr.ttl, rr.rdata.hex()]


def _rr_load(x):
    return RR(tuple(bytes.fromhex(l) for l in x[0]), x[1], x[2], x[3], bytes.fromhex(x[4]))


class Cache:
    def __init__(self, path=None):
        self.path = path
        self.lock = threading.Lock()
        self.entries = {}        # (name, qtype) -> Entry
        self.delegations = {}    # zone -> (expire, [ip, ...])
        self.dirty = False

    # ответы
    def get(self, name, qtype):
        now = time.time()
        with self.lock:
            e = self.entries.get((name, qtype))
            if e is None:
                return None
            if e.expire <= now:
                del self.entries[(name, qtype)]
                self.dirty = True
                return None
        elapsed = int(now - e.stored)

        def aged(rr):                      # TTL уменьшается по мере "старения" записи
            return replace(rr, ttl=max(1, rr.ttl - elapsed))
        return Result(e.rcode, [aged(r) for r in e.answers], [aged(r) for r in e.authority], True)

    def put(self, name, qtype, res):
        ttl = min(result_ttl(res), MAX_CACHE_TTL)
        if ttl <= 0:
            return
        now = time.time()
        with self.lock:
            if len(self.entries) >= MAX_CACHE_ENTRIES:
                self._evict(now)
            self.entries[(name, qtype)] = Entry(res.rcode, res.answers, res.authority, now, now + ttl)
            self.dirty = True

    def _evict(self, now):
        for k in [k for k, e in self.entries.items() if e.expire <= now]:
            del self.entries[k]
        if len(self.entries) >= MAX_CACHE_ENTRIES:
            oldest = sorted(self.entries, key=lambda k: self.entries[k].stored)
            for k in oldest[:MAX_CACHE_ENTRIES // 10]:
                del self.entries[k]

    # делегирования (кто отвечает за зону)
    def get_delegation(self, name):
        now = time.time()
        with self.lock:
            for i in range(len(name)):            # от самого длинного суффикса к самому короткому
                zone = name[i:]
                d = self.delegations.get(zone)
                if d is not None:
                    if d[0] > now:
                        return zone, list(d[1])
                    del self.delegations[zone]
        return (), []

    def put_delegation(self, zone, ips, ttl):
        ttl = min(ttl, MAX_CACHE_TTL)
        if ttl <= 0 or not ips:
            return
        with self.lock:
            self.delegations[zone] = (time.time() + ttl, list(ips))
            self.dirty = True

    # сохранение
    def save(self):
        if not self.path:
            return
        now = time.time()
        with self.lock:
            self._evict_expired(now)
            data = {
                "version": 1,
                "entries": [
                    {"name": [l.hex() for l in k[0]], "qtype": k[1], "rcode": e.rcode,
                     "stored": e.stored, "expire": e.expire,
                     "answers": [_rr_dump(r) for r in e.answers],
                     "authority": [_rr_dump(r) for r in e.authority]}
                    for k, e in self.entries.items()],
                "delegations": [{"zone": [l.hex() for l in z], "expire": d[0], "ips": d[1]}
                                for z, d in self.delegations.items()],
            }
            self.dirty = False
        tmp = self.path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, self.path)          # атомарно: файл не бывает "наполовину записан"
            log.info("кеш сохранён: %d записей, %d делегирований", len(data["entries"]), len(data["delegations"]))
        except OSError as e:
            log.warning("не удалось сохранить кеш: %s", e)

    def _evict_expired(self, now):
        for k in [k for k, e in self.entries.items() if e.expire <= now]:
            del self.entries[k]
        for z in [z for z, d in self.delegations.items() if d[0] <= now]:
            del self.delegations[z]

    def load(self):
        if not self.path or not os.path.exists(self.path):
            return
        try:
            with open(self.path) as f:
                data = json.load(f)
            now = time.time()
            for x in data.get("entries", []):
                if x["expire"] <= now:
                    continue
                key = (tuple(bytes.fromhex(l) for l in x["name"]), x["qtype"])
                self.entries[key] = Entry(x["rcode"], [_rr_load(r) for r in x["answers"]],
                                          [_rr_load(r) for r in x["authority"]], x["stored"], x["expire"])
            for x in data.get("delegations", []):
                if x["expire"] > now:
                    self.delegations[tuple(bytes.fromhex(l) for l in x["zone"])] = (x["expire"], x["ips"])
            log.info("кеш загружен: %d записей, %d делегирований", len(self.entries), len(self.delegations))
        except (OSError, ValueError, KeyError, TypeError, IndexError) as e:
            log.warning("кеш повреждён, начинаем с пустого: %s", e)
            self.entries.clear()
            self.delegations.clear()


#  Итеративный резолвер
FINAL, REFERRAL, BAD = "final", "referral", "bad"


def walk_answers(answers, name, qtype):
    """Идём по цепочке CNAME внутри одного ответа. -> (цепочка, последнее_имя, найдено_ли_целевое)"""
    chain, seen = [], set()
    while name not in seen:
        seen.add(name)
        hit = [r for r in answers if r.name == name and (r.type == qtype or qtype == T_ANY)]
        if hit:
            return chain + hit, name, True
        cn = [r for r in answers if r.name == name and r.type == T_CNAME]
        if not cn or qtype == T_CNAME:
            break
        chain.append(cn[0])
        name = rdata_name(cn[0])
    return chain, name, False


def classify(msg, name, zone):
    if any(r.name == name for r in msg.answers):
        return FINAL
    has_soa = any(r.type == T_SOA for r in msg.authority)
    if msg.rcode == NXDOMAIN:
        # без AA - типичная подделка перехватчиков DNS
        return FINAL if (msg.aa or has_soa) else BAD
    if has_soa:
        return FINAL                                   # NODATA
    for r in msg.authority:
        if r.type == T_NS and is_under(name, r.name) and len(r.name) > len(zone):
            return REFERRAL
    return FINAL if msg.aa else BAD


def soa_authority(msg):
    return [replace(r, ttl=min(r.ttl, soa_minimum(r))) for r in msg.authority if r.type == T_SOA]


class Resolver:
    def __init__(self, cache, roots=None, upstream_port=53):
        self.cache = cache
        self.roots = list(roots or ROOT_SERVERS)
        self.port = upstream_port

    # публичный вход
    def resolve(self, name, qtype, budget, depth=0):
        cached = self.cache.get(name, qtype)
        if cached is not None:
            return cached
        if depth > MAX_DEPTH:
            return Result(SERVFAIL, [], [])
        msg = self._iterate(name, qtype, budget, depth)
        if msg is None:
            return Result(SERVFAIL, [], [])

        chain, last, done = walk_answers(msg.answers, name, qtype)
        if done:
            res = Result(NOERROR, chain, [])
        elif msg.rcode == NXDOMAIN:
            res = Result(NXDOMAIN, chain, soa_authority(msg))
        elif chain:
            # цепочка CNAME уходит за пределы этого ответа
            sub = self.resolve(last, qtype, budget, depth + 1)
            if sub.rcode == SERVFAIL:
                return sub
            res = Result(sub.rcode, chain + sub.answers, sub.authority)
        else:
            res = Result(NOERROR, [], soa_authority(msg))      # NODATA
        self.cache.put(name, qtype, res)
        return res

    # спуск по делегированиям
    def _iterate(self, name, qtype, budget, depth):
        zone, servers = self.cache.get_delegation(name)
        starts = []
        if zone:
            starts.append((zone, servers))
        starts.append(((), list(self.roots)))          # запасной вариант - всегда можно начать с корня
        for zone, servers in starts:
            for _ in range(MAX_REFERRALS):
                nxt = None
                for msg in self._ask(servers, name, qtype, budget):
                    kind = classify(msg, name, zone)
                    if kind == FINAL:
                        return msg
                    if kind == REFERRAL:
                        nxt = self._follow_referral(msg, name, zone, budget, depth)
                        if nxt:
                            break
                if nxt is None:
                    break
                zone, servers = nxt
        return None

    def _ask(self, servers, name, qtype, budget):
        order = list(servers)
        random.shuffle(order)
        for ip in order[:SERVERS_PER_STEP]:
            msg = self._exchange(ip, name, qtype, budget)
            if msg is not None:
                yield msg

    def _exchange(self, ip, name, qtype, budget):
        if not budget.take():
            return None
        qid = secrets.randbits(16)
        wire = build_query(qid, name, qtype)
        qkey = (name, qtype, C_IN)
        timeout = max(0.1, min(UPSTREAM_TIMEOUT, budget.remaining()))
        try:
            msg = udp_exchange(ip, self.port, wire, qid, qkey, timeout)
            if msg is not None and msg.tc:
                log.debug("TC от %s, повторяем по TCP", ip)
                msg = tcp_exchange(ip, self.port, wire, qid, qkey, timeout)
        except (OSError, ParseError) as e:
            log.debug("ошибка обмена с %s: %s", ip, e)
            return None
        if msg is None or msg.rcode not in (NOERROR, NXDOMAIN):
            return None
        log.debug("%s <- %s %s %s", name_to_str(name), ip, TYPE_NAMES.get(qtype, qtype), RCODE_NAMES.get(msg.rcode))
        return msg

    def _follow_referral(self, msg, name, zone, budget, depth):
        ns_rrs = [r for r in msg.authority
                  if r.type == T_NS and is_under(name, r.name) and len(r.name) > len(zone)]
        if not ns_rrs:
            return None
        new_zone = ns_rrs[0].name
        ns_rrs = [r for r in ns_rrs if r.name == new_zone]
        ns_names = [rdata_name(r) for r in ns_rrs]

        ips = []
        for r in msg.additional:                      # glue
            if r.type == T_A and len(r.rdata) == 4 and r.name in ns_names:
                ip = socket.inet_ntoa(r.rdata)
                if ip not in ips:
                    ips.append(ip)
        if not ips:                                   # glue нет - ищем адреса NS сами
            shuffled = ns_names[:]
            random.shuffle(shuffled)
            for ns in shuffled[:4]:
                sub = self.resolve(ns, T_A, budget, depth + 1)
                for r in sub.answers:
                    if r.type == T_A and len(r.rdata) == 4:
                        ip = socket.inet_ntoa(r.rdata)
                        if ip not in ips:
                            ips.append(ip)
                if len(ips) >= 2:
                    break
        if not ips:
            return None
        self.cache.put_delegation(new_zone, ips, min(r.ttl for r in ns_rrs))
        return new_zone, ips


#  ".multiply." - считаем сами
def multiply_answer(name):
    """2.22.multiply.test.com -> 44. Берутся числа, стоящие непосредственно перед меткой multiply."""
    for i in range(1, len(name)):
        if name[i] == b"multiply":
            j, result = i, 1
            while j > 0 and name[j - 1].isdigit():     # bytes.isdigit(): только ASCII-цифры
                j -= 1
                result = (result * int(name[j])) % 256
            if j != i:
                return result
    return None


#  Обработка клиентских запросов
class App:
    def __init__(self, resolver):
        self.resolver = resolver

    def handle(self, data, tcp, client):
        """Никогда не бросает исключений: в худшем случае вернёт SERVFAIL (или None для мусора)."""
        try:
            return self._handle(data, tcp, client)
        except Exception:
            log.exception("внутренняя ошибка при обработке запроса от %s", client)
            try:
                return build_response(parse_message(data), SERVFAIL, limit=None)
            except Exception:
                return None

    def _handle(self, data, tcp, client):
        t0 = time.monotonic()
        try:
            q = parse_message(data)
        except ParseError as e:
            log.info("%s: некорректный пакет (%s) -> FORMERR", client, e)
            return build_formerr(data)
        if q.qr:
            return None                                # это не запрос, а чей-то ответ - игнорируем

        opt = next((r for r in q.additional if r.type == T_OPT), None)
        limit = 65535 if tcp else (max(512, min(opt.cls, MAX_UDP_PAYLOAD)) if opt else 512)

        def reply(rcode, answers=(), authority=()):
            return build_response(q, rcode, answers, authority, limit, opt is not None)

        if q.opcode != 0:
            return reply(NOTIMP)
        if len(q.questions) != 1:
            return reply(FORMERR)
        qname_orig, qtype, qcls = q.questions[0]
        if qcls != C_IN or qtype in (T_AXFR, T_IXFR, T_OPT):
            return reply(REFUSED)

        name = lower(qname_orig)
        label = f"{client[0]} {name_to_str(name)} {TYPE_NAMES.get(qtype, qtype)}"

        mult = multiply_answer(name)
        if mult is not None:
            answers = [RR(name, T_A, C_IN, 60, bytes([127, 0, 0, mult]))] if qtype in (T_A, T_ANY) else []
            log.info("%s -> NOERROR [multiply 127.0.0.%d]", label, mult)
            return reply(NOERROR, answers)

        res = self.resolver.resolve(name, qtype, Budget())
        log.info("%s -> %s%s %d зап. (%.0f мс)", label, RCODE_NAMES.get(res.rcode, res.rcode),
                 " [кеш]" if res.cached else "", len(res.answers), (time.monotonic() - t0) * 1000)
        return reply(res.rcode, res.answers, res.authority)


class UDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        resp = self.server.app.handle(data, False, self.client_address)
        if resp:
            try:
                sock.sendto(resp, self.client_address)
            except OSError as e:
                log.debug("не удалось отправить ответ %s: %s", self.client_address, e)


class TCPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        sock = self.request
        sock.settimeout(TCP_IDLE_TIMEOUT)
        try:
            while True:                                 # на одном соединении может быть несколько запросов
                (n,) = struct.unpack("!H", recv_exact(sock, 2))
                data = recv_exact(sock, n)
                resp = self.server.app.handle(data, True, self.client_address)
                if resp is None:
                    return
                sock.sendall(struct.pack("!H", len(resp)) + resp)
        except (OSError, struct.error):
            pass


class ThreadingUDP(socketserver.ThreadingUDPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_packet_size = 65535


class ThreadingTCP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 128


#  main
def main():
    ap = argparse.ArgumentParser(description="Итеративный DNS-сервер с кешем")
    ap.add_argument("--host", default="127.0.0.1", help="адрес для прослушивания (по умолчанию 127.0.0.1)")
    ap.add_argument("--port", type=int, default=53, help="порт UDP и TCP (по умолчанию 53)")
    ap.add_argument("--cache-file", default="dns_cache.json", help="файл для сохранения кеша ('' - не сохранять)")
    ap.add_argument("--root", action="append", metavar="IP", help="корневой сервер; можно несколько раз")
    ap.add_argument("--upstream-port", type=int, default=53, help="порт вышестоящих серверов (для тестов)")
    ap.add_argument("-v", "--verbose", action="store_true", help="подробный лог")
    args = ap.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")

    cache = Cache(args.cache_file or None)
    cache.load()
    app = App(Resolver(cache, args.root, args.upstream_port))

    try:
        udp = ThreadingUDP((args.host, args.port), UDPHandler)
        tcp = ThreadingTCP((args.host, args.port), TCPHandler)
    except PermissionError:
        sys.exit(f"Нет прав на порт {args.port}. Запустите через sudo или выберите другой порт (--port 5353).")
    except OSError as e:
        sys.exit(f"Не удалось занять {args.host}:{args.port}: {e}")
    udp.app = tcp.app = app

    stop = threading.Event()
    for srv in (udp, tcp):
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def autosave():
        while not stop.wait(SAVE_INTERVAL):
            if cache.dirty:
                cache.save()
    threading.Thread(target=autosave, daemon=True).start()

    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(sig, lambda *_: stop.set())
        except (ValueError, OSError):
            pass

    log.info("слушаю %s:%d (UDP+TCP), корневых серверов: %d", args.host, args.port, len(app.resolver.roots))
    try:
        while not stop.wait(0.5):
            pass
    except KeyboardInterrupt:
        pass
    log.info("останавливаюсь...")
    udp.shutdown()
    tcp.shutdown()
    cache.save()


if __name__ == "__main__":
    main()