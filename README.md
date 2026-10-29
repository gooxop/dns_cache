@'
# DNS-cache

Итеративный DNS-сервер с кешем. Запросы и ответы формируются вручную, без сторонних DNS-библиотек.

## Запуск

    python3 dns_cache.py                  # 127.0.0.1:53 (нужен root/sudo)
    python3 dns_cache.py --port 5353      # без root
    python3 dns_cache.py -v               # подробный лог

## Проверка

    dig example.com @127.0.0.1
    dig example.com MX @127.0.0.1
    dig +tcp example.com @127.0.0.1
    dig 2.22.multiply.test.com @127.0.0.1     # -> 127.0.0.44

На Windows: `dig example.com "@127.0.0.1"` (кавычки обязательны).

## Что умеет

- Итеративный опрос от корневых серверов
- Много клиентов одновременно (поток на запрос)
- Кеш с учётом TTL, в т.ч. отрицательный (NXDOMAIN / NODATA)
- Кеш сохраняется в файл и не теряется при перезапуске
- Работа по UDP и TCP
- Типы записей: A, AAAA, NS, CNAME, SOA, MX, TXT, PTR, SRV, ANY
- `.multiply.` — отвечает сам, без похода в сеть