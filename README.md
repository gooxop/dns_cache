@'
# DNS-cache

Итеративный DNS-резолвер с кешем. Ручное формирование пакетов DNS (без `dnspython`).

## Запуск

    sudo python3 dns_cache.py             # 127.0.0.1:53
    python3 dns_cache.py --port 5353      # без root
    python3 dns_cache.py -v               # подробный лог

## Проверка

    dig example.com @127.0.0.1
    dig example.com MX @127.0.0.1
    dig 2.22.multiply.test.com @127.0.0.1   # -> 127.0.0.44
    dig +tcp example.com @127.0.0.1

## Возможности

- Итеративный опрос от корневых серверов (13 root-серверов)
- Многопоточная обработка (поток на запрос)
- Кеш ответов и делегирований с учётом TTL, включая отрицательный (NXDOMAIN/NODATA по SOA)
- Персистентность кеша в JSON (атомарная запись)
- UDP + TCP, повтор по TCP при TC=1
- Поддержка A, AAAA, NS, CNAME, SOA, MX, TXT, PTR, SRV, ANY
- `.multiply.` — локальный ответ без похода в сеть
'@ | Set-Content -Encoding utf8 README.md