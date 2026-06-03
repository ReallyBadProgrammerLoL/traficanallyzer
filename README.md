# Python NIDS/IPS

Упрощённый аналог Snort/Suricata на Python: перехват трафика, разбор пакетов,
сопоставление сигнатур (Aho-Corasick), детект сканирований и **реальная
блокировка** через NFQUEUE — всё управляется из веб-интерфейса.

Запускается на localhost как пентест-утилита, без Docker и виртуалок. По
умолчанию работает в **безопасном режиме мониторинга** (firewall не трогается);
блокировку оператор включает вручную для выбранного интерфейса.

---

## Возможности

- **Перехват трафика** живьём (Scapy `AsyncSniffer`) или из pcap-файла.
- **Разбор пакетов** в плоскую структуру (IP/TCP/UDP/ICMP).
- **Сигнатуры** в Snort-синтаксисе: заголовки + контент. Все content-паттерны
  компилируются в один автомат Aho-Corasick → один проход по payload на пакет.
- **Stateful-детект** сканов: горизонтальный (host sweep) и вертикальный
  (port scan) с дедупликацией — один алерт на скан, а не на каждый SYN.
- **Correlation / автоблок**: когда источник пересекает порог (вертикальный скан
  одного хоста, свип многих хостов или просто поток «пустых» SYN), он уходит в
  карантин на N секунд — и **весь** его последующий трафик роняется (sid 2003),
  а не только SYN. То есть первые N запросов это предупреждение, остальные
  блокируются. Как и любой drop, гейтится режимом: protect → `blocked`,
  monitor → `would-block`. Пороги (окно, порог скана/свипа/флуда, cooldown,
  длительность карантина) настраиваются на вкладке **Scan** и хранятся в
  `scan.json`. Каждый заблокированный пакет логируется на вкладке Alerts —
  enforcement-вердикты (`blocked`/`would-block`) не глушатся дедупом.
- **Глубокий анализ (DPI) DNS**: эвристика поверх разбора DNS — ловит туннели/C2
  по подозрительным командам (`powershell`, `certutil`, `/bin/sh`, `-enc`…),
  аномально длинным меткам и base64-блобам в qname/TXT даже без фиксированной
  сигнатуры. Срабатывание роняет пакет (`drop`, sid 3001). Все эвристики
  (токены, порог длины метки, base64, свои regex по qname/TXT/payload)
  настраиваются из вкладки **DPI** и хранятся в `dpi.json`.
- **Инлайн-IPS**: пакеты идут через NFQUEUE, движок выносит вердикт
  accept/drop — то есть `drop`-правило реально роняет соединение.
- **Две модели безопасности**:
  - `allow` — пропускать неизвестный трафик (поведение Snort/IDS);
  - `deny` — блокировать всё, что не разрешено `pass`-правилом (firewall/allowlist).
- **Веб-консоль**: живые алерты и весь трафик (SSE), редактор правил, выбор
  интерфейса/подсети/политики, переключатель защиты, счётчики.
- **Внутренности пакета по клику**: любая строка (алерт или прошедший трафик)
  разворачивается в hex-дамп + расшифровку (DNS-запрос с qname/qtype/TXT,
  первая строка HTTP, поля заголовков).

---

## Архитектура

```
                 ┌── monitor: AsyncSniffer ──┐
   трафик ──►    │                           ├─► decoder ─► Engine.process ─► вердикт
                 └── protect: NFQUEUE+iptables┘                  │
                                                                 ├─► Alerter ─► stdout / alerts.json / Hub(/stream)
                                                                 └─► traffic Hub (/traffic)
```

| Файл            | Роль |
|-----------------|------|
| `app.py`        | Точка входа живого NIDS/IPS (веб-консоль). |
| `controller.py` | Переключение режимов monitor ⇄ protect, владеет всем. |
| `engine.py`     | Вердикт по пакету: pass/drop/alert + политика allow/deny. |
| `decoder.py`    | Scapy-пакет → dict. |
| `rule_parser.py`| Парсер правил + `RuleStore` (редактирование/валидация). |
| `detector.py`   | Сигнатуры через Aho-Corasick. |
| `analyzer.py`   | Stateful-детект сканов + correlation-автоблок; пороги в `ScanStore` (scan.json). |
| `dpi.py`        | DPI DNS: эвристика туннелей/C2 + конфиг `DPIStore` (dpi.json). |
| `dissect.py`    | Hex-дамп + лёгкий разбор протоколов (DNS/HTTP) для деталей. |
| `firewall.py`   | Управление правилами iptables NFQUEUE. |
| `inline.py`     | Чтение пакетов из NFQUEUE, accept/drop. |
| `alerting.py`   | Сборка записей, throttle, sinks, Hub (pub/sub + история). |
| `web.py`        | Flask: REST API + SSE-потоки. |
| `templates/index.html` | Дашборд (вкладки Alerts / Traffic / Rules / DPI / Scan / Settings). |
| `simulate.py`   | Генератор атак реальными сокетами. |
| `netns.sh`      | Поднять/снести изолированную демо-сеть (veth + namespace). |
| `main.py`       | Оффлайн-анализ pcap / консольный мониторинг. |

---

## Библиотеки для запуска

Питоновские зависимости (`requirements.txt`) — какой модуль каждую использует:

| Библиотека        | Версия    | Зачем нужна | Где используется |
|-------------------|-----------|-------------|------------------|
| `scapy`           | `>=2.5`   | захват и разбор пакетов | `sniffer.py`, `decoder.py`, `inline.py` |
| `pyahocorasick`   | `>=2.0`   | один проход Aho-Corasick по payload для всех content-сигнатур | `detector.py` |
| `flask`           | `>=3.0`   | веб-консоль: REST API + SSE-потоки | `web.py` |
| `NetfilterQueue`  | `>=1.1`   | чтение пакетов из NFQUEUE для инлайн-блокировки | `inline.py` |

Системно нужны Python 3, `iptables` и ядро с поддержкой NFQUEUE (только для
режима Protect). Стандартная библиотека (`socket`, `subprocess`, `threading`,
`json`, `argparse`) — для генерации трафика, управления firewall и точек входа.

---

## Установка

Требуется Python 3, `iptables`, и (для блокировки) ядро с поддержкой NFQUEUE.
На Arch/CachyOS `scapy`/`pyahocorasick` обычно ставятся системно — venv создаётся
с `--system-site-packages`, чтобы их видеть.

```sh
./install.sh
```

`netfilterqueue` лучше иметь системно (тогда его видит root под sudo):

```sh
sudo pip install --break-system-packages netfilterqueue
```

> Если `netfilterqueue` стоит только в `~/.local`, `start.sh` сам пробросит его
> в окружение root через `PYTHONPATH` — отдельных действий не нужно.

---

## Запуск

```sh
./start.sh                 # дашборд на http://127.0.0.1:8080
./start.sh --port 9000     # любые флаги app.py пробрасываются
```

Один скрипт: при первом запуске создаёт venv и ставит зависимости, затем
поднимает консоль под root. На старте режим **idle** — захват пакетов не идёт
вообще, сеть не трогается. Оператор сам включает в интерфейсе либо **Monitor**
(пассивный сниффер, только алерты), либо **Protection** (инлайн-блокировка).

---

## Интерфейс

- **Alerts** — только события безопасности: `blocked`, `would-block`,
  `alerted`, `default-deny`. С цветовой меткой вердикта, сигнатурой, SID.
- **Traffic** — *каждый* пакет, прошедший через движок, с его вердиктом.
  Фильтр по вердикту, пауза, очистка, счётчик. Удобно показать, что `pass`-трафик
  ходит, а заблокированный — нет.
- **Клик по строке** (в Alerts и Traffic) разворачивает детали пакета: hex-дамп
  payload и человекочитаемую расшифровку. Повторный клик сворачивает.
- **Rules** — редактор правил. Save & reload валидирует и перезагружает движок
  на лету; ошибки парсинга подсвечиваются и файл не перезаписывается.
- **DPI** — настройка глубокого анализа. Токены и base64-детект работают по
  payload **любого** протокола (не только DNS); порог длины метки и цели
  `qname`/`txt` — DNS-специфичные. Поля: тумблер DPI, порог длины метки,
  детект base64, список командных токенов (+/−) и свои regex-правила
  (regex + цель qname/txt/payload + msg + sid). Save & reload валидирует,
  пишет `dpi.json` и перезагружает инспектор на лету.
- **Settings** — интерфейс (scope), HOME_NET, политика для неизвестного трафика.

Вердикты:

| Вердикт         | Что значит |
|-----------------|------------|
| `passed`        | пропущен (нет совпадений в allow-режиме, либо `pass`-правило). |
| `alerted`       | пропущен, но помечен сигнатурой/детектом. |
| `would-block`   | сработало `drop`/deny, но защита выключена (предпросмотр). |
| `blocked`       | дропнут `drop`-правилом (защита включена). |
| `default-deny`  | дропнут политикой deny (нет разрешающего `pass`). |

> Счётчик **passed** растёт только при включённой защите: в режиме monitor движок
> ничего не пропускает «по-настоящему», поэтому пропущенное там не считается.

---

## Режимы и политика

- **Idle** (по умолчанию): захват не идёт, ни одного пакета не обрабатывается,
  firewall не трогается. Безопасный старт.
- **Monitor**: пассивный сниффер, только алерты, firewall не трогается.
  `drop`-правила и DPI показываются как `would-block`. Включается тумблером Monitor.
- **Protect**: трафик идёт инлайн через NFQUEUE, `drop`/deny/DPI реально роняют
  пакеты. Включается тумблером Protection (с `--queue-bypass` → при падении
  процесса трафик идёт мимо, сеть не виснет).

> Monitor и Protection — это уровень *enforcement*, общий для всего движка:
> сигнатуры, детект сканов и DPI одинаково показываются `would-block` в Monitor
> и `blocked` в Protect. DPI не работает «в обход» этого переключателя.

- **Политика allow** — это и есть Snort: трафик без совпадений проходит, работают
  только сигнатуры.
- **Политика deny** — firewall поверх IDS: проходит только то, что разрешено
  `pass`-правилом, остальное дропается. ⚠ На боевом интерфейсе с включённой
  защитой это оборвёт сеть — используйте только в изолированной подсети
  (`lo` / `veth`).

---

## Синтаксис правил

```
action proto src_ip src_port -> dst_ip dst_port (options)
```

Действия: `drop` (блок), `alert` (пропустить + сигнал), `pass` (whitelist), `log`.

```
# контент-сигнатура
alert tcp any any -> any 389 (msg:"LDAP Enumeration"; content:"LDAP"; sid:1004;)
# hex-контент
alert tcp any any -> any 445 (msg:"SMB Null Session"; content:"|00 00 00 00|"; sid:1003;)
# блокировка
drop udp any any -> any 53 (msg:"BLOCK DNS Evil"; content:"evil"; sid:9002;)
# allowlist для HTTP (обе стороны соединения)
pass tcp any any -> any 8080 (msg:"allow http request"; sid:8000;)
pass tcp any 8080 -> any any (msg:"allow http response"; sid:8001;)
```

Сканы (sweep/port scan) ловятся stateful в `analyzer.py`, поэтому per-SYN правил
в `rules.txt` намеренно нет — они дают только шум.

---

## Демонстрация

### A. Loopback (быстро, без настройки сети)

```sh
python simulate.py connect --port 445   # refused  →  TIMEOUT после включения защиты
python simulate.py dns-evil             # DNS-запрос с "evil" → дропается (sid 9002)
python simulate.py dns-tunnel           # DNS TXT с командой/base64 → DPI дропает (sid 3001)
python simulate.py port-scan            # вертикальный скан → один алерт
python simulate.py sweep                # горизонтальный скан → один алерт
```

В Settings: iface `lo`, HOME_NET `127.0.0.0/8`. Включить Monitor (только алерты)
или Protection (реальная блокировка) тумблером в шапке.

### B. Изолированная подсеть через network namespace (реалистично)

Вся настройка сети — одним скриптом:

```sh
sudo ./netns.sh up        # создаёт testns + veth0/veth1, раздаёт IP
sudo ./netns.sh attack    # прогон всех атак изнутри namespace по хосту
sudo ./netns.sh down      # снести демо-сеть
```

В Settings: iface `veth0`, HOME_NET `10.0.0.0/24`, включить Protection (тумблер
в шапке). Хост
владеет `10.0.0.1`, «жертва» в namespace — `10.0.0.2`. Трафик хост ↔ namespace
идёт через INPUT/OUTPUT интерфейса `veth0` — это ровно те цепочки, которыми
управляет `firewall.py` (FORWARD не задействуется, поэтому правил для него не
нужно).

Отдельные атаки изнутри namespace, если нужно вручную:

```sh
sudo ip netns exec testns python simulate.py sweep --target 10.0.0.1
sudo ip netns exec testns python simulate.py connect --target 10.0.0.1 --port 445
```

Демо allowlist (политика deny): поднять сервис на хосте, добавить `pass`-правила
для 8080 и показать, что без них curl из namespace висит, а с ними — проходит:

```sh
python -m http.server 8080 --bind 10.0.0.1
sudo ip netns exec testns curl --max-time 3 http://10.0.0.1:8080
```

Очистка:

```sh
sudo ip netns delete testns
sudo ip link delete veth0 2>/dev/null
```

> `ping -I veth0 10.0.0.2` идёт через OUTPUT/INPUT (хост — владелец IP), а не
> FORWARD. Цепочку FORWARD задействует только маршрутизация между двумя
> namespace’ами — для текущей схемы она не нужна.

---

## Оффлайн-анализ pcap

Без root, вердикты в консоль и `alerts.json`:

```sh
./run.sh --pcap attack.pcap                 # в консоль
./run.sh --pcap attack.pcap --web           # + дашборд (вкладки Alerts/Traffic)
```

---

## Безопасность

- Старт в режиме **idle** — захват не идёт, защита выключена, сеть не трогается.
- NFQUEUE ставится с `--queue-bypass` (fail-open).
- Все правила iptables снимаются при выключении защиты и при выходе (`atexit`).
- HOME_NET ограничивает анализ нужной подсетью.
- Политику `deny` применять только к изолированному интерфейсу.

---

## Troubleshooting

- **`ModuleNotFoundError: netfilterqueue` под sudo** — пакет стоит в `~/.local`
  (per-user), root его не видит. Поставьте системно
  (`sudo pip install --break-system-packages netfilterqueue`) или используйте
  `start.sh` (он пробрасывает путь сам).
- **Вкладка Traffic пустует** — на старте режим idle, захвата нет: включите
  Monitor или Protection. Если уже включено — проверьте, что HOME_NET включает
  вашу подсеть, иначе трафик отфильтровывается до записи.
- **Блокировка «не блокирует»** — убедитесь, что включён Protection и выбран
  правильный интерфейс (scope).
- **fish shell**: запускайте скрипты как `./start.sh` (shebang `bash`).
