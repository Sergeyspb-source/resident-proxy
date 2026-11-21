# exitnode

[English version](README.en.md)

Прокси, который выходит в интернет с чужого домашнего компьютера. Владелец
компьютера запускает агент, вы получаете ключ и ходите через его адрес.

```
клиент → шлюз (VPS) → агент (ПК) → сайт
```

Шлюз нужен только для связи: он не видит, куда именно вы идёте. Компьютер
агента не открывает портов наружу — он сам подключается к шлюзу.

---

## Из чего состоит

| Команда | Где работает | Что делает |
|---|---|---|
| `relay` | VPS с публичным адресом | принимает агентов и клиентов, сводит их вместе |
| `agent` | компьютер-выход | держит соединение со шлюзом и выпускает трафик в интернет |
| `client` | компьютер пользователя | поднимает локальный SOCKS5 и HTTP-прокси |
| `hop` | промежуточный VPS | пробрасывает порт на второй шлюз |
| `setup` | Windows и Linux | установка, автозапуск, ярлыки, удаление |

Версия: **0.0.23**. Клиент и агент начиная с 0.0.20 должны быть одной волны —
внутри они договариваются по TLS 1.3.

---

## Быстрый старт

### 1. Шлюз на VPS

Нужен домен, указывающий на VPS, и сертификат (например, Let's Encrypt).

```bash
exitnode relay \
  -socks 0.0.0.0:2084 \
  -tunnel :2083 \
  -cert /etc/exitnode/tls/fullchain.pem \
  -key /etc/exitnode/tls/privkey.pem \
  -socks-tls \
  -token-file /etc/exitnode/token \
  -ui 127.0.0.1:17880
```

Токен — случайная строка не короче 32 символов, общая для шлюза и агентов.

Юнит systemd:

```ini
[Unit]
Description=exitnode relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=exitnode
Group=exitnode
ExecStart=/opt/exitnode/exitnode relay -socks 0.0.0.0:2084 -tunnel :2083 \
  -cert /etc/exitnode/tls/fullchain.pem -key /etc/exitnode/tls/privkey.pem \
  -socks-tls -token-file /etc/exitnode/token -ui 127.0.0.1:17880
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 2. Агент на компьютере-выходе

Windows:

```
proxy.exe agent -relay proxy.example.com:2083 -token-file %LOCALAPPDATA%\exitnode\token.txt ^
  -name "Дом" -public-socks proxy.example.com:2084
```

Linux, одной командой с автозапуском:

```bash
./exitnode setup --systemd --invite agent.exitnode
```

или без приглашения:

```bash
./exitnode setup --systemd --relay proxy.example.com:2083 \
  --token-file ./token --public-socks proxy.example.com:2084 --name "Дом"
```

Служба ставится в `~/.config/systemd/user`, включается и переживает перезагрузку.

### 3. Клиент у пользователя

Windows: запустить `proxy.exe client`, вставить ключ или открыть файл
приглашения. Клиент живёт в трее, окно можно закрывать.

Linux:

```bash
./exitnode client -ui
```

Появляется иконка в области уведомлений с меню: открыть панель,
запустить/остановить, выход.

### 4. Проверка

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me/ip
```

Адрес должен быть адресом компьютера-выхода.

---

## Порты

| Порт | Где | Назначение |
|---|---|---|
| 2083 | шлюз | агенты, TLS |
| 2084 | шлюз | клиенты, SOCKS5 поверх TLS |
| 17880 | шлюз | панель шлюза, только 127.0.0.1 |
| 17890 | агент | панель агента, только 127.0.0.1 |
| 1080 | клиент | локальный SOCKS5 |
| 8080 | клиент | локальный HTTP-прокси для системных настроек Windows |
| 17893 | клиент | окно клиента, только 127.0.0.1 |

Если 1080 занят (например, Xray), клиент берёт следующий свободный в диапазоне
1080–1099 и показывает его в окне.

---

## Ключи и лимиты

Ключ — это пароль. Он даёт доступ к узлу, поэтому пересылать его нужно
файлом приглашения `.exitnode`, а не текстом в чате.

Владелец агента в панели «Пользователи» задаёт для каждого ключа:

- **Домены** — если список пуст, разрешено всё; иначе только эти сайты и их поддомены.
- **Квота в сутки** и **в месяц** — при исчерпании активные соединения обрываются,
  новые отклоняются. `0` — без лимита.
- **Скорость** — общий потолок в КБ/с на загрузку и отдачу по всем соединениям ключа.

Изменения действуют сразу, перезапуск не нужен.

---

## Безопасность

- Шлюз общается с агентами и клиентами по TLS 1.3.
- Клиент отправляет шлюзу `sha256` ключа и фиктивный адрес `e2e.invalid`.
  Куда идти на самом деле, знает только агент.
- Поверх этого клиент и агент поднимают собственный TLS 1.3 с взаимной
  проверкой полным ключом. Шлюз видит объём и время, но не сайты и не содержимое.
- Хеш ключа для шлюза — идентификатор маршрута, а не пропуск: без полного ключа
  соединение до агента не установится.
- Панели слушают только `127.0.0.1`. Снаружи — через SSH-туннель.
- Шлюз открыт в интернет, поэтому на нём стоят лимиты и баны (см. ниже).

---

## Защита шлюза

Готовые файлы — в `deploy/`:

```bash
apt-get install -y fail2ban
install -m 644 deploy/fail2ban-exitnode.conf  /etc/fail2ban/filter.d/exitnode.conf
install -m 644 deploy/fail2ban-exitnode.local /etc/fail2ban/jail.d/exitnode.local
install -m 644 deploy/exitnode-guard.nft      /etc/exitnode/guard.nft
install -m 644 deploy/exitnode-guard.service  /etc/systemd/system/exitnode-guard.service
systemctl daemon-reload
systemctl enable --now exitnode-guard fail2ban
```

- **fail2ban** читает журнал шлюза и банит IP на 30 минут после 12 неудач
  за 10 минут. Бан закрывает только 2083 и 2084.
- **exitnode-guard** ограничивает новые соединения: 900 в минуту и 400
  одновременно с одного IP на 2084, 30 в минуту на 2083.

---

## Панели

**Панель агента** (`127.0.0.1:17890`) — три вкладки: обзор с графиком,
пользователи с ключами и лимитами, настройки с автозапуском.

**Панель шлюза** (`127.0.0.1:17880`) — подключённые узлы, активные сессии,
текущая скорость и расход по каждому узлу.

С домашнего компьютера к панели шлюза подключаются туннелем:

```bash
ssh -L 17880:127.0.0.1:17880 root@VPS
```

и открывают `http://127.0.0.1:17880/`.

---

## Второй хоп

Если нужно скрыть адрес клиента и от шлюза, между ними ставят промежуточный VPS:

```bash
exitnode hop -listen 0.0.0.0:2084 -target 203.0.113.10:2084 -max-conns 512
```

Клиент указывает адрес промежуточного VPS, а имя в сертификате оставляет
от конечного:

```bash
exitnode client -server VPS1:2084 -server-name proxy.example.com -tls -key-file key.txt
```

TLS клиента заканчивается на конечном шлюзе, промежуточный видит только
шифротекст.

---

## Обновления

Панель проверяет последний релиз через `/api/update`. Манифест `update.json`
(версия и sha256 файлов) подписан ed25519, публичный ключ вшит в программу
(`internal/update/pubkey.go`). Если подписи нет, версия показывается красным
с пометкой «подпись не проверена».

Выпуск новой версии:

```bash
go run ./cmd/sign -key release-key.json -version 0.0.24 -dir bin ^
  -files exitnode-agent.exe,exitnode-client.exe,exitnode-linux
gh release create v0.0.24 bin/exitnode-agent.exe bin/exitnode-client.exe ^
  bin/exitnode-linux bin/update.json
```

Приватный ключ хранится вне репозитория. Потеряете — подписать новые релизы
будет нечем.

---

## Установка и удаление

`exitnode setup` умеет:

| Флаг | Что делает |
|---|---|
| `--agent` / `--client` | установка на Windows |
| `--invite FILE` | взять адрес и ключ из приглашения |
| `--systemd` | Linux: служба с автозапуском |
| `--desktop` | Linux: ярлык в меню и связь с `.exitnode` |
| `--relay`, `--token-file`, `--public-socks`, `--name` | параметры узла без приглашения |
| `--uninstall` | удалить программу и службу |

Удаление на Linux: `./exitnode setup --uninstall`. Ключи и состояние остаются
в `~/.cache/exitnode`.

---

## Где что лежит

| Что | Windows | Linux |
|---|---|---|
| Токен агента | `%LOCALAPPDATA%\exitnode\token.txt` | `~/.config/exitnode/agent.json` |
| Настройки клиента | `%LOCALAPPDATA%\exitnode\client.json` | `~/.cache/exitnode/client.json` |
| Ключи агента | `%LOCALAPPDATA%\exitnode` | `~/.cache/exitnode` |
| Резервная копия прокси | `%LOCALAPPDATA%\exitnode\sysproxy.json` | — |

---

## Если что-то не работает

**Агент не подключается.** Проверьте, что с компьютера открывается
`proxy.example.com:2083` и токен совпадает с шлюзом.

**Клиент пишет «неизвестный ключ».** Ключ удалён или принадлежит агенту,
который сейчас офлайн.

**Страницы не открываются, а спидтест работает.** Обычно это доменные
ограничения ключа или исчерпанная квота — смотрите панель агента.

**Порт 1080 занят.** Клиент возьмёт 1081–1099 и покажет порт в окне.

**Системный прокси Windows не подхватился.** Chrome и Edge берут настройку
сами, Firefox нужно переключить на «системные настройки прокси».

---

## Разработка

```bash
go build ./...
go vet ./...
go test ./...
```

Сборка релиза:

```bash
go build -ldflags "-H=windowsgui -s -w" -o bin/proxy.exe ./cmd/proxy
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/exitnode-linux ./cmd/proxy
```

Версия задаётся в `internal/buildinfo/version.go`.
