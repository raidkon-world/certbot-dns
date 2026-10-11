# Документация certbot-dns

Утилита `certbot-dns` выпускает и продлевает сертификаты Let's Encrypt методом **DNS-01**, управляя TXT-записями через один или несколько DNS-провайдеров (**FastVPS FastDNS**, **Alibaba Cloud DNS**). Опционально зеркалирует записи зоны с master на slave-провайдеры или из BIND `.zone` файла.

## Содержание

1. [Требования](#требования)
2. [Установка](#установка)
3. [Конфигурация](#конфигурация)
4. [Разбор доменов и каталоги](#разбор-доменов-и-каталоги)
5. [DNS-01 и провайдеры](#dns-01-и-провайдеры)
6. [Синхронизация зон (sync)](#синхронизация-зон-sync)
7. [Продление и режим daemon](#продление-и-режим-daemon)
8. [Чекпоинт выпуска](#чекпоинт-выпуска)
9. [Docker](#docker)
10. [Логирование](#логирование)
11. [Тесты](#тесты)
12. [Устранение неполадок](#устранение-неполадок)

## Требования

- Go 1.25+ (или Docker)
- Учётные данные хотя бы одного поддерживаемого DNS-провайдера
- Домены, делегированные в DNS, куда пишутся TXT для DNS-01
- Контактный email для регистрации ACME

| Провайдер | Что нужно |
|-----------|-----------|
| `fastdns` | API-токен FastVPS FastDNS |
| `alibabacloud` | Access Key ID + Secret (AliDNS), при необходимости `region_id` |

## Установка

### install.sh (рекомендуется, Linux + systemd)

```bash
curl -fsSL https://github.com/raidkon/certbot-dns/raw/master/install.sh -o get-certbot-dns.sh
sudo sh ./get-certbot-dns.sh --dry-run
sudo sh ./get-certbot-dns.sh
```

Скрипт загружает tar.gz из GitHub Release (бинарник, `certbot-dns.service`, `config.example.toml`, `env.example`, `example.com.zone`), создаёт пользователя `certbot-dns`, каталог `/var/lib/certbot-dns` и включает systemd-сервис в режиме **daemon**.

```bash
sudo cp /etc/certbot-dns/config.example.toml /etc/certbot-dns/config.toml   # при первой установке
sudo nano /etc/certbot-dns/config.toml
sudo nano /etc/certbot-dns/env
sudo systemctl restart certbot-dns
journalctl -u certbot-dns -f
```

Опции: `--version v1.0.0`, `--no-start`. Удаление: `uninstall.sh` (`--purge`).

### Из исходников

```bash
git clone https://github.com/raidkon/certbot-dns.git
cd certbot-dns
sudo cp config.example.toml /etc/certbot-dns/config.toml

export FASTDNS_API_TOKEN="ваш-токен"

cd src
go test ./...
go build -o certbot-dns .
./certbot-dns -config /etc/certbot-dns/config.toml
```

По умолчанию конфиг: `/etc/certbot-dns/config.toml`.

## Конфигурация

Полный пример — [`config.example.toml`](../config.example.toml). Для systemd после установки — [`packaging/config.example.toml`](../packaging/config.example.toml).

Секреты удобно держать в `/etc/certbot-dns/env` (см. `packaging/env.example`): `FASTDNS_API_TOKEN`, `ALIBABA_ACCESS_KEY_ID`, `ALIBABA_ACCESS_KEY_SECRET`, опционально `ALIBABA_REGION_ID`.

### Секция `[acme]`

| Параметр | Описание |
|----------|----------|
| `email` | Email ACME-аккаунта (обязателен) |
| `directory` | `production` — боевой LE; `staging` — тестовый каталог |
| `state_dir` | Каталог для `account.key` и `registration.json` (по умолчанию `.acme-state`) |
| `user_agent` | Необязательно; по умолчанию `certbot-dns/1` |

### Блоки `[[providers]]`

Именованные DNS-провайдеры. Имя (`name`) указывается в `[[certificates]].provider` и в `[sync]`.

| `type` | Поля |
|--------|------|
| `fastdns` | `api_token`, необязательно `api_url` |
| `alibabacloud` | `access_key_id`, `access_key_secret`, необязательно `region_id` |

Алиасы типа: `alidns`, `ali-dns`, `alicloud`.

**Обратная совместимость:** секция `[fastdns]` без `[[providers]]` создаёт провайдер `name = "default"`. Если `provider` в сертификате не указан, используется `default`.

Пример двух провайдеров:

```toml
[[providers]]
name = "fv-main"
type = "fastdns"
api_token = "${FASTDNS_API_TOKEN}"

[[providers]]
name = "ali-dns"
type = "alibabacloud"
access_key_id = "${ALIBABA_ACCESS_KEY_ID}"
access_key_secret = "${ALIBABA_ACCESS_KEY_SECRET}"
region_id = "${ALIBABA_REGION_ID}"
```

### Секция `[dns_challenge]`

| Параметр | Описание |
|----------|----------|
| `propagation_timeout` | Максимальное ожидание появления TXT в DNS (например `24h`) |
| `propagation_interval` | Пауза между проверками (например `10m`) |
| `recursive_resolvers` | Список `host:port` для pre-check TXT; если не задан — `8.8.8.8:53` и `1.1.1.1:53` |

Явные резолверы нужны в закрытых сетях. Не полагайтесь только на `127.0.0.53` (systemd-resolved).

### Блоки `[[certificates]]`

| Параметр | Описание |
|----------|----------|
| `id` | Метка для логов (необязательно) |
| `provider` | **Строка или массив** имён из `[[providers]]` — TXT для DNS-01 создаётся **во всех** перечисленных провайдерах (по умолчанию `default`) |
| `domains` | Список имён; см. [разбор доменов](#разбор-доменов-и-каталоги) |
| `output_dir` | Базовый каталог для выпусков этого блока |
| `key_type` | `ec256`, `ec384`, `rsa2048`, … (по умолчанию `ec256`) |
| `renew_before_days` | За сколько дней до `NotAfter` перевыпускать (по умолчанию `25`) |

```toml
[[certificates]]
id = "sites"
provider = ["fv-main"]
domains = ["*.example.com"]
output_dir = "/var/lib/certbot-dns/certs/sites"
```

Поле `zone` в конфиге **не используется**: apex-зона выводится автоматически (последние две метки FQDN).

### Секция `[sync]`

| Параметр | Описание |
|----------|----------|
| `enabled` | `true` — зеркалировать записи master → slaves (после прохода ACME в том же цикле) |
| `interval` | **`onstart`** (по умолчанию) — sync один раз при старте процесса; или длительность (`5m`) — повторять sync в daemon и ограничивать паузу сна |
| `record_types` | Какие типы копировать (по умолчанию A, AAAA, CNAME, MX, TXT, NS, SRV) |
| `exclude_names` | Glob; по умолчанию `_acme-challenge` и `_acme-challenge.*` (TXT ACME на slaves не затираются) |

Блок `[[sync.zones]]`:

| Поле | Описание |
|------|----------|
| `zone` | Apex-зона (например `example.com`) |
| `master` | Имя провайдера из `[[providers]]` **или** `file:///etc/certbot-dns/example.com.zone` |
| `slaves` | Список имён провайдеров, куда применить `SetRecords` |

Файл master — BIND `.zone` (как экспорт FastDNS). `$ORIGIN` должен совпадать с `zone`. Пример в репозитории: [`packaging/example.com.zone`](../packaging/example.com.zone).

### Секция `[runtime]`

| Параметр | Описание |
|----------|----------|
| `mode` | `once` — один проход и выход; `daemon` — бесконечный цикл |
| `poll_when_ok` | В daemon: максимальная пауза, если все сертификаты свежие (например `24h`) |
| `loglevel` | `debug`, `verbose`, `info`, `warning`, `error`, `fatal` |

Переменные окружения подставляются в строки конфига через `${VAR}`.

## Разбор доменов и каталоги

Один блок `[[certificates]]` с несколькими именами в `domains` может превратиться в **несколько** отдельных сертификатов.

### Wildcard

- `*.example.com` → SAN: `*.example.com` и `example.com`
- Каталог: `{output_dir}/wc-example-com/`
- Зона DNS: `example.com`

### Одиночный apex

- `example.com` без подходящего wildcard → отдельный сертификат, каталог `apex-example-com/`

### Поддомен на один уровень под wildcard

- При `*.example.com` имя `www.example.com` попадает в ту же wildcard-группу

### Структура файлов на диске

```
output_dir/wc-example-com/
  live -> 2026-05-22
  2026-05-22/
    fullchain.pem
    privkey.pem
    issuer.pem
  .obtain-checkpoint.json
```

Чтение: сначала `live/fullchain.pem`, иначе legacy `fullchain.pem` в корне `output_dir`.

## DNS-01 и провайдеры

Перед выпуском для каждой пары (провайдер, зона) вызывается `GetRecords` — проверка учётных данных.

### Общее поведение

1. При нескольких провайдерах в `provider` TXT создаётся и удаляется **на каждом** из них (один ACME-заказ).
2. **FastDNS:** перед `Present` удаляются старые TXT с тем же именем; challenges обрабатываются **последовательно** (ограничение API).
3. **Alibaba Cloud DNS:** стандартный libdns-провайдер без специальной очистки FastDNS.

Имя зоны в API: для `host.example.com` → `example.com` (последние две метки). Для `co.uk` эвристика может быть неточной.

## Синхронизация зон (sync)

При `sync.enabled = true` после ACME (в том же цикле) для каждого `[[sync.zones]]`:

1. Читаются записи master (API или `.zone` файл).
2. Фильтруются по `record_types` и `exclude_names`.
3. На каждом slave вызывается `SetRecords`: зона приводится к master + **сохраняются** исключённые записи slave (например `_acme-challenge`).

**Внимание:** `SetRecords` перезаписывает зону на slave (кроме исключений). Проверяйте на staging или с `enabled = false` до уверенности в конфиге.

Пример master из файла (после установки из tar.gz):

```toml
[sync]
enabled = true
interval = "onstart"

[[sync.zones]]
zone = "example.com"
master = "file:///etc/certbot-dns/example.com.zone"
slaves = ["ali-dns"]
```

## Продление и режим daemon

### Режим `once`

Один проход: проверка сроков, выпуск, sync (если включён), выход `0`.

```cron
0 3 * * * /usr/local/bin/certbot-dns -config /etc/certbot-dns/config.toml
```

### Режим `daemon`

Цикл: ACME → sync (по правилам `interval`) → сон до ближайшего продления (не дольше `poll_when_ok`; при `interval = 5m` сон также ограничен 5 минутами).

Перевыпуск: нет `fullchain` **или** время ≥ `NotAfter - renew_before_days`.

## Чекпоинт выпуска

Файл `.obtain-checkpoint.json` в каталоге выпуска:

- URI заказа ACME
- ID TXT (`challenge_key|имя_провайдера` при нескольких провайдерах)
- PEM закрытого ключа

При следующем запуске выпуск продолжается с того же заказа. После успеха файл удаляется. При смене `domains` — новый заказ.

## Docker

См. [README.md](../README.md#docker). В `config.docker.example.toml` — пути под volume `/var/lib/certbot-dns`.

## Логирование

| Уровень | Назначение |
|---------|------------|
| `debug` | Максимум деталей + file:line |
| `verbose` | Как debug без file:line |
| `info` | Штатная работа |
| `warning` / `error` | Предупреждения и ошибки |
| `fatal` | Критические сообщения и выход |

## Тесты

```bash
cd src && go test ./...
cd src && go test ./... -cover
```

Покрывают конфиг, провайдеры, разбор domains, zone-файлы, sync, DNS solver group.

## Устранение неполадок

### Зона недоступна через API

Проверьте учётные данные провайдера, делегирование домена и имя зоны (лог `проверка зоны DNS`).

### AppendRecords / пустая ошибка (FastDNS)

Лимит «одна TXT на имя» или старые `_acme-challenge`. Утилита очищает конфликты перед `Present`; проверьте панель DNS.

### Sync испортил зону на slave

Отключите `sync.enabled`, восстановите зону из backup. Перед включением сверьте master и `exclude_names`.

### TXT не распространяется

Увеличьте `propagation_timeout`, задайте `recursive_resolvers`.

### Staging vs production

`directory = "staging"` для первых тестов.

### Коды выхода

| Код | Причина |
|-----|---------|
| `0` | Успех (`once`) |
| `1` | Ошибка выпуска, зоны, sync или цикла daemon |
| `2` | Ошибка конфигурации |

---

English: [docs/en.md](en.md) · другие языки: [docs/README.md](README.md)
