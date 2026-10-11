# certbot-dns

Утилита на Go для автоматического выпуска и продления TLS-сертификатов Let's Encrypt через **DNS-01** с именованными DNS-провайдерами (**FastVPS FastDNS**, **Alibaba Cloud DNS**) и опциональным зеркалированием зон.

Один TOML-конфиг описывает несколько групп доменов (wildcard и apex), режим однократного запуска или демона, чекпоинты при обрыве выпуска и версионирование сертификатов на диске.

## Документация

Полные руководства: **English**, **Русский**. Остальные языки — краткие страницы со ссылками на них ([индекс всех языков](docs/README.md)).

| Язык | Файл |
|------|------|
| English | [docs/en.md](docs/en.md) |
| Русский | [docs/ru.md](docs/ru.md) |
| Deutsch | [docs/de.md](docs/de.md) |
| Français | [docs/fr.md](docs/fr.md) |
| Español | [docs/es.md](docs/es.md) |
| 中文（简体） | [docs/zh-CN.md](docs/zh-CN.md) |
| 日本語 | [docs/ja.md](docs/ja.md) |
| Português | [docs/pt.md](docs/pt.md) |
| Українська | [docs/uk.md](docs/uk.md) |
| Polski | [docs/pl.md](docs/pl.md) |
| Italiano | [docs/it.md](docs/it.md) |
| Nederlands | [docs/nl.md](docs/nl.md) |
| Türkçe | [docs/tr.md](docs/tr.md) |
| 한국어 | [docs/ko.md](docs/ko.md) |
| العربية | [docs/ar.md](docs/ar.md) |
| עברית | [docs/he.md](docs/he.md) |
| Čeština | [docs/cs.md](docs/cs.md) |
| Svenska | [docs/sv.md](docs/sv.md) |

## Лицензия

[MIT](LICENSE)

## Установка (Linux, systemd)

```bash
curl -fsSL https://github.com/raidkon/certbot-dns/raw/master/install.sh -o get-certbot-dns.sh
sudo sh ./get-certbot-dns.sh --dry-run
sudo sh ./get-certbot-dns.sh
```

Скрипт скачивает бинарник и файлы из [GitHub Release](https://github.com/raidkon/certbot-dns/releases) (tar.gz: бинарник, systemd unit, примеры `config.toml`, `env`, `example.com.zone`), создаёт пользователя `certbot-dns`, каталоги и сервис.

После установки:

```bash
sudo nano /etc/certbot-dns/config.toml   # email, [[providers]], [[certificates]]
sudo nano /etc/certbot-dns/env           # FASTDNS_API_TOKEN, ALIBABA_* …
sudo systemctl restart certbot-dns
sudo journalctl -u certbot-dns -f
```

Опции: `--version v1.0.0`, `--no-start`. Удаление: [uninstall.sh](uninstall.sh) (`--purge` — конфиг и данные).

## Возможности

- ACME v2 (Let's Encrypt production / staging)
- Именованные провайдеры `[[providers]]`: `fastdns`, `alibabacloud` (устаревший блок `[fastdns]` → провайдер `default`)
- DNS-01: один или несколько провайдеров на блок `[[certificates]]` (`provider = ["fv-main", "ali-dns"]`)
- FastDNS: последовательная публикация TXT и очистка конфликтующих записей
- Разбор списка `domains` в несколько сертификатов (wildcard → `wc-*`, apex → `apex-*`)
- **Sync зон** (опционально): master → slaves; master — провайдер или `file:///path/to.zone`
- Автопродление по `renew_before_days`
- Возобновление прерванного выпуска (`.obtain-checkpoint.json`)
- Каталоги выпуска `YYYY-MM-DD/` и symlink `live/`
- Режимы `once` и `daemon` (установщик настраивает **daemon** + systemd)
- Docker multi-arch (distroless)

## Минимальный конфиг

```toml
[acme]
email = "admin@example.com"

[[providers]]
name = "fv-main"
type = "fastdns"
api_token = "${FASTDNS_API_TOKEN}"

[[certificates]]
id = "sites"
provider = ["fv-main"]
domains = ["*.example.com"]
output_dir = "/var/lib/certbot-dns/certs/sites"

[runtime]
mode = "daemon"
loglevel = "info"
```

Подробнее: [`config.example.toml`](config.example.toml), [docs/ru.md](docs/ru.md).

## Сборка из исходников

```bash
sudo mkdir -p /etc/certbot-dns
sudo cp config.example.toml /etc/certbot-dns/config.toml

export FASTDNS_API_TOKEN="ваш-токен"

cd src && go test ./... && go build -o certbot-dns .
./certbot-dns -config /etc/certbot-dns/config.toml
```

Без `-config` используется `/etc/certbot-dns/config.toml`.

## Docker

### docker-compose (опубликованный образ)

При релизе (`git tag v1.0.0`) в [GitHub Container Registry](https://github.com/raidkon/certbot-dns/pkgs/container/certbot-dns) публикуется multi-arch образ:

`ghcr.io/raidkon/certbot-dns:latest` · `ghcr.io/raidkon/certbot-dns:v1.0.0`

```bash
cp docker-compose.example.yml docker-compose.yml
cp config.docker.example.toml config.toml
cp .env.example .env
# config.toml: email, [[providers]], [[certificates]]
# .env: FASTDNS_API_TOKEN, ALIBABA_ACCESS_KEY_ID, …
mkdir -p data
sudo chown -R 1000:1000 data

docker compose up -d
docker compose logs -f certbot-dns
```

По умолчанию процесс работает от **1000:1000**. Другой пользователь — `user:` в compose или `CERTBOT_DNS_UID` / `CERTBOT_DNS_GID` в `.env`.

```bash
CERTBOT_DNS_VERSION=v1.0.0 docker compose up -d
```

Первый раз пакет GHCR может быть private — в настройках пакета выберите **Public**.

### Локальная сборка образа

```bash
docker build -f docker/Dockerfile -t certbot-dns:local .
docker run --rm \
  -e FASTDNS_API_TOKEN=... \
  -v "$(pwd)/config.docker.example.toml:/etc/certbot-dns/config.toml:ro" \
  -v certbot-dns-data:/var/lib/certbot-dns \
  certbot-dns:local
```

## Релизы

```bash
git tag v1.2.0
git push origin v1.2.0
```

GitHub Actions (workflow `Release`, только по тегу `v*`):

- `certbot-dns_*_linux_{amd64,arm64}.tar.gz` + `SHA256SUMS` (бинарник, unit, примеры конфига/env, `example.com.zone`);
- Docker `ghcr.io/raidkon/certbot-dns` — теги `v1.2.0`, `1.2.0`, `latest`.

