# SIPBXGO

A small, self-hosted SIP PBX for **extension-to-extension** calling, written in Go.

Cheap SIP desk phones sound great. SIPBXGO lets them call each other across
the internet with nothing but a VPS in the middle: family homes, a WAN office,
or a pop-up location. There are no trunks and no outside line, and none of the
Asterisk/FreePBX sprawl. It runs as one static binary in a small Docker
container, with one SQLite file for state.

> **Status: early development (Phase 1).** Phones can register and
> authenticate. Calling between extensions is next.

## Features

| | Status |
|---|---|
| Registration with digest auth (UDP + TCP) | ✅ |
| Multiple phones per extension | ✅ |
| Auto-ban of password guessers and SIP scanners | ✅ |
| CLI for managing extensions | ✅ |
| Extension-to-extension calls with RTP media relay (NAT-safe) | 🚧 next |
| Web UI (extensions, live registrations, active calls, call history) | planned |
| TLS + SRTP | planned |
| Hold music, voicemail, conference rooms | planned |
| Busy lights on phone buttons (BLF), phone auto-provisioning | planned |

## Quick start (Docker on a VPS)

```sh
git clone https://github.com/JustSparx/SIPBXGO.git
cd SIPBXGO
# Edit docker-compose.yml: set SIPBX_PUBLIC_IP to your VPS's public IP.
docker compose up -d --build

# Create extensions. Each one prints the password to put into the phone.
docker compose exec sipbxgo sipbxgo ext add 101 -name "Kitchen"
docker compose exec sipbxgo sipbxgo ext add 102 -name "Office"

# Watch phones come online
docker compose exec sipbxgo sipbxgo reg list
docker compose logs -f
```

Open the SIP port on the VPS firewall, UDP **and** TCP (for example `ufw allow 5060`).

CI also publishes images to `ghcr.io/justsparx/sipbxgo`. The repository is
private, so the VPS needs `docker login ghcr.io` with a token that has
`read:packages` before it can pull. Building on the VPS as shown above avoids that.

## Managing extensions

```
sipbxgo ext add <number> [-name N] [-secret S]   create (password generated if omitted)
sipbxgo ext list [-show-secrets]                 list, with number of registered phones
sipbxgo ext show <number>                        show one, including its password
sipbxgo ext set <number> [-name N] [-secret S] [-new-secret] [-enable|-disable]
sipbxgo ext del <number>                         delete
sipbxgo reg list                                 registered phones: source IP, transport, user agent
```

Extension numbers are 2–8 digits. The SIP **username is the extension number**.
You can run the CLI while the server is up; changes take effect immediately.

## Configuring a phone

| Phone setting | Value |
|---|---|
| Proxy / registrar server | your VPS IP (or DNS name) |
| Port | `SIPBX_SIP_ADDR` port (default 5060) |
| User ID / auth username | extension number, e.g. `101` |
| Password | from `sipbxgo ext add` / `ext show` |
| Transport | UDP, or TCP if your router's SIP ALG causes trouble |
| Registration expiry | 60–300 s |

**Poly/Obihai OBi phones:** OBi phones have several SIP account slots (SP1–SP6).
Keep Google Voice on its slot and put SIPBXGO on a free one, for example SP2. Set
*Service Providers → ITSP Profile B → SIP → ProxyServer* and *RegistrarServer*
to the VPS, and *Voice Services → SP2 Service* AuthUserName/AuthPassword to the
extension credentials. Then map a line key to SP2. Menu names vary a little by
model and firmware; a step-by-step guide will come with the auto-provisioning work.

## Configuration

All settings are environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `SIPBX_PUBLIC_IP` | *(empty)* | Public IP of the server. Required once calling is enabled. |
| `SIPBX_SIP_ADDR` | `:5060` | SIP bind address (UDP + TCP). A non-standard port cuts scanner noise a lot. |
| `SIPBX_DATA_DIR` | `./data` (`/data` in Docker) | Where `sipbxgo.db` lives |
| `SIPBX_REALM` | `sipbxgo` | Digest auth realm |
| `SIPBX_MIN_EXPIRES` / `SIPBX_MAX_EXPIRES` | `60` / `300` | Allowed registration interval (s). Short intervals keep NAT mappings open. |
| `SIPBX_BAN_THRESHOLD` | `5` | Failed auths before an IP is banned (0 disables) |
| `SIPBX_BAN_WINDOW` | `10m` | Window for counting failures |
| `SIPBX_BAN_DURATION` | `1h` | How long a ban lasts |
| `SIPBX_TRUSTED_NETS` | *(empty)* | Comma-separated IPs/CIDRs that are never banned |
| `SIPBX_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `SIPBX_SIP_DEBUG` | *(empty)* | Set to anything to log every SIP message |

## Security notes

- Any public SIP port gets scanned within hours. Failed logins, unknown
  extensions and known scanner user agents lead to an automatic ban. Banned
  IPs get **no response at all**.
- Unknown extensions and wrong passwords get the same `403`, so scanners can't
  work out which extensions exist.
- Passwords are stored in plain text in the SQLite file, because the phones
  and (later) auto-provisioning need them. Protect the data volume and its backups.
- Until TLS is added (Phase 3), SIP signaling travels unencrypted.

## Development

```sh
go test ./...                 # unit + end-to-end SIP tests
go run ./cmd/sipbxgo serve    # run locally (data in ./data)
SIPBX_SIP_DEBUG=1 SIPBX_LOG_LEVEL=debug go run ./cmd/sipbxgo serve
```

Layout:

```
cmd/sipbxgo/          CLI + entry point
internal/config/      environment configuration
internal/store/       SQLite: extensions, registrations (migrations in store.go)
internal/sipauth/     digest auth (stateless nonces) + request guard
internal/security/    auto-ban list, scanner detection
internal/registrar/   REGISTER handling
internal/pbx/         SIP server wiring
```

Built on [sipgo](https://github.com/emiago/sipgo) and
[modernc.org/sqlite](https://gitlab.com/cznic/sqlite).
