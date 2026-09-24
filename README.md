# SIPBXGO

A small, self-hosted SIP PBX for **extension-to-extension** calling, written in Go.

Cheap SIP desk phones sound great. SIPBXGO lets them call each other across
the internet with nothing but a VPS in the middle: family homes, a WAN office,
or a pop-up location. There are no trunks and no outside line, and none of the
Asterisk/FreePBX sprawl. It runs as one static binary in a small Docker
container, with one SQLite file for state.

> **Status: early development (Phase 1).** Phones register and call each
> other, with audio relayed through the server so NAT is not a problem.

## Features

| | Status |
|---|---|
| Registration with digest auth (UDP + TCP) | ✅ |
| Extension-to-extension calls, audio relayed through the server (NAT-safe) | ✅ |
| Multiple phones per extension (all ring, first to answer wins) | ✅ |
| Hold / resume, DTMF (RFC 2833 and SIP INFO), busy, cancel | ✅ |
| Call history | ✅ |
| Auto-ban of password guessers and SIP scanners | ✅ |
| CLI for managing extensions | ✅ |
| Call transfer | planned |
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

Open the firewall for SIP (UDP **and** TCP) and the audio port range:

```sh
ufw allow 5060
ufw allow 10000:10999/udp
```

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
sipbxgo call list [-n 20]                        recent calls: who, when, how long, who hung up
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
| Codecs | anything both phones support (G.722 HD and G.711 work everywhere); the PBX passes audio through untouched |
| NAT / STUN / ICE | not needed: leave off or at the defaults, the PBX relays all audio |

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
| `SIPBX_PUBLIC_IP` | auto-detected | Public IP written into SIP and SDP. Auto-detection is right on a typical VPS; set it explicitly if the server is itself behind NAT. |
| `SIPBX_SIP_ADDR` | `:5060` | SIP bind address (UDP + TCP). A non-standard port cuts scanner noise a lot. |
| `SIPBX_DATA_DIR` | `./data` (`/data` in Docker) | Where `sipbxgo.db` lives |
| `SIPBX_REALM` | `sipbxgo` | Digest auth realm |
| `SIPBX_MIN_EXPIRES` / `SIPBX_MAX_EXPIRES` | `60` / `300` | Allowed registration interval (s). Short intervals keep NAT mappings open. |
| `SIPBX_BAN_THRESHOLD` | `5` | Failed auths before an IP is banned (0 disables) |
| `SIPBX_BAN_WINDOW` | `10m` | Window for counting failures |
| `SIPBX_BAN_DURATION` | `1h` | How long a ban lasts |
| `SIPBX_TRUSTED_NETS` | *(empty)* | Comma-separated IPs/CIDRs that are never banned |
| `SIPBX_RTP_PORTS` | `10000-10999` | UDP port range for call audio (4 ports per call) |
| `SIPBX_RING_TIMEOUT` | `60s` | How long a call rings before giving up |
| `SIPBX_MEDIA_TIMEOUT` | `5m` | Hang up a call when neither phone has sent audio for this long (e.g. one lost power) |
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
- Calls require authentication too. Caller ID is always the extension that
  authenticated, so a phone can't pretend to be another extension.
- The media relay only accepts audio from the IP of the phone in the call, so
  outsiders can't inject audio into it.
- Until TLS/SRTP is added (Phase 3), signaling and audio travel unencrypted.

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
internal/b2bua/       call engine: INVITE/BYE/re-INVITE, forking, call history
internal/sdp/         SDP parsing and rewriting for the relay
internal/media/       RTP/RTCP relay with NAT latching
internal/pbx/         SIP server wiring
```

Built on [sipgo](https://github.com/emiago/sipgo) and
[modernc.org/sqlite](https://gitlab.com/cznic/sqlite).
