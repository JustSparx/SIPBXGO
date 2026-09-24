# SIPBXGO

A small, self-hosted SIP PBX for **extension-to-extension** calling, written in Go.

Cheap SIP desk phones sound great. SIPBXGO lets them call each other across
the internet with nothing but a VPS in the middle: family homes, a WAN office,
or a pop-up location. There are no trunks and no outside line, and none of the
Asterisk/FreePBX sprawl. It runs as one static binary in a small Docker
container, with one SQLite file for state.

> **Status: early development (Phase 3).** Phones register and call each
> other, with audio relayed through the server so NAT is not a problem.
> Signaling and audio can be encrypted on every phone-to-server hop
> (TLS + SRTP), and everything is managed from a web UI.

## Features

| | Status |
|---|---|
| Registration with digest auth (UDP + TCP) | ✅ |
| Extension-to-extension calls, audio relayed through the server (NAT-safe) | ✅ |
| Multiple phones per extension (all ring, first to answer wins) | ✅ |
| Hold / resume with hold music (built-in or your own WAV), DTMF, busy, cancel | ✅ |
| Call history | ✅ |
| Auto-ban of password guessers and SIP scanners | ✅ |
| Web UI: live dashboard, extensions, call history, bans | ✅ |
| CLI for managing extensions and admins | ✅ |
| Call transfer | planned |
| Encrypted calls: SIP over TLS + SRTP audio, per-extension "require encryption" | ✅ |
| Conference rooms with optional PIN, join/leave chimes, live view | ✅ |
| Busy lights on phone buttons (BLF), phone auto-provisioning | planned |

## Quick start (Docker on a VPS)

```sh
git clone https://github.com/JustSparx/SIPBXGO.git
cd SIPBXGO
cp .env.example .env    # then edit: public IP, domain, time zone
docker compose up -d --build

# Create a web UI login (prints a generated password)
docker compose exec sipbxgo sipbxgo admin add admin

# Create extensions in the web UI, or from the CLI:
docker compose exec sipbxgo sipbxgo ext add 101 -name "Kitchen"

# Watch phones come online
docker compose exec sipbxgo sipbxgo reg list
docker compose logs -f
```

Open the firewall for SIP (UDP **and** TCP) and the audio port range:

```sh
ufw allow 5060
ufw allow 5061/tcp        # SIP over TLS
ufw allow 10000:10999/udp
```

CI also publishes images to `ghcr.io/justsparx/sipbxgo`. The repository is
private, so the VPS needs `docker login ghcr.io` with a token that has
`read:packages` before it can pull. Building on the VPS as shown above avoids that.

## Web UI

The web UI shows live registrations and calls, and manages extensions
(including a copy-paste phone setup card), call history, and bans. It listens
on `SIPBX_HTTP_ADDR`, which defaults to `127.0.0.1:8080` (not reachable from
the network). **Put it behind a TLS reverse proxy.** It holds every phone's
password.

### Behind Traefik

SIPBXGO uses host networking, so it can't join Traefik's Docker network.
Traefik reaches host-network containers through `host.docker.internal`, which
on Linux you have to define yourself:

1. On the **Traefik** service, add:
   ```yaml
   extra_hosts:
     - "host.docker.internal:host-gateway"
   ```
2. In `.env`, set `SIPBX_DOMAIN` to the UI's hostname. `SIPBX_HTTP_ADDR`
   defaults to `172.17.0.1:8080`, the host's address on Docker's default
   bridge (check with `ip -4 addr show docker0`).
3. Point a DNS record (e.g. `pbx.example.com`) at the server.
4. If `ufw` is active, allow containers to reach the UI:
   `ufw allow from 172.16.0.0/12 to any port 8080 proto tcp`.

Sign-in uses admin accounts created with `sipbxgo admin add <name>`.
Passwords are bcrypt-hashed and sessions last 7 days. After 10 failed sign-ins
an IP is locked out for 15 minutes. Cross-site form posts are rejected.

## Encrypted calls (TLS + SRTP)

With a certificate configured, SIPBXGO also listens for **SIP over TLS** on
port 5061. Phones registered over TLS automatically get **SRTP** (encrypted
audio, SDES with AES-128). Keys are exchanged per phone over its TLS
connection. The server decrypts and re-encrypts, so a plain phone can still
call an encrypted one; that call shows as *partly encrypted*.

**Certificate from Traefik** (when Traefik already serves the web UI):

```sh
cp docker-compose.override.example.yml docker-compose.override.yml
# adjust the acme.json path inside if needed
docker compose up -d
```

The override mounts Traefik's `acme.json` read-only. Traefik keeps that file
root-only, so the container runs as root, but with every Linux capability
dropped except file access (`DAC_OVERRIDE`) and privilege escalation blocked.
Renewals are picked up automatically.

**Certificate from files:** set `SIPBX_TLS_CERT` and `SIPBX_TLS_KEY` to PEM
files you mount into the container.

**On the phone:** transport **TLS**, port **5061**, server = your domain
(it must match the certificate), and media encryption **SRTP** (in Linphone:
*Media encryption: SRTP*). To stop an extension from ever using plain
SIP/RTP, tick **Require encryption** on its page (or
`sipbxgo ext set 101 -require-tls`).

## Hold music

When a phone puts a call on hold, SIPBXGO answers the hold itself and plays
music to the other person. The other phone's call is untouched, so this works
the same with any phone. The built-in music is generated in code, so it is
royalty-free. To use your own, mount a WAV file and point
`SIPBX_HOLD_MUSIC` at it, e.g. in `docker-compose.override.yml`:

```yaml
services:
  sipbxgo:
    volumes:
      - ./hold.wav:/music/hold.wav:ro
    environment:
      SIPBX_HOLD_MUSIC: /music/hold.wav
```

## Conference rooms

Create a room (web UI → **Conferences**, or `sipbxgo room add 800 -name Family`)
and any extension can dial its number to join. The server mixes the audio,
and everyone hears everyone else but not themselves.

- **PIN (optional):** callers hear two short beeps, key the PIN, then `#`.
  Keypad tones work both in-band (RFC 4733) and by SIP INFO. Three wrong
  tries and the call ends.
- **Chimes:** a rising chime when someone joins, a falling one when they leave.
- **Alone in the room:** you hear the hold music until someone else arrives.
- **Encryption:** each phone's leg is encrypted exactly as for normal calls.
- **Codecs:** the room mixes in G.711 (PCMU/PCMA), which every phone supports.
- **Numbers:** room numbers share the extension number space, so they can't
  collide.

## Managing extensions

```
sipbxgo ext add <number> [-name N] [-secret S]   create (password generated if omitted)
sipbxgo ext list [-show-secrets]                 list, with number of registered phones
sipbxgo ext show <number>                        show one, including its password
sipbxgo ext set <number> [-name N] [-secret S] [-new-secret] [-enable|-disable]
sipbxgo ext del <number>                         delete
sipbxgo reg list                                 registered phones: source IP, transport, user agent
sipbxgo call list [-n 20]                        recent calls: who, when, how long, who hung up
sipbxgo admin add <name> [-password P]           web UI admin (password generated if omitted)
sipbxgo admin passwd <name> | list | del <name>
sipbxgo room add <number> [-name N] [-pin P]     conference room
sipbxgo room set <number> [-name N] [-pin P | -no-pin] | list | del <number>
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

All settings are environment variables. With Docker, set them in `.env`
(see `.env.example`); the compose file maps them into the container.

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
| `SIPBX_TLS_ADDR` | `:5061` | SIP over TLS listen address (`off` disables). Only active with a certificate. |
| `SIPBX_TLS_ACME_JSON` | *(empty)* | Traefik `acme.json` to take the certificate from |
| `SIPBX_TLS_DOMAIN` | `SIPBX_SIP_DOMAIN` | Certificate name to use from `acme.json`; also put in TLS Contact headers |
| `SIPBX_TLS_CERT` / `SIPBX_TLS_KEY` | *(empty)* | PEM certificate chain and key, instead of `acme.json` |
| `SIPBX_HOLD_MUSIC` | `builtin` | Played to whoever is put on hold: `builtin` (a generated, royalty-free loop), `off` (silence), or the path of a WAV file inside the container (any rate, mono or stereo, 8/16-bit PCM) |
| `SIPBX_HTTP_ADDR` | `127.0.0.1:8080` | Web UI listen address (`off` disables it) |
| `SIPBX_SIP_DOMAIN` | *(empty)* | Server name shown in the web UI's phone setup card (defaults to the public IP) |
| `TZ` | `UTC` | Time zone for times shown in the UI, e.g. `America/Los_Angeles` |
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
- Without TLS configured, signaling and audio travel unencrypted. With TLS,
  phones that use it get encrypted signaling and audio. SRTP keys are
  exchanged only over TLS, and each phone only ever learns its own key.
- SRTP packets that fail authentication are dropped and never used to
  latch a phone's address, so forged packets can't redirect audio.

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
internal/store/       SQLite: extensions, rooms, registrations, calls, admins, sessions
internal/sipauth/     digest auth (stateless nonces) + request guard
internal/security/    auto-ban list, scanner detection
internal/registrar/   REGISTER handling
internal/b2bua/       call engine: INVITE/BYE/re-INVITE, forking, call history
internal/sdp/         SDP parsing and rewriting for the relay
internal/media/       RTP/RTCP endpoints (NAT latching, SRTP), call relay, hold music player
internal/audio/       G.711 codec, generated hold music and tones, WAV loading
internal/conference/  conference mixer: rooms, PIN entry, DTMF, chimes
internal/tlscert/     TLS certificate from PEM files or Traefik's acme.json, auto-reload
internal/pbx/         SIP server wiring
internal/web/         web UI: handlers, templates, static assets (embedded)
```

Built on [sipgo](https://github.com/emiago/sipgo) and
[modernc.org/sqlite](https://gitlab.com/cznic/sqlite).
