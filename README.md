# SIPBXGO

A small, self-hosted SIP PBX for **extension-to-extension** calling, written in Go.

Cheap SIP desk phones sound great. SIPBXGO lets them call each other across
the internet with nothing but a VPS in the middle: family homes, a WAN office,
or a pop-up location. It runs as one static binary in a small Docker
container, with one SQLite file for state. There's no Asterisk/FreePBX sprawl.

> **Version 1.0: the "personal server" edition.** Deliberately small and
> complete for its job: phones anywhere register to your server and call each
> other, with the calls encrypted, a conference room when you need one, hold
> music, and a web UI to run it all. Features that matter for big phone fleets
> or outside lines are left for later versions (see [Roadmap](#roadmap)).

---

## Contents

- [What it does](#what-it-does)
- [What it doesn't do (on purpose)](#what-it-doesnt-do-on-purpose)
- [How it works](#how-it-works)
- [Requirements](#requirements)
- [Installation](#installation)
- [Setting up phones](#setting-up-phones)
- [Using it](#using-it)
- [The web UI](#the-web-ui)
- [Command-line reference](#command-line-reference)
- [Configuration reference](#configuration-reference)
- [Security](#security)
- [Operations: updates, backups, logs](#operations-updates-backups-logs)
- [Troubleshooting](#troubleshooting)
- [Development](#development)
- [Roadmap](#roadmap)
- [Contributing](#contributing)
- [License](#license)

---

## What it does

**Calling**
- Extension-to-extension calls between phones anywhere on the internet.
- Audio is relayed through the server, so phones behind home and office NAT
  just work. There's nothing to configure on routers and no STUN/ICE.
- Several phones can share one extension (a desk phone and a softphone): all
  ring, and the first to answer takes the call.
- Hold with **hold music** (a generated, royalty-free loop, or your own WAV),
  keypad tones (DTMF), busy, decline, no-answer and cancel all behave properly.
- **Conference rooms:** dial a room number to join. There's an optional PIN,
  join/leave chimes, and music while you're alone in the room.
- Call history.

**Security**
- Digest authentication for registrations *and* calls. Caller ID can't be
  spoofed between extensions.
- **Encrypted calls:** SIP over TLS with SRTP audio. The certificate comes from
  Let's Encrypt (shared from Traefik, or from files) and renewals are automatic.
- A per-extension **"Require encryption"** switch.
- Auto-ban of password guessers and SIP scanners. Banned IPs get no response
  at all.

**Management**
- A web UI with a live dashboard, extensions (including a copy-paste phone
  setup card), conference rooms, call history, bans and certificate status.
- A command-line tool for everything, which you can use while the server runs.

## What it doesn't do (on purpose)

- **No outside line:** there are no SIP trunks and no calls to or from the
  phone network. Use your mobile or the phone's other account (for example
  Google Voice on an OBi) for that.
- **No voicemail:** if someone doesn't pick up, call their mobile.
- **No call transfer, busy lights (BLF), or phone auto-provisioning** yet.
  Phones are set up by hand, which takes a couple of minutes each.
- **No video:** audio only.

## How it works

```
  Phone A ──SIP (UDP/TCP/TLS)──┐                 ┌──SIP──── Phone B
  (home, behind NAT)           │    SIPBXGO      │   (office, behind NAT)
                               ├── on your VPS ──┤
  Phone A ════ audio (RTP/SRTP)╪═> relay ═══════>╪═ audio ══ Phone B
```

SIPBXGO is a *back-to-back user agent*: every call is two legs, caller↔server
and server↔callee.
- **Audio flows through the server.** Each phone sends its audio to the
  server, and the server learns the phone's real public address from those
  packets. That's what makes NAT a non-issue.
- **Encryption is per leg.** Each phone exchanges its SRTP keys only with the
  server, which decrypts and re-encrypts. An encrypted phone can therefore
  call a plain one; the call is shown as *partly encrypted*.
- **The server handles audio itself** where needed: it answers holds and plays
  music, and it mixes conference rooms.

## Requirements

- **A VPS** (or any Linux host) with a **public IP**. 1 vCPU and 512 MB RAM is
  plenty for a household or small office.
- **Docker** with the Compose plugin.
- **A domain name** pointed at the server, for the web UI and TLS
  certificates, e.g. `pbx.example.com`.
- **A reverse proxy with Let's Encrypt** (for example Traefik) for the web UI.
  You can skip it and reach the UI over an SSH tunnel instead.
- **SIP phones or softphones.** Tested with Poly/Obihai OBi phones and
  Linphone (iOS). Anything standards-compliant should work.
- **Open firewall ports:**

  | Port | Protocol | Used for |
  |---|---|---|
  | 5060 | UDP + TCP | SIP |
  | 5061 | TCP | SIP over TLS (encrypted calls) |
  | 10000–10999 | UDP | Call audio (4 ports per call) |

## Installation

### 1. Get the code onto the server

```sh
git clone https://github.com/JustSparx/SIPBXGO.git /opt/SIPBXGO
cd /opt/SIPBXGO
```

If the repository is private, GitHub won't accept a password over HTTPS. Use
a read-only **deploy key**: run `ssh-keygen -t ed25519 -f ~/.ssh/sipbxgo`, add
the `.pub` file under *Repository → Settings → Deploy keys*, then clone with
`git clone git@github.com:JustSparx/SIPBXGO.git` using that key.

### 2. Settings

```sh
cp .env.example .env
```

Edit `.env`. The important lines:

```ini
SIPBX_PUBLIC_IP=203.0.113.10        # your server's public IP
SIPBX_DOMAIN=pbx.example.com        # web UI hostname, also used for TLS
TZ=America/Los_Angeles              # for times shown in the UI
```

Everything else has sensible defaults ([full list](#configuration-reference)).
`.env` is ignored by git, so updates never overwrite it.

### 3. Firewall

```sh
ufw allow 5060
ufw allow 5061/tcp
ufw allow 10000:10999/udp
```

### 4. Start it

```sh
docker compose up -d --build
docker compose logs -f
```

You should see `SIP listening` and `web UI listening`. The container uses
host networking: SIP needs each phone's real address, and Docker handles
large UDP port ranges badly.

### 5. Create your admin login

```sh
docker compose exec sipbxgo sipbxgo admin add admin
```

This prints a generated password. Change it after signing in, on the Account page.

### 6. Reach the web UI

**With Traefik** (the compose file already carries the labels):

1. In **Traefik's** compose service, add this so it can reach
   host-network containers:
   ```yaml
   extra_hosts:
     - "host.docker.internal:host-gateway"
   ```
   Then run `docker compose up -d traefik`.
2. Make sure DNS for `SIPBX_DOMAIN` points at the server.
3. Open `https://<SIPBX_DOMAIN>` and sign in.

The UI listens on `172.17.0.1:8080`, the host side of Docker's default
bridge. Containers can reach it, the internet can't. If `ufw` blocks
container traffic, run
`ufw allow from 172.16.0.0/12 to any port 8080 proto tcp`.

**Without a reverse proxy:** set `SIPBX_HTTP_ADDR=127.0.0.1:8080` in `.env`,
then from your computer run `ssh -L 8080:127.0.0.1:8080 you@server` and
open `http://localhost:8080`.

### 7. Turn on encrypted calls (TLS + SRTP)

If Traefik already has a certificate for `SIPBX_DOMAIN` (it does once the web
UI route works), SIPBXGO can share it:

```sh
cp docker-compose.override.example.yml docker-compose.override.yml
# edit the acme.json path inside if yours isn't /opt/n8n/traefik/acme.json
docker compose up -d
```

The logs now show `SIP over TLS listening … names=[pbx.example.com]`, and the
Security page shows the certificate and its expiry.

Traefik keeps `acme.json` root-only, so the override runs the container as
root, but with every Linux capability dropped except file access
(`DAC_OVERRIDE`) and privilege escalation blocked. `acme.json` is mounted
read-only. Certificate renewals are picked up without a restart.

To use certificate files instead, mount them and set `SIPBX_TLS_CERT` and
`SIPBX_TLS_KEY` in `.env`.

## Setting up phones

Create an extension first (web UI → **Extensions**, or
`sipbxgo ext add 101 -name "Kitchen"`). Its page has a **Phone setup** card
with every value below, each with a copy button.

| Phone setting | Value |
|---|---|
| Server / registrar / proxy | your domain, e.g. `pbx.example.com` |
| Transport and port | **TLS on 5061** (recommended), or UDP/TCP on 5060 |
| Username / auth ID | the extension number, e.g. `101` |
| Password | shown on the extension's page |
| Media encryption | **SRTP** when using TLS |
| Registration expiry | 60–300 seconds |
| Codecs | leave as is: G.722 (HD) and G.711 work; audio passes through untouched |
| NAT, STUN, ICE | not needed; leave off or at defaults |

With TLS, always use the **domain name**, not the IP address. The phone checks
the certificate against the name.

### Poly / Obihai OBi phones

OBi phones have several account slots (SP1–SP6). Keep Google Voice (or
whatever you use) on its slot and give SIPBXGO a free one, e.g. **SP2**.
Menu names vary a little by model and firmware:

1. **Service Providers → ITSP Profile B → SIP:** set *ProxyServer* and
   *RegistrarServer* to your domain. For encrypted calls, set the transport to
   **TLS**, the port to **5061**, and enable **SRTP**.
2. **Voice Services → SP2 Service:** set *AuthUserName* to the extension
   number and *AuthPassword* to its password.
3. Map a **line key** to SP2, so calls to and from the PBX use that key.

The phone shows up on the dashboard within a few seconds, with its model and
public address. Registrations over TLS get a **TLS** badge.

### Linphone (iOS / Android / desktop)

1. Add a **SIP account**: username = extension number, password, domain =
   your domain, transport = **TLS**.
2. In settings, set **Media encryption → SRTP**.
3. Mobile apps may stop listening for calls in the background, depending on
   their push-notification setup. The phone must be registered to ring.

### Several phones on one extension

Register several phones with the same extension credentials. They all ring,
and the first to answer gets the call.

## Using it

- **Calling:** dial the extension number, e.g. `102`.
- **Hold:** press hold on your phone. The other person hears music. Press it
  again (or resume) to come back.
- **Conference rooms:** dial the room number, e.g. `800`.
  - If the room has a PIN you'll hear **two short beeps**. Key the PIN, then `#`.
  - A **rising chime** means someone joined; a **falling chime** means someone left.
  - While you're alone you hear music.
  - Three wrong PINs, or 30 seconds without one, ends the call.
- **Busy / no answer:** you get a busy signal, or the call gives up after
  `SIPBX_RING_TIMEOUT` (60 s by default).
- **Keypad tones** are passed through to the other phone.

## The web UI

| Page | What's there |
|---|---|
| **Dashboard** | Live counts; calls in progress (hold state, an encryption badge, and a warning if audio is only arriving from one side); conference rooms in use; registered phones (model, public address, TLS badge, last seen); offline extensions |
| **Extensions** | All extensions with busy-lamp style status dots. Each one's page has the phone setup card, name, enable/disable, **Require encryption**, change or regenerate password, live registrations, recent calls, delete |
| **Conferences** | Rooms (number, name, optional PIN), add/edit/delete, and who's in each room right now, including callers still entering the PIN |
| **Calls** | Call history filterable by extension: result, encryption, duration, who hung up |
| **Security** | TLS certificate name, expiry and source; banned IPs with an unban button; ban policy; trusted networks |
| **Account** | Change your password; list of admins |

The live parts refresh every few seconds. Light and dark themes follow your
system setting.

## Command-line reference

Run inside the container with `docker compose exec sipbxgo sipbxgo <command>`.
Changes take effect immediately, even while the server is running.

```
sipbxgo ext add <number> [-name N] [-secret S]      create an extension (password generated if omitted)
sipbxgo ext list [-show-secrets]                    list, with registered phone counts
sipbxgo ext show <number>                           one extension, including its password
sipbxgo ext set <number> [-name N] [-secret S] [-new-secret]
                         [-enable|-disable] [-require-tls|-allow-plain]
sipbxgo ext del <number>                            delete

sipbxgo room add <number> [-name N] [-pin P]        create a conference room
sipbxgo room set <number> [-name N] [-pin P | -no-pin]
sipbxgo room list | del <number>

sipbxgo reg list                                    registered phones: address, transport, model
sipbxgo call list [-n 20]                           recent calls

sipbxgo admin add <name> [-password P]              web UI admin (password generated if omitted)
sipbxgo admin passwd <name> [-password P]           reset a password (signs that admin out)
sipbxgo admin list | del <name>

sipbxgo version
```

Extension and room numbers are 2–8 digits and share one number space. The SIP
username is always the extension number.

## Configuration reference

All settings are environment variables. With Docker, the common ones go in
`.env` (the compose file maps them in). Anything else can be set under
`environment:` in `docker-compose.override.yml`.

| Variable (in `.env`) | Default | Meaning |
|---|---|---|
| `SIPBX_PUBLIC_IP` | auto-detected | Public IP written into SIP and SDP. Auto-detection is right on a typical VPS; set it if the server is behind NAT. |
| `SIPBX_DOMAIN` | *(empty)* | Web UI hostname (Traefik route), shown to phones, and the certificate name for TLS |
| `SIPBX_SIP_PORT` | `5060` | SIP port (UDP + TCP). A non-standard port cuts scanner noise a lot. |
| `SIPBX_TLS_PORT` | `5061` | SIP over TLS port |
| `SIPBX_RTP_PORTS` | `10000-10999` | UDP port range for call audio (4 ports per call; 2 per conference participant) |
| `SIPBX_HTTP_ADDR` | `172.17.0.1:8080` | Web UI listen address (`off` disables it) |
| `SIPBX_TRUSTED_NETS` | *(empty)* | Comma-separated IPs/CIDRs that are never banned, e.g. your office |
| `SIPBX_HOLD_MUSIC` | `builtin` | `builtin`, `off`, or the path to a WAV file inside the container (any rate, mono or stereo, 8/16-bit PCM). Also used when alone in a conference room. |
| `SIPBX_TLS_ACME_JSON` | *(empty)* | Traefik `acme.json` to take the certificate from (the override example sets it) |
| `SIPBX_TLS_CERT` / `SIPBX_TLS_KEY` | *(empty)* | PEM certificate chain and key, instead of `acme.json` |
| `SIPBX_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |
| `TZ` | `UTC` | Time zone for times in the UI, e.g. `America/Los_Angeles` |

Advanced settings (set via `docker-compose.override.yml`):

| Variable | Default | Meaning |
|---|---|---|
| `SIPBX_MIN_EXPIRES` / `SIPBX_MAX_EXPIRES` | `60` / `300` | Allowed registration interval (s). Short intervals keep NAT mappings open. |
| `SIPBX_RING_TIMEOUT` | `60s` | How long a call rings before giving up |
| `SIPBX_MEDIA_TIMEOUT` | `5m` | Hang up when a phone has sent no audio for this long (e.g. it lost power) |
| `SIPBX_BAN_THRESHOLD` / `SIPBX_BAN_WINDOW` / `SIPBX_BAN_DURATION` | `5` / `10m` / `1h` | Failed logins within the window before a ban, and how long the ban lasts (threshold 0 disables) |
| `SIPBX_TLS_DOMAIN` | `SIPBX_DOMAIN` | Certificate name to use, if different from the domain |
| `SIPBX_TLS_ADDR` | `:5061` | TLS listen address (`off` disables TLS) |
| `SIPBX_REALM` | `sipbxgo` | Digest authentication realm |
| `SIPBX_DATA_DIR` | `/data` | Where `sipbxgo.db` lives |
| `SIPBX_SIP_DEBUG` | *(empty)* | Set to anything to log every SIP message |

Custom hold music example (`docker-compose.override.yml`):

```yaml
services:
  sipbxgo:
    volumes:
      - ./hold.wav:/music/hold.wav:ro
    environment:
      SIPBX_HOLD_MUSIC: /music/hold.wav
```

## Security

- **Scanners are expected.** Any public SIP port gets probed within hours.
  Failed logins, unknown extensions and known scanner tools lead to an
  automatic ban, and banned IPs get **no response at all**. Unknown extensions
  and wrong passwords get the same answer, so scanners can't find which
  extensions exist.
- **Calls are authenticated too.** Caller ID is always the extension that
  logged in.
- **The media relay is locked down.** It only accepts audio from the IP of the
  phone in the call. With SRTP, a packet that fails authentication is dropped
  and can never redirect where a phone's audio goes.
- **Encryption is per leg.** With TLS, signaling and audio are encrypted
  between each phone and the server. SRTP keys are exchanged only over TLS,
  and each phone only ever learns its own key. The server itself can hear
  calls; it is your server.
- **Phone passwords are stored in plain text** in the SQLite file, because
  phones need the real password for digest authentication. Protect the data
  volume and its backups.
- **Web UI:**
  - admin passwords are bcrypt-hashed;
  - sessions are random tokens, stored hashed, in HttpOnly cookies (Secure
    behind HTTPS);
  - 10 failed sign-ins lock an IP out for 15 minutes;
  - cross-site form posts are rejected;
  - a strict Content-Security-Policy is sent;
  - it listens only on a private address by default.

## Operations: updates, backups, logs

**Update**
```sh
cd /opt/SIPBXGO
git pull
docker compose up -d --build
```
Database changes apply automatically on start. Calls in progress are hung up
cleanly during the restart.

**Back up** (everything lives in one Docker volume):
```sh
docker compose stop
docker run --rm -v sipbxgo_sipbxgo-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/sipbxgo-backup.tgz -C /data .
docker compose start
```
(`docker volume ls` shows the exact volume name.) Restore by extracting into
the same volume. Keep backups private: they contain the phone passwords.

**Logs**
```sh
docker compose logs -f
```
You'll see phones registering, calls starting, answered and ended (with
duration, encryption and packet counts), holds, conference joins, bans and
certificate reloads. Set `SIPBX_LOG_LEVEL=debug` for more detail.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| Phone won't register, logs say `auth failed` | Wrong password. Check the extension page. After 5 failures the IP is banned for an hour: unban it on the **Security** page, and consider adding your network to `SIPBX_TRUSTED_NETS`. |
| Logs say `registration refused: extension requires TLS` | **Require encryption** is on for that extension. Set the phone to TLS on 5061, or turn the switch off. |
| Phone gets no response at all | Its IP is banned (Security page), or the firewall blocks 5060/5061. |
| TLS registration fails | Use the **domain name**, not the IP, as the phone's server; the certificate is for the name. Check the Security page shows a valid certificate. |
| `has no certificate for …` at startup | Traefik doesn't have a certificate for `SIPBX_DOMAIN` yet. Open the web UI once so Traefik issues it, then restart. |
| Call connects but there's no audio in one or both directions | Open UDP 10000–10999 on the firewall, and check `SIPBX_PUBLIC_IP`. The dashboard flags calls where audio arrives from only one side. |
| A call ends by itself after a few minutes | Neither phone sent any audio for `SIPBX_MEDIA_TIMEOUT` (5 min), which usually means one lost power or network. Raise the timeout if your phones go fully silent (e.g. both muted) for long stretches. |
| Web UI returns 502 through Traefik | Traefik is missing `extra_hosts: host.docker.internal:host-gateway`, `docker0` isn't `172.17.0.1` (change `SIPBX_HTTP_ADDR`), or `ufw` blocks container → host traffic on 8080. |
| Times in the UI are off | Set `TZ` in `.env`. |
| Conference caller hears beeps, then gets hung up | The room has a PIN: key it, then `#`. |

For deep debugging, set `SIPBX_SIP_DEBUG=1` to log every SIP message.

## Development

```sh
go test ./...                 # unit + end-to-end tests with real SIP phones in-process
go run ./cmd/sipbxgo serve    # run locally (data in ./data)
SIPBX_SIP_DEBUG=1 SIPBX_LOG_LEVEL=debug go run ./cmd/sipbxgo serve
```

The end-to-end tests run complete calls between in-process SIP phones:
registration, two-way audio, hold music, forking, TLS with SRTP, conference
mixing and PINs. CI also runs them under the race detector.

```
cmd/sipbxgo/          CLI and entry point
internal/config/      environment configuration
internal/store/       SQLite: extensions, rooms, registrations, calls, admins, sessions
internal/sipauth/     digest auth (stateless nonces) and request guard
internal/security/    auto-ban list, scanner detection
internal/registrar/   REGISTER handling
internal/b2bua/       call engine: INVITE/BYE/re-INVITE, forking, hold, SRTP negotiation, conference calls
internal/sdp/         SDP parsing, rewriting and building
internal/media/       RTP/RTCP endpoints (NAT latching, SRTP), call relay, music player
internal/audio/       G.711 codec, generated hold music and tones, WAV loading
internal/conference/  conference mixer: rooms, PIN entry, DTMF, chimes
internal/tlscert/     TLS certificates from PEM files or Traefik's acme.json, auto-reload
internal/pbx/         SIP server wiring
internal/web/         web UI: handlers, templates, static assets (embedded)
```

Built on [sipgo](https://github.com/emiago/sipgo),
[pion/srtp](https://github.com/pion/srtp) and
[modernc.org/sqlite](https://gitlab.com/cznic/sqlite).

## Roadmap

Version 1.0 is feature-complete for its "personal server" scope. Ideas for
later versions, for larger setups:

- **Phone auto-provisioning:** OBi config files, and a Linphone QR code
  scanned from the extension page.
- **Busy lights (BLF)** on phone line keys.
- **Call transfer** (blind and attended).
- **Voicemail.**

## Contributing

Issues and pull requests are welcome. Please read
[CONTRIBUTING.md](CONTRIBUTING.md) first; for features, open an issue to
discuss before writing code. Report security issues privately as described in
[SECURITY.md](SECURITY.md).

## License

SIPBXGO is free and open-source software under the
[Apache License 2.0](LICENSE). Copyright 2026 JustSparx and the SIPBXGO
contributors.

It builds on excellent open-source work, including
[sipgo](https://github.com/emiago/sipgo) (BSD-2-Clause),
[pion](https://github.com/pion) rtp/rtcp/srtp (MIT),
[modernc.org/sqlite](https://gitlab.com/cznic/sqlite) (BSD-3-Clause) and the
Go standard library (BSD-3-Clause). The full list, with every copyright notice
and license text, is in [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). It is
also included in the Docker image under `/usr/share/doc/sipbxgo/`.
