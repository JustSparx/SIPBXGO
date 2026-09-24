# Security policy

SIPBXGO sits on the public internet and handles phone credentials and call
audio, so security reports are taken seriously.

## Reporting a vulnerability

Please **don't open a public issue.** Report it privately through GitHub:
**Security → Report a vulnerability** on this repository. Include:

- what the issue is and what an attacker could do with it;
- how to reproduce it (the version from `sipbxgo version`, configuration, steps);
- any logs or packet captures, with secrets removed.

You'll get an acknowledgement as soon as possible. Once a fix is released
you'll be credited, unless you'd rather not be.

## Supported versions

Security fixes go into the latest release. There are no long-term support
branches at this stage.

## Scope

In scope: the SIP server, media relay, SRTP handling, authentication and ban
logic, the web UI and its sessions, and the Docker setup in this repository.

Out of scope: vulnerabilities in phones, in reverse proxies such as Traefik,
or in the host OS. Report those to their vendors.
