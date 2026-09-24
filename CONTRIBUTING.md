# Contributing to SIPBXGO

Thanks for your interest! SIPBXGO is a small project with a deliberately
narrow scope, so a little coordination up front saves everyone time.

## Before you start

- **Bugs:** open an issue with the bug report template. Logs help a lot. Run
  with `SIPBX_LOG_LEVEL=debug` (and `SIPBX_SIP_DEBUG=1` for SIP traces), and
  remove passwords, keys and public IPs you'd rather not share.
- **Features:** open an issue to discuss it *before* writing code. Version 1.x
  is the "personal server" edition and stays small on purpose (see
  [What it doesn't do](README.md#what-it-doesnt-do-on-purpose) and the
  [Roadmap](README.md#roadmap)). Bigger features such as voicemail,
  transfer, BLF and provisioning are planned for a later edition.
- **Security issues:** please don't open a public issue. See [SECURITY.md](SECURITY.md).

## Making a change

1. Fork the repository and create a branch from `main`.
2. Keep the change focused. One fix or feature per pull request.
3. Match the surrounding code: standard `gofmt`, clear names, comments that
   explain *why*, and no new dependencies unless there's no reasonable
   alternative.
4. Add or update tests. Most behaviour has end-to-end tests in
   `internal/pbx/`, which run real SIP phones in-process, and the unit tests
   sit next to the code.
5. Run the checks CI runs:
   ```sh
   gofmt -l .                     # must print nothing
   go vet ./...
   go test -race ./...            # -race needs cgo; plain go test is fine locally
   ```
6. If you add, remove or upgrade a dependency, regenerate the notices:
   ```sh
   go run ./tools/notices > THIRD_PARTY_NOTICES
   ```
7. Open a pull request and fill in the template. A maintainer will review it.
   Changes may be requested before it's merged.

## Licensing of contributions

SIPBXGO is licensed under the [Apache License 2.0](LICENSE). Under section 5
of that license, any contribution you submit is licensed under the same
terms, with no separate agreement needed. Only submit code you wrote or have
the right to contribute. Dependencies must use a license compatible with
Apache-2.0 (MIT, BSD, Apache and similar); GPL-family code can't be accepted.
