# Building & running signal2sip

## Layout

- `daemon/` - the long-running multi-account daemon (`signal2sip-daemon`)
- `gendb/` - companion CLI for account lifecycle: register/link/verify/config (`signal2sip-gendb`)
- `signal/`, `storage/`, `util/` - Signal Protocol, SQLCipher storage, shared HTTP/base64 helpers
- `voip/`, `ringrtc/` - RingRTC <-> PJSIP audio bridge
- `tui/` - terminal UI for account management
- `test/` - live verification binaries (not unit tests - most talk to real Signal servers)
- `proto/` - Signal's protobuf wire definitions
- `systemd/` - unit file for deploying the daemon

## Building

See [`build-from-scratch.sh`](build-from-scratch.sh) for a full from-source
build of every dependency (libsignal-ffi, ringrtc+webrtc, a dedicated PJSIP) -
it clones each one as a sibling checkout next to this repo (`../libsignal`,
`../ringrtc`, `../pjproject-tls`). If those are already built, just
`cmake -B build && cmake --build build -j` (see `CMakeLists.txt`'s
`LIBSIGNAL_DIR`/`RINGRTC_DIR`/`PJPROJECT_DIR` cache variables to point
elsewhere).

See [`REQUIREMENTS.md`](REQUIREMENTS.md) for exactly what the build
installs on your system (including the one package that comes from a
third-party APT repo) and what the resulting binaries need at runtime.

## Running

```
signal2sip-gendb <account-name> register --e164 <e164> sms   # or: link
signal2sip-daemon /etc/signal2sip/signal2sip.conf
```

## Config

`signal2sip.conf` only ever holds one `[global]` section (`db_path`,
`db_key`, plus a few daemon-wide tuning knobs) - it's created automatically
on first run of `signal2sip-gendb` if missing (default `db_path`
`/var/lib/signal2sip/signal2sip.db`, a fresh `db_key` generated only when no
database already exists at that path yet). Everything per-account (SIP
trunk settings, enabled flag, deployment config) lives in the `account`
table of that same SQLCipher database, not in the file - manage it live via
`signal2sip-gendb <name> config get|set|list` / `enable|disable`, or
interactively through `signal2sip-tui` (account list -> detail -> SIP config
editor screen, which just drives the same `gendb config set` calls under the
hood). No daemon restart required either way - see `daemon/Config.h` for the
full format and `systemd/signal2sip-daemon.service` for a deployable unit.
