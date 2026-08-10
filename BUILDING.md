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

By default signal2sip itself builds Release, stripped of debug symbols
(`daemon`/`gendb`/`tui` all carry a `-s` link flag scoped to Release only -
see `CMakeLists.txt`). Pass `--debug` to build it with symbols kept
instead: `./build-from-scratch.sh --debug`, or manually
`cmake -B build -DCMAKE_BUILD_TYPE=Debug && cmake --build build -j`. Only
signal2sip's own code is affected - libsignal-ffi/ringrtc/webrtc are
always built release either way, regardless of this flag.

See [`REQUIREMENTS.md`](REQUIREMENTS.md) for exactly what the build
installs on your system (including the one package that comes from a
third-party APT repo) and what the resulting binaries need at runtime.

See [`TESTING.md`](TESTING.md) for what each of the verification
binaries under `test/` is for and how to run it - several are "live"
and hit real Signal/SIP infrastructure with real credentials.

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

### SIP trunk (`sip_host`): ports and the TLS/SNI hostname bug

**Ports:** `sip_host` with no explicit `:port` uses the plain SIP default
(5060) for `sip_transport=udp`; for `sip_transport=tls` (`sips:`),
`Config.cpp` explicitly defaults it to `:5061` (Asterisk's usual TLS
listener port) if no port was given. Either way, adding an explicit
`:<port>` to `sip_host` (e.g. `sip_host=192.0.2.10:5063`) always wins -
this isn't a fixed pair of choices, just the fallback when you don't
specify one.

**`sip_host` as a hostname (not just an IP) now works for
`sip_transport=tls`, as of the `signal2sip-2.14.1-sni-fix` branch of
[`signal2sip/pjproject-tls`](https://github.com/signal2sip/pjproject-tls)
that `build-from-scratch.sh` builds from.** This was a real PJSIP bug,
not a signal2sip limitation: `pjlib/src/pj/ssl_sock_ossl.c`'s
`ssl_set_peer_name()` segfaulted during the TLS handshake's SNI setup
(`SSL_set_tlsext_host_name`) specifically when the configured remote was
a hostname rather than an IP, because it passed a `pj_str_t` that isn't
null-terminated directly into an API that reads it as a plain C string.
Confirmed live via `gdb` backtrace (`asock_on_connect_complete` ->
`ssl_set_peer_name` -> crash), reproduced 100% of the time on a hostname
and gone 100% of the time on the equivalent IP; confirmed present in
2.14.1, 2.17, and current pjsip/pjproject `master` (`ssl_set_peer_name`
itself was untouched by any upstream commit across that whole range, so
just upgrading PJSIP would not have fixed it). Full writeup, root cause,
and the fix itself: [signal2sip/pjproject-tls#1](https://github.com/signal2sip/pjproject-tls/issues/1).
Verified fixed 2026-08-10 with a real hostname-based TLS registration
against DPDZK's Asterisk, no crash, daemon stable.

If you're building against a different/older PJSIP checkout that
doesn't have this patch, using an IP literal in `sip_host` sidesteps the
crash entirely and costs nothing functionally either way: signal2sip's
TLS trust model is `sip_tls_ca_file` (pin the exact server certificate)
or explicit `sip_tls_insecure=yes`, never SNI/hostname-based
verification.
