# signal2sip

Native C++ daemon bridging Signal calling to SIP/PJSIP, in the spirit of
[tg2sip-webrtc](https://github.com/vladonv/tg2sip-webrtc) but for Signal
instead of Telegram. One process serves any number of Signal accounts at
once (each optionally with its own SIP trunk), driven entirely by real
incoming/outgoing Signal calls - real Signal Protocol send/receive, RingRTC
calling, and a PJSIP ring-buffer audio bridge, all per-account.

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
build of every dependency (libsignal-ffi, ringrtc+webrtc, a dedicated PJSIP),
or `cmake -B build && cmake --build build -j` if those are already built
under `~/GIT/signal2sip/{libsignal,ringrtc,pjproject-tls}` (see
`CMakeLists.txt`'s `LIBSIGNAL_DIR`/`RINGRTC_DIR`/`PJPROJECT_DIR` cache
variables to point elsewhere).

## Running

```
signal2sip-gendb <account-name> register --e164 <e164> sms   # or: link
signal2sip-daemon /etc/signal2sip/signal2sip.conf
```

See `daemon/Config.h` for the config file format and `systemd/signal2sip-daemon.service`
for a deployable unit.
