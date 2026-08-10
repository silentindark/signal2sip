# Third-party licenses

signal2sip's own code (this repository) is licensed under [AGPL-3.0](LICENSE).
That choice isn't arbitrary - two of the libraries statically linked into
`signal2sip-daemon`/`signal2sip-gendb` are themselves AGPL-3.0, which
requires any combined work distributing or running them to be licensed
under AGPL-3.0 too. This file documents what's actually linked in and
under what terms, so that's verifiable rather than asserted.

## Statically linked (become part of the binary)

| Dependency | License | Notes |
|---|---|---|
| [`libsignal`](https://github.com/signalapp/libsignal) | **AGPL-3.0** | Official Signal Protocol implementation - the reason this project is AGPL-3.0. |
| [`ringrtc`](https://github.com/signal2sip/ringrtc) (fork of [signalapp/ringrtc](https://github.com/signalapp/ringrtc)) | **AGPL-3.0** | Same reasoning as libsignal. |
| [`webrtc`](https://github.com/signal2sip/webrtc) (fork of Google's WebRTC) | BSD-3-Clause | Permissive - imposes no copyleft obligation on its own. |
| [`pjproject`](https://github.com/pjsip/pjproject) 2.14.1 | **GPL-2.0-or-later** | The "or later" option makes it combinable with GPLv3-family code (GPLv3 §13 explicitly permits linking with AGPLv3-licensed works); the combined binary as a whole is governed by AGPL-3.0, the strictest license among the three copyleft components. |

Because AGPL-3.0's copyleft (including its network-use clause, §13) covers
the combined work, this applies regardless of which of these three you'd
point to individually - the binary as distributed/operated is AGPL-3.0 in
full.

## Dynamically linked (system shared libraries, not embedded)

These stay as separate `.so` files the binaries load at runtime rather
than becoming part of them - see [`REQUIREMENTS.md`](REQUIREMENTS.md) for
exactly which binary needs which. Standard system libraries, not modified
by this project:

| Library | License |
|---|---|
| OpenSSL (`libssl`/`libcrypto`) | Apache-2.0 |
| libcurl | MIT-style (curl license) |
| libprotobuf | BSD-3-Clause |
| SQLCipher (`libsqlcipher`) | BSD-style (SQLCipher community edition) |
| libwebsockets | MIT |
| libqrencode | LGPL-2.1 |
| PulseAudio (`libpulse`) | LGPL-2.1 |
| FTXUI (`libftxui`, `signal2sip-tui` only) | MIT |

## Build-only (never shipped)

Not linked into anything, only used to produce the build - see
[`REQUIREMENTS.md`](REQUIREMENTS.md) for the full breakdown:

- `depot_tools`, Rust toolchains (rustup), LLVM/Clang/`lld-21` - all
  build tooling, none of their code ends up in the compiled binaries.

## What this means in practice

- **Running signal2sip as-is (even modified) and letting others interact
  with it over the network** (the SIP/Signal bridging it exists to do)
  triggers AGPL-3.0 §13: those users are entitled to the corresponding
  source code of the exact version running.
- **Distributing binaries** (built or pre-built) requires making the
  complete corresponding source available under AGPL-3.0 - including any
  local modifications.
- This isn't a project-specific policy choice - it flows directly from
  linking AGPL-3.0 libsignal/ringrtc statically. Replacing either with a
  differently-licensed alternative would be required before this project
  could ship under a more permissive license.
