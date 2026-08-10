# signal2sip

Native C++ daemon bridging Signal calling to SIP/PJSIP, in the spirit of
[tg2sip-webrtc](https://github.com/vladonv/tg2sip-webrtc) but for Signal
instead of Telegram. One process serves any number of Signal accounts at
once (each optionally with its own SIP trunk), driven entirely by real
incoming/outgoing Signal calls - real Signal Protocol send/receive, RingRTC
calling, and a PJSIP ring-buffer audio bridge, all per-account.

See [`BUILDING.md`](BUILDING.md) for the repo layout, build, run, and
config instructions.

Copyright (C) 2026 Vlad Vorobev. Licensed under [AGPL-3.0](LICENSE) (see
[`NOTICE`](NOTICE)) - see [`THIRD_PARTY_LICENSES.md`](THIRD_PARTY_LICENSES.md)
for why (statically linking Signal's own AGPL-3.0 `libsignal`/`ringrtc`).
