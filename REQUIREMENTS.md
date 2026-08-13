# Build & runtime requirements

What [`build-from-scratch.sh`](build-from-scratch.sh) puts on your system,
broken out by source, plus what the resulting binaries actually need
installed to run. Compiled from the script itself and from what a live
run on a fresh Debian 13 (trixie) box actually did (verified: nothing
outside this list touches the system - no hidden `install-build-deps.sh`,
no extra `apt-get`/`dpkg -i` calls anywhere in ringrtc's or webrtc's own
tooling).

## Third-party APT repository

The script adds exactly **one** non-Debian APT source:
`http://apt.llvm.org/<codename>/` (signed by a key it drops at
`/usr/share/keyrings/llvm-snapshot.gpg`, registered via
`/etc/apt/sources.list.d/llvm.list`). This persists on the system after
the build finishes - it isn't removed.

From that repository, the script installs exactly **one** package:

- `lld-21` - a specific LLVM linker version pinned because Debian's own
  `lld` (14.0.6 on bookworm) mislinks `signal2sip-daemon` into a
  pre-`main()` segfault (see `CMakeLists.txt`'s `PIN_LLD21`). Bookworm and
  trixie both get the same pinned version from apt.llvm.org rather than
  whatever their own repos happen to carry.

Everything else the script installs - including plain `clang` - comes from
Debian's own repos, even though `clang` sits in the same apt-get command
as `lld-21`; only `lld-21` actually resolves to apt.llvm.org (verified via
`apt-cache policy` on a live box: `clang` and `build-essential` both
resolve to `deb.debian.org`).

## Non-APT installs (not tracked by dpkg at all)

These don't touch the system package manager, so `apt list --installed`
won't show them and removing them is just deleting a directory:

- **Rust toolchain** - installed to `~/.cargo` / `~/.rustup` via
  `curl https://sh.rustup.rs | sh` if `rustup` isn't already on `PATH`.
  Pulls two toolchains: `nightly-2026-07-15` (libsignal) and `1.91.1`
  (ringrtc).
- **depot_tools** - `git clone`d from `chromium.googlesource.com` into a
  sibling directory (`../depot_tools`) and prepended to `PATH` for the
  build. Just files on disk, not a system install.
- **WebRTC sysroots** - `gclient sync` downloads prebuilt Debian
  bullseye i386/amd64 chroot images from
  `commondatastorage.googleapis.com` into the webrtc checkout itself
  (`ringrtc/src/webrtc/src/build/linux/debian_bullseye_*-sysroot`) - these
  are used only to compile against, and never touch the host's real
  root filesystem.

## Debian-repo packages (build-time only)

Installed via `apt-get install -y` from Debian's own repos:

```
build-essential cmake git curl pkg-config python3
libssl-dev libcurl4-openssl-dev libqrencode-dev nlohmann-json3-dev
protobuf-compiler libprotobuf-dev libsqlcipher-dev
libclang-dev clang libpulse-dev libftxui-dev
```

(plus `wget gnupg`, needed only to register the apt.llvm.org key above).

## Runtime dependencies (what a deployment target actually needs)

`ringrtc`, `webrtc`, `libsignal-ffi`, and the dedicated PJSIP 2.14.1 are
all statically linked (`.a`) into the final binaries - none of their
build dependencies need to exist on a machine that just *runs*
signal2sip, only on the machine that *builds* it.

The binaries do dynamically link a handful of shared libraries, so these
runtime (non-`-dev`) packages must be present on the deployment target:

| Binary | Runtime packages needed |
|---|---|
| `signal2sip-daemon` | `libssl3t64`, `libprotobuf32t64`, `libsqlcipher1`, `libpulse0` |
| `signal2sip-gendb` | `libssl3t64`, `libcurl4t64`, `libqrencode4`, `libprotobuf32t64`, `libsqlcipher1` |
| `signal2sip-tui` | `libftxui-component5.0.0`, `libftxui-dom5.0.0`, `libftxui-screen5.0.0`, `libsqlcipher1` |

(exact package names/versions as of Debian 13 trixie - re-check with
`ldd` against the actual binary if deploying to a different release).
None of these come from apt.llvm.org - that repo is a build-time-only
dependency (for `lld-21`) and isn't needed at runtime at all.

Plus the usual base system libraries every C++ binary needs (`libc6`,
`libstdc++6`, `libgcc-s1`) - always present on any Debian install.

## Disk & time

The WebRTC step alone needs 100GB+ free disk (depot_tools/gclient pulls
WebRTC's full third-party tree, tens of GB, before compiling it) and is
by far the slowest step; everything else is comparatively quick.
