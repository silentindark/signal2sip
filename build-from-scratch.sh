#!/bin/bash
# Full from-scratch build of signal2sip and every from-source dependency
# it needs: libsignal-ffi (Rust), ringrtc+webrtc (Rust/C++, with this
# project's AUDIO_TRANSPORT/raw-PCM patches), and a dedicated PJSIP 2.14.1
# (OpenSSL-3-safe, isolated from any system/shared PJSIP install a box
# might already have for something else, e.g. tg2sip-webrtc).
#
# Run this from wherever you cloned signal2sip/signal2sip - every
# dependency gets cloned as a sibling checkout next to it (../ringrtc,
# ../libsignal, ../pjproject-tls), matching CMakeLists.txt's own default
# CACHE PATH values (LIBSIGNAL_DIR/RINGRTC_DIR/PJPROJECT_DIR, all relative
# to CMAKE_CURRENT_SOURCE_DIR) - no -D overrides needed, and no assumption
# about $HOME or any particular parent directory name.
#
# Everything this clones (libsignal, ringrtc, webrtc, pjproject) is public.
#
# The webrtc step is genuinely heavy (depot_tools/gclient pulls WebRTC's
# full third-party tree, tens of GB, then compiles it) - budget real time
# and disk (100GB+ free is a safe bet) for that one step specifically;
# everything else here is comparatively quick.
#
# Usage: build-from-scratch.sh [--debug]
#   --debug   build signal2sip itself with debug symbols kept (see
#             CMAKE_BUILD_TYPE below) instead of the default stripped
#             Release build.

set -euo pipefail

# --debug builds signal2sip itself (only - libsignal-ffi/ringrtc/webrtc
# stay release either way, see below) with CMAKE_BUILD_TYPE=Debug instead
# of the default Release, which keeps debug symbols instead of stripping
# them (CMakeLists.txt's `-s` link option is scoped to
# $<$<CONFIG:Release>:-s> for exactly this reason - see its own comment).
CMAKE_BUILD_TYPE="Release"
for arg in "$@"; do
    case "$arg" in
        --debug) CMAKE_BUILD_TYPE="Debug" ;;
        *)
            echo "usage: $0 [--debug]" >&2
            exit 2
            ;;
    esac
done

# This script's own directory is the signal2sip checkout; dependencies go
# one level up, as siblings of it - not a hardcoded ~/GIT/<anything>.
SIGNAL2SIP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GIT_ROOT="$(dirname "$SIGNAL2SIP_DIR")"
cd "$GIT_ROOT"

# Pinned to what this project's own dev checkout uses as of 08-03 - bump
# these deliberately, not by accident, if upstream/the forks move on.
LIBSIGNAL_COMMIT="97801d22dcf9f5bf714f7b8fa3212cdc973ae1c8"
WEBRTC_PATCH_COMMIT="4f5e63d65e606c9f7745e9a754e4f273023b63a8"
# signal2sip/pjproject-tls's signal2sip-2.14.1-sni-fix branch, not
# upstream pjsip/pjproject's own 2.14.1 tag directly - carries one real
# patch on top: ssl_set_peer_name() (pjlib/src/pj/ssl_sock_ossl.c)
# SIGSEGVs during the TLS handshake whenever sip_host is a hostname
# (not an IP literal), a genuine PJSIP bug present in every version
# checked from 2.14.1 through current master (confirmed live via gdb,
# and by diffing upstream's own history - not fixed by any upstream
# commit). See signal2sip/pjproject-tls#1 for the full writeup;
# verified fixed 2026-08-10 with a real hostname-based TLS registration
# against DPDZK's Asterisk.
#
# A 2.17 migration was attempted the same day (branch
# signal2sip-2.17-sni-fix still exists, carries this same SNI fix plus
# two cherry-picked upstream fixes - pjlib pool allocator hardening
# 2a161e3b0, pjmedia/conference race fixes db33371d6+93410b161) but was
# reverted: real calls (SIP side not answering) reliably SIGABRT the
# daemon with a "double free or corruption" inside pjmedia's conference
# bridge port-removal path (conf_port_on_destroy -> pj_pool_destroy_int),
# root-caused as far as a likely trigger - RingRtcSipBridge's
# audio_input_/audio_output_ ports get added then almost immediately
# removed when the PBX side doesn't answer, racing 2.17's rewritten
# async (op-queue + group-lock-deferred) port removal in a way neither
# of those two upstream fixes fully covers - but not fixed. Stay on
# 2.14.1 until that's actually root-caused; don't re-attempt the 2.17
# move by just bumping this tag without addressing that first.
PJPROJECT_TAG="2.14.1"
PJPROJECT_BRANCH="signal2sip-2.14.1-sni-fix"

# depot_tools (gclient/gn/ninja) - required by ringrtc's own
# bin/gsync-webrtc / bin/build-desktop for the WebRTC step below. Found
# live that a fresh shell has no idea where this is even once cloned, so
# export it explicitly rather than relying on the caller's own PATH/rc
# files having it (this script runs non-interactively).
if [ ! -d depot_tools ]; then
    git clone https://chromium.googlesource.com/chromium/tools/depot_tools.git
fi
export PATH="$GIT_ROOT/depot_tools:$PATH"
# A freshly-cloned depot_tools hasn't bootstrapped itself yet - the
# python-bin/python3 wrapper build-desktop's own tooling calls refuses to
# run until depot_tools/python3_bin_reldir.txt exists. Neither
# `gclient --version` nor `update_depot_tools` actually create that file
# on Linux (found live: gclient sync ran fine without it, using its own
# vpython path, then build-desktop's separate wrapper failed on the exact
# same missing-file error regardless) - `ensure_bootstrap` is the one that
# actually writes it (see depot_tools/bootstrap/bootstrap.py).
( cd depot_tools && ./ensure_bootstrap )

echo "=== [1/6] System packages ==="
# Root doesn't need sudo, and some minimal containers/VMs (found live on
# .82) don't even have the sudo package installed - only shell out to it
# when actually running as a non-root user.
SUDO=""
if [ "$(id -u)" -ne 0 ]; then
    SUDO="sudo"
fi
$SUDO apt-get update -y

# lld-21 specifically, NOT the plain distro `lld` package: its version
# varies by Debian release, and bookworm's own (14.0.6) mislinks
# signal2sip-daemon into a pre-main() segfault - see CMakeLists.txt's
# PIN_LLD21 comment and project_signal2sip_debian12_daemon_crash memory.
# apt.llvm.org ships the same Clang/LLVM 21 packages on every Debian
# release, same approach tg2sip-webrtc's own CI already uses for its
# toolchain pin - added unconditionally (idempotent: apt-get install on an
# already-installed package is a silent no-op) rather than only on
# bookworm, so a from-scratch build stays identical everywhere instead of
# depending on whichever version a given release's own repos happen to
# carry (trixie's own trixie-backports has lld-21 too, but backports isn't
# guaranteed enabled on a fresh box, and relying on it instead of a pinned
# source would silently drift out of sync with what bookworm needs).
if ! apt-cache policy lld-21 2>/dev/null | grep -q "Candidate:.*[0-9]"; then
    $SUDO apt-get install -y wget gnupg
    CODENAME="$(. /etc/os-release && echo "$VERSION_CODENAME")"
    wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | $SUDO gpg --batch --yes --dearmor -o /usr/share/keyrings/llvm-snapshot.gpg
    echo "deb [signed-by=/usr/share/keyrings/llvm-snapshot.gpg] http://apt.llvm.org/$CODENAME/ llvm-toolchain-$CODENAME-21 main" | \
        $SUDO tee /etc/apt/sources.list.d/llvm.list >/dev/null
    $SUDO apt-get update -y
fi

$SUDO apt-get install -y \
    build-essential cmake git curl pkg-config python3 lld-21 \
    libssl-dev libcurl4-openssl-dev libqrencode-dev \
    libwebsockets-dev nlohmann-json3-dev \
    protobuf-compiler libprotobuf-dev libsqlcipher-dev \
    libclang-dev clang libpulse-dev libftxui-dev

echo "=== [2/6] Rust toolchains (nightly for libsignal, 1.91.1 for ringrtc) ==="
if ! command -v rustup >/dev/null 2>&1; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
fi
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
rustup toolchain install nightly-2026-07-15 1.91.1

echo "=== [3/6] libsignal-ffi (release) ==="
if [ ! -d libsignal ]; then
    git clone https://github.com/signalapp/libsignal.git
fi
git -C libsignal fetch origin
git -C libsignal checkout "$LIBSIGNAL_COMMIT"
( cd libsignal/rust && cargo build --release -p libsignal-ffi )

echo "=== [4/6] ringrtc + webrtc from source (release), with our patches ==="
if [ ! -d ringrtc ]; then
    git clone https://github.com/signal2sip/ringrtc.git
fi
git -C ringrtc fetch origin
git -C ringrtc checkout main
git -C ringrtc reset --hard origin/main
# gsync-webrtc writes webrtc-version.env into $OUTPUT_DIR (ringrtc/out by
# default) but never creates that directory itself - found live, nothing
# else in this pipeline creates it first either.
mkdir -p ringrtc/out
( cd ringrtc && bin/gsync-webrtc )
# gsync-webrtc always checks out whatever upstream release branch-head
# config/version.sh pins (see env.sh's WEBRTC_REVISION) - our own patch
# commit sits one commit ahead of that on the fork's main branch, so it
# needs applying explicitly on top; cherry-pick (not a hard reset to our
# main) because the pinned branch-head is the correct base to build
# against, we just want this one patch added to it.
git -C ringrtc/src/webrtc/src fetch origin
if ! git -C ringrtc/src/webrtc/src cat-file -e "$WEBRTC_PATCH_COMMIT" 2>/dev/null; then
    echo "ERROR: $WEBRTC_PATCH_COMMIT not found in the webrtc checkout - check signal2sip/webrtc is what gsync-webrtc actually pulled (config/webrtc.gclient.common)."
    exit 1
fi
git -C ringrtc/src/webrtc/src cherry-pick "$WEBRTC_PATCH_COMMIT"
( cd ringrtc && bin/build-desktop --webrtc-only -r )
( cd ringrtc/src/rust && OUTPUT_DIR="$GIT_ROOT/ringrtc/out" cargo build --features native --release )

echo "=== [5/6] Dedicated PJSIP $PJPROJECT_TAG (OpenSSL 3-safe, +SNI fix) ==="
if [ ! -d pjproject-tls ]; then
    git clone --branch "$PJPROJECT_BRANCH" --depth 1 https://github.com/signal2sip/pjproject-tls.git pjproject-tls
fi
if [ ! -f pjproject-tls/local-install/lib/pkgconfig/libpjproject.pc ]; then
    ( cd pjproject-tls && ./aconfigure --prefix="$GIT_ROOT/pjproject-tls/local-install" \
        --disable-sound CFLAGS="-O3 -DNDEBUG -fPIC" )
    ( cd pjproject-tls && make dep && make -j"$(nproc)" && make install )
fi

echo "=== [6/6] signal2sip itself ==="
# No clone here - this script only runs from inside an existing
# signal2sip checkout ($SIGNAL2SIP_DIR), so there's nothing to fetch.
mkdir -p "$SIGNAL2SIP_DIR/build"
( cd "$SIGNAL2SIP_DIR/build" && cmake -DCMAKE_BUILD_TYPE="$CMAKE_BUILD_TYPE" .. && cmake --build . -j"$(nproc)" )

echo "=== Done ==="
ls -lh "$SIGNAL2SIP_DIR/build/signal2sip-daemon" "$SIGNAL2SIP_DIR/build/signal2sip-gendb"
