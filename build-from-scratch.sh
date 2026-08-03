#!/bin/bash
# Full from-scratch build of signal2sip and every from-source dependency
# it needs: libsignal-ffi (Rust), ringrtc+webrtc (Rust/C++, with this
# project's AUDIO_TRANSPORT/raw-PCM patches), and a dedicated PJSIP 2.14.1
# (OpenSSL-3-safe, isolated from any system/shared PJSIP install a box
# might already have for something else, e.g. tg2sip-webrtc).
#
# Clones everything under ~/GIT/vladonv/ to match native/CMakeLists.txt's
# own default CACHE PATH values (LIBSIGNAL_DIR/RINGRTC_DIR/PJPROJECT_DIR) -
# no -D overrides needed if this script is just run as-is.
#
# Needs, before running: a GH_TOKEN env var with at least read access to
# the private vladonv/signal2sip repo (a fine-grained PAT is enough - this
# script only ever clones/fetches it, never pushes). Everything else
# (libsignal, ringrtc, webrtc, pjproject) is public.
#
# The webrtc step is genuinely heavy (depot_tools/gclient pulls WebRTC's
# full third-party tree, tens of GB, then compiles it) - budget real time
# and disk (100GB+ free is a safe bet) for that one step specifically;
# everything else here is comparatively quick.

set -euo pipefail

GIT_ROOT="$HOME/GIT/vladonv"
mkdir -p "$GIT_ROOT"
cd "$GIT_ROOT"

# Pinned to what this project's own dev checkout uses as of 08-03 - bump
# these deliberately, not by accident, if upstream/the forks move on.
LIBSIGNAL_COMMIT="97801d22dcf9f5bf714f7b8fa3212cdc973ae1c8"
WEBRTC_PATCH_COMMIT="0afdc03505cde0fcf72a545df51fcb4b7b6c5931"
PJPROJECT_TAG="2.14.1"

echo "=== [1/6] System packages ==="
sudo apt-get update -y
sudo apt-get install -y \
    build-essential cmake git curl pkg-config python3 lld \
    libssl-dev libcurl4-openssl-dev libqrencode-dev \
    libwebsockets-dev nlohmann-json3-dev \
    protobuf-compiler libprotobuf-dev libsqlcipher-dev

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
    git clone https://github.com/vladonv/ringrtc.git
fi
git -C ringrtc fetch origin
git -C ringrtc checkout main
git -C ringrtc reset --hard origin/main
( cd ringrtc && bin/gsync-webrtc )
# gsync-webrtc always checks out whatever upstream release branch-head
# config/version.sh pins (see env.sh's WEBRTC_REVISION) - our own patch
# commit sits one commit ahead of that on the fork's main branch, so it
# needs applying explicitly on top; cherry-pick (not a hard reset to our
# main) because the pinned branch-head is the correct base to build
# against, we just want this one patch added to it.
git -C ringrtc/src/webrtc/src fetch origin
if ! git -C ringrtc/src/webrtc/src cat-file -e "$WEBRTC_PATCH_COMMIT" 2>/dev/null; then
    echo "ERROR: $WEBRTC_PATCH_COMMIT not found in the webrtc checkout - check vladonv/webrtc is what gsync-webrtc actually pulled (config/webrtc.gclient.common)."
    exit 1
fi
git -C ringrtc/src/webrtc/src cherry-pick "$WEBRTC_PATCH_COMMIT"
( cd ringrtc && bin/build-desktop --webrtc-only -r )
( cd ringrtc/src/rust && OUTPUT_DIR="$GIT_ROOT/ringrtc/out" cargo build --features native --release )

echo "=== [5/6] Dedicated PJSIP $PJPROJECT_TAG (OpenSSL 3-safe) ==="
if [ ! -d pjproject-tls ]; then
    git clone --branch "$PJPROJECT_TAG" --depth 1 https://github.com/pjsip/pjproject.git pjproject-tls
fi
if [ ! -f pjproject-tls/local-install/lib/pkgconfig/libpjproject.pc ]; then
    ( cd pjproject-tls && ./aconfigure --prefix="$GIT_ROOT/pjproject-tls/local-install" \
        --disable-sound CFLAGS="-O3 -DNDEBUG -fPIC" )
    ( cd pjproject-tls && make dep && make -j"$(nproc)" && make install )
fi

echo "=== [6/6] signal2sip itself ==="
if [ ! -d signal2sip ]; then
    : "${GH_TOKEN:?GH_TOKEN must be set to clone the private vladonv/signal2sip repo}"
    git clone "https://oauth2:${GH_TOKEN}@github.com/vladonv/signal2sip.git"
fi
mkdir -p signal2sip/native/build
( cd signal2sip/native/build && cmake .. && cmake --build . -j"$(nproc)" )

echo "=== Done ==="
ls -lh signal2sip/native/build/signal2sip-daemon signal2sip/native/build/signal2sip-gendb
