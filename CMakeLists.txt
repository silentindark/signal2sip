cmake_minimum_required(VERSION 3.16)
project(signal2sip-native CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Default to Release if the caller didn't ask for anything else - found
# live that signal2sip-daemon/signal2sip-gendb were previously coming out
# at 400-500MB, ~82% of that unstripped debug info (WebRTC/RingRTC/PJSIP's
# own static libs all carry their own debug sections, none of which get
# trimmed just by our own code being small) - stripped to ~85-90MB with
# nothing else changed. See the `-s` link option on the two real
# executables below, scoped to Release only (test binaries keep their
# symbols, since those are for debugging failures locally, not deploying).
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

# Debian 12 bookworm's default lld (14.0.6, the plain `lld` apt package)
# mislinks any binary pulling in two independent Rust static libs at once
# (libsignal_ffi.a + libringrtc.a - only signal2sip-daemon does both, see
# the --allow-multiple-definition comment below) - confirmed live on .82:
# signal2sip-daemon segfaulted before main() even ran, inside
# libprotobuf's own ELF constructor (InitProtobufDefaultsSlow), rip
# landing at address 0x1. Debian 13 trixie's default lld (19.1.7, this
# project's main dev machine) links the exact same sources fine - the bug
# is specific to bookworm's older lld picking the wrong copy of a
# duplicate symbol. Pin an explicit newer lld everywhere instead of
# trusting whatever a given Debian release's plain `lld` package happens
# to default to, same reasoning tg2sip-webrtc's debian/rules already
# applies to its own Clang/LLVM version pin.
# GCC (this project's compiler; no CMAKE_CXX_COMPILER override anywhere
# in this file) doesn't understand Clang's -fuse-ld=lld-21 suffix
# spelling ("unrecognized command-line option '-fuse-ld=lld-21'; did you
# mean '-fuse-ld=lld'?", confirmed live) - -B<dir> instead adds LLVM 21's
# own bin/ to GCC's linker search path, so the plain -fuse-ld=lld below
# resolves collect2's "ld.lld" lookup to that directory's copy rather
# than /usr/bin/ld.lld's distro-default symlink.
set(LLD21_BINDIR "/usr/lib/llvm-21/bin" CACHE PATH
    "LLVM 21's own bin/ dir (apt.llvm.org on bookworm, trixie-backports locally) - see PIN_LLD21 below")
set(PIN_LLD21 -B${LLD21_BINDIR} -fuse-ld=lld)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLCIPHER REQUIRED IMPORTED_TARGET sqlcipher)
pkg_check_modules(LIBWEBSOCKETS REQUIRED IMPORTED_TARGET libwebsockets)
# Was the same shared /usr/local install tg2sip-webrtc itself links
# against (PJSIP 2.9, built with --disable-sound - fine for us too, since
# the whole point of Milestone F's ring-buffer bridge is to never touch
# PJSIP's own sound-device layer; it registers custom virtual pjmedia_port
# objects via registerMediaPort() instead, same proven pattern
# tg2sip-webrtc uses for its own calls) - until 08-03, when
# sip_transport=tls (native/daemon/main.cpp) turned out to SEGV the whole
# daemon on any real TLS connection: PJSIP 2.9's OpenSSL glue
# (pjlib/src/pj/ssl_sock_ossl.c) predates upstream's OpenSSL 3 support
# (commit 914ce755a, first shipped in tag 2.14), and this box's system
# OpenSSL is 3.x. Rather than upgrade the SHARED /usr/local install
# in-place (real risk to tg2sip-webrtc, a separately-deployed production
# service depending on that exact 2.9 build), this points ONLY
# signal2sip's own build at a second, independent PJSIP checkout - same
# --disable-sound flags, just a newer, OpenSSL-3-safe tag (2.14.1,
# deliberately the earliest tag with the fix rather than the latest
# release, to minimize unrelated behavior drift from the already-proven
# 2.9 codepaths this project depends on elsewhere). /usr/local and
# tg2sip-webrtc's own build are never touched by this.
set(PJPROJECT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../pjproject-tls/local-install" CACHE PATH
    "Dedicated PJSIP 2.14.1+ install with OpenSSL 3 support - NOT /usr/local, which stays on 2.9 for tg2sip-webrtc")
set(ENV{PKG_CONFIG_PATH} "${PJPROJECT_DIR}/lib/pkgconfig:$ENV{PKG_CONFIG_PATH}")
pkg_check_modules(PJSIP REQUIRED IMPORTED_TARGET libpjproject)
# 2.14.1's libpjproject.pc properly splits public Libs: (just the pj*
# archives themselves) from Libs.private: (their own transitive deps -
# uuid, srtp, resample, the codec libs, PJSIP's own vendored echo-canceller
# "webrtc" module, opus/ssl/crypto/vpx/av*) - the OLD 2.9 .pc file dumped
# everything into one public Libs: line instead (a packaging-metadata
# change upstream, confirmed by diffing both .pc files - not a new
# dependency we didn't already have), so PkgConfig::PJSIP's default
# (public-only) link libraries used to be complete by accident. CMake's
# pkg_check_modules(... IMPORTED_TARGET ...) only wires up the public set
# automatically; add the private set explicitly since we link PJSIP
# statically. (PJSIP's own "-lwebrtc-*" here is its unrelated, vendored
# echo-canceller module, not RingRTC's real WebRTC - the old build already
# linked it the same way with no symbol collision against the `webrtc`
# CMake target below, so this isn't new risk.)
target_link_libraries(PkgConfig::PJSIP INTERFACE ${PJSIP_STATIC_LDFLAGS})
find_package(Protobuf REQUIRED)
find_package(nlohmann_json REQUIRED)
# CURL: plain HTTPS for RegistrationClient (native/util/) - used by gendb's
# Flow A/B and, since 08-05, the daemon's StorageServiceSync (storage.signal.org
# is a plain-REST host too, unlike chat.signal.org's persistent-websocket
# AuthSocket). OpenSSL::Crypto: AES-256-CBC/HMAC-SHA256 for gendb's
# provisioning cipher (Flow B) and StorageServiceSync's own AES-256-GCM/HMAC.
find_package(CURL REQUIRED)
find_package(OpenSSL REQUIRED)
pkg_check_modules(QRENCODE REQUIRED IMPORTED_TARGET libqrencode)

# signal2sip-tui only - see native/tui/main.cpp's own doc comment.
# Packaged in Debian's apt archive (libftxui-dev) - a real dependency, not
# hand-rolled raw ncurses escape sequences, deliberately: FTXUI's
# flexbox-like layout is what makes maintaining several real screens
# (account list/detail/config-edit/wizard) tractable, unlike this
# project's usual "small hand-rolled parser" preference for things that
# genuinely are simple.
find_package(ftxui REQUIRED)

# Signal's on-the-wire message shapes, unchanged from the Node prototype -
# same .proto sources (pulled from signalapp/Signal-Android, see
# ../PROTOCOL.md), compiled fresh for C++ instead of loaded at runtime via
# protobufjs.
set(SIGNAL_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(SIGNAL_PROTO_FILES
    ${SIGNAL_PROTO_DIR}/SignalService.proto
    ${SIGNAL_PROTO_DIR}/WebSocketResources.proto
    ${SIGNAL_PROTO_DIR}/Provisioning.proto
    ${SIGNAL_PROTO_DIR}/StorageService.proto
    ${SIGNAL_PROTO_DIR}/DeviceName.proto
)
protobuf_generate_cpp(SIGNAL_PROTO_SRCS SIGNAL_PROTO_HDRS ${SIGNAL_PROTO_FILES})

add_library(signal2sip_proto STATIC ${SIGNAL_PROTO_SRCS})
target_include_directories(signal2sip_proto PUBLIC ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(signal2sip_proto PUBLIC protobuf::libprotobuf)

# Embed storage/schema.sql into a generated header so the schema ships
# inside the binary (no runtime dependency on a .sql file next to it) while
# schema.sql itself stays a plain, directly-runnable SQL file for reference/
# manual testing. Re-run cmake if schema.sql changes.
file(READ ${CMAKE_CURRENT_SOURCE_DIR}/storage/schema.sql SCHEMA_SQL)
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/storage/schema_sql.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/schema_sql.h
    @ONLY
)

add_library(signal2sip_storage STATIC
    storage/Storage.cpp
)
target_include_directories(signal2sip_storage
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR}
)
target_link_libraries(signal2sip_storage PUBLIC PkgConfig::SQLCIPHER)

add_library(signal2sip_util STATIC
    util/Base64.cpp
    util/RegistrationClient.cpp
)
target_include_directories(signal2sip_util PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip_util PUBLIC CURL::libcurl)

add_executable(storage_test test/storage_test.cpp)
target_link_libraries(storage_test PRIVATE signal2sip_storage)

add_library(signal2sip_padding STATIC
    signal/Padding.cpp
)
target_include_directories(signal2sip_padding PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip_padding PUBLIC signal2sip_storage)

add_executable(padding_test test/padding_test.cpp)
target_link_libraries(padding_test PRIVATE signal2sip_padding)

add_library(signal2sip_authsocket STATIC
    signal/AuthSocket.cpp
)
target_include_directories(signal2sip_authsocket PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip_authsocket PUBLIC signal2sip_storage signal2sip_proto signal2sip_util PkgConfig::LIBWEBSOCKETS)

add_executable(authsocket_test test/authsocket_test.cpp)
target_link_libraries(authsocket_test PRIVATE signal2sip_authsocket)

# libsignal's C ABI (see /home/vlad/.claude/plans/jiggly-mapping-plum.md
# Milestone B) - built via `cargo build -p libsignal-ffi` in the sibling
# ../libsignal checkout (a directory up from this repo, not inside it -
# see build-from-scratch.sh). LIBSIGNAL_DIR lets that path be overridden;
# signal_ffi.h is a checked-in generated file in that repo, not a build
# artifact, so it's read straight from its source location.
#
# signal_ffi.h is generated for C consumption and isn't quite valid C++:
# two enums (SignalFfiPublicKeyType, SignalSvr2CredentialsResult) declare
# `enum Name { ... };` immediately followed by an unrelated `typedef
# uint8_t Name;` - legal in C (separate tag/ordinary namespaces) but a
# redeclaration conflict in C++ (enum tags share the ordinary namespace
# there). We use neither enum tag directly (only the plain uint8_t
# typedefs, which every function signature actually uses), so the fix is
# to rename just the two conflicting `enum Name {` tags in a patched copy
# - never touch the checked-out libsignal repo itself.
#
# It also declares every function with plain C linkage in mind (matching
# the plain, unmangled `signal_*` symbol names the Rust side exports via
# #[no_mangle] extern "C" fns - confirmed with `nm` against the built
# libsignal_ffi.a) but has no `extern "C" { ... }` guard of its own, so a
# C++ translation unit including it directly would silently C++-mangle
# every declaration and then fail to link against those plain symbols.
# Wrap the whole patched copy in extern "C" to match the real ABI.
set(LIBSIGNAL_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../libsignal" CACHE PATH "Path to the libsignal checkout")
file(READ ${LIBSIGNAL_DIR}/swift/Sources/SignalFfi/signal_ffi.h SIGNAL_FFI_H_CONTENT)
string(REPLACE "enum SignalFfiPublicKeyType {" "enum SignalFfiPublicKeyType_Tag {" SIGNAL_FFI_H_CONTENT "${SIGNAL_FFI_H_CONTENT}")
string(REPLACE "enum SignalSvr2CredentialsResult {" "enum SignalSvr2CredentialsResult_Tag {" SIGNAL_FFI_H_CONTENT "${SIGNAL_FFI_H_CONTENT}")
set(SIGNAL_FFI_H_CONTENT "#ifdef __cplusplus\nextern \"C\" {\n#endif\n${SIGNAL_FFI_H_CONTENT}\n#ifdef __cplusplus\n}\n#endif\n")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/generated/signal_ffi_cxx/signal_ffi.h "${SIGNAL_FFI_H_CONTENT}")

# target/release, not target/debug (`cargo build --release -p
# libsignal-ffi`) - found live 08-03 that the debug archive is 1.2GB vs
# release's 192MB, and directly inflates both signal2sip-daemon and
# signal2sip-gendb's final size (gendb links almost nothing else
# statically, so its whole ~66MB was essentially this). Matches
# RINGRTC_DIR's own target/release convention just below.
# libsignal_ffi.a vendors its own separate BoringSSL-family copy (aws-lc-rs,
# monolithic module bcm.cc.o) that collides with system OpenSSL's plain-C
# API the exact same way WebRTC's bcm.o does - see
# tools/isolate_webrtc_boringssl_symbols.py's docstring (found chasing the
# same aesGcmDecrypt() bug: isolating WebRTC's copy alone wasn't enough,
# since this archive's copy - earlier on the link line than the real
# -lcrypto - silently took over instead).
set(LIBSIGNAL_FFI_OPENSSL_SAFE ${CMAKE_CURRENT_BINARY_DIR}/generated/libsignal_ffi_openssl_safe.a)
add_custom_command(
    OUTPUT ${LIBSIGNAL_FFI_OPENSSL_SAFE}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/generated
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tools/isolate_webrtc_boringssl_symbols.py
            ${LIBSIGNAL_DIR}/target/release/libsignal_ffi.a ${LIBSIGNAL_FFI_OPENSSL_SAFE}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tools/isolate_webrtc_boringssl_symbols.py
            ${LIBSIGNAL_DIR}/target/release/libsignal_ffi.a
    COMMENT "Isolating libsignal_ffi's bundled BoringSSL-family crypto symbols from system OpenSSL's"
    VERBATIM
)
add_custom_target(libsignal_ffi_openssl_safe_gen DEPENDS ${LIBSIGNAL_FFI_OPENSSL_SAFE})
add_library(libsignal_ffi STATIC IMPORTED)
set_target_properties(libsignal_ffi PROPERTIES
    IMPORTED_LOCATION ${LIBSIGNAL_FFI_OPENSSL_SAFE}
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/generated/signal_ffi_cxx
)
add_dependencies(libsignal_ffi libsignal_ffi_openssl_safe_gen)

add_library(signal2sip_signal STATIC
    signal/ProtocolStores.cpp
    signal/Crypto.cpp
    signal/PreKeys.cpp
    signal/Cdsi.cpp
)
target_include_directories(signal2sip_signal PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip_signal PUBLIC signal2sip_storage signal2sip_padding signal2sip_util libsignal_ffi
    ${CMAKE_DL_LIBS} pthread m)

add_executable(signal_roundtrip_test test/signal_roundtrip_test.cpp)
target_link_libraries(signal_roundtrip_test PRIVATE signal2sip_signal signal2sip_authsocket signal2sip_proto
    signal2sip_config nlohmann_json::nlohmann_json)

# Local-only (no chat.signal.org) unit test for the DecryptionErrorMessage
# session-recovery feature - just signal2sip_signal, no AuthSocket/proto/
# json needed.
add_executable(decryption_error_message_test test/decryption_error_message_test.cpp)
target_link_libraries(decryption_error_message_test PRIVATE signal2sip_signal)

add_executable(refresh_prekeys_test test/refresh_prekeys_test.cpp)
target_link_libraries(refresh_prekeys_test PRIVATE signal2sip_signal signal2sip_authsocket signal2sip_proto
    signal2sip_config nlohmann_json::nlohmann_json)

# Live verification for Cdsi.h (see that file's own doc comment) - needs
# AuthSocket only to fetch the short-lived directory-service token
# (GET /v2/directory/auth); CDSI itself is a separate libsignal `net`
# transport, not signal2sip's usual chat.signal.org websocket.
add_executable(cdsi_lookup_test test/cdsi_lookup_test.cpp)
target_link_libraries(cdsi_lookup_test PRIVATE signal2sip_signal signal2sip_authsocket signal2sip_config
    nlohmann_json::nlohmann_json)

# One-off scratch helper (see the file's own doc comment) - not linked into
# anything else, exists purely to feed refresh_prekeys_test/cdsi_lookup_test
# a real account's credentials without hand-copying them out of the DB.
add_executable(dump_account_json_test test/dump_account_json_test.cpp)
target_link_libraries(dump_account_json_test PRIVATE signal2sip_storage nlohmann_json::nlohmann_json)

# One-off scratch helper (see the file's own doc comment) - forces a live
# PUT /v1/accounts/attributes/ discoverableByPhoneNumber change to kick
# Signal's CDS directory-sync pipeline for an account with no real app UI.
add_executable(toggle_discoverability_test test/toggle_discoverability_test.cpp)
target_link_libraries(toggle_discoverability_test PRIVATE signal2sip_storage signal2sip_authsocket
    nlohmann_json::nlohmann_json)

# Live verification for ContactResolver.h - the cache+CDSI resolution path
# signal2sip-daemon itself now uses for outgoing_call_target, minus the
# actual signal2sip_call_start_outgoing call (so this never places a real
# call to whatever target it's given).
add_executable(resolve_outgoing_target_test test/resolve_outgoing_target_test.cpp)
target_link_libraries(resolve_outgoing_target_test PRIVATE signal2sip_daemon signal2sip_storage
    signal2sip_authsocket)

# Isolation test for the "no active codec"/PJSIP_ESESSIONINSECURE bugs
# found live 08-04 in startSipBridge() - mirrors main.cpp's shared-Endpoint
# SIP setup exactly (no RingRTC/Signal at all) so this can be iterated on
# without needing a real phone call each time.
add_executable(sip_bridge_codec_test test/sip_bridge_codec_test.cpp)
target_include_directories(sip_bridge_codec_test PRIVATE ${PJSIP_INCLUDE_DIRS})
target_link_libraries(sip_bridge_codec_test PRIVATE PkgConfig::PJSIP)

# RingRTC's Milestone D/E C ABI (see /home/vlad/.claude/plans/
# jiggly-mapping-plum.md and this project's memory) - built via `cargo
# build --features native --release` (no `prebuilt_webrtc`) in the
# sibling ../ringrtc checkout (a directory up from this repo, not inside
# it - see build-from-scratch.sh), linking a from-source WebRTC static lib
# (`bin/gsync-webrtc` + `bin/build-desktop --webrtc-only -r`) with the
# per-instance AUDIO_TRANSPORT fix baked in
# (../webrtc/ringrtc/rffi/src/audio_device.cc, a sibling of ../ringrtc -
# Signal's official prebuilt binary obviously doesn't have this). RELEASE,
# not debug, purely to match what the original Signal-prebuilt path always
# used - NOT because debug vs release was ever the cause of the "Failed
# to setup SRTP crypto parameters" regression (that was tried as a
# hypothesis and disproven: release reproduced the identical failure).
# The actual cause was signal2sip-daemon's own link line reintroducing
# the raw `webrtc` target's vendored libsrtp symbols alongside
# webrtc_pjsip_safe - see the comment there.
# ringrtc/signal2sip_ringrtc.h (this repo) is hand-written (that crate has
# no cbindgen setup) and kept in sync with cpp_ffi.rs manually.
set(RINGRTC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../ringrtc" CACHE PATH "Path to the ringrtc checkout")
add_library(ringrtc STATIC IMPORTED)
set_target_properties(ringrtc PROPERTIES
    IMPORTED_LOCATION ${RINGRTC_DIR}/target/release/libringrtc.a
)
add_library(webrtc STATIC IMPORTED)
set_target_properties(webrtc PROPERTIES
    IMPORTED_LOCATION ${RINGRTC_DIR}/out/release/obj/libwebrtc.a
)

add_executable(ringrtc_two_party_test test/ringrtc_two_party_test.cpp)
target_include_directories(ringrtc_two_party_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(ringrtc_two_party_test PRIVATE ringrtc webrtc ${CMAKE_DL_LIBS} pthread m stdc++ pulse)
# GNU ld chokes on the prebuilt WebRTC static lib's .eh_frame sections
# (hundreds of "table will not be created" errors, fatal in this ld
# version, --no-eh-frame-hdr does not suppress it) - lld (Chromium's own
# toolchain's usual linker) handles them fine.
target_link_options(ringrtc_two_party_test PRIVATE ${PIN_LLD21})

# fancy-swimming-church.md §0: proves two independent CallManagers (and
# therefore two independent raw-PCM ADMs) can run concurrently in one
# process without crossing audio - only meaningful once linked against a
# webrtc.a built with the per-instance AUDIO_TRANSPORT fix, see this
# file's own top-of-file comment.
add_executable(two_call_managers_audio_isolation_test test/two_call_managers_audio_isolation_test.cpp)
target_include_directories(two_call_managers_audio_isolation_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(two_call_managers_audio_isolation_test PRIVATE ringrtc webrtc ${CMAKE_DL_LIBS} pthread m stdc++ pulse)
target_link_options(two_call_managers_audio_isolation_test PRIVATE ${PIN_LLD21})

# Milestone F: bridges the ring-buffer PJSIP ports (ported from
# tg2sip-webrtc/tg2sip/voip/{ring_buffer,audio_bridge}.h) to RingRTC's
# raw-PCM C ABI - see native/voip/ringrtc_sip_bridge.h.
#
# Any binary linking both `webrtc` (RingRTC's prebuilt WebRTC, which
# vendors its own libsrtp) and PJSIP (which vendors a separate,
# differently-versioned copy of the exact same libsrtp API under the
# exact same symbol names) must NOT link the plain `webrtc` target above -
# see tools/isolate_webrtc_srtp_symbols.py's docstring for the full story
# (real bug hit live: pjsua_init() failed with a libsrtp bad_param error
# because PJSIP's calls silently resolved into WebRTC's incompatible
# copy, since libwebrtc.a comes first on the link line). Use
# `webrtc_pjsip_safe` instead, a derived copy with the vendored libsrtp's
# plain-C symbols renamed out of the way.
# Two isolation passes chained (order doesn't matter - disjoint symbol
# namespaces, see isolate_webrtc_boringssl_symbols.py's docstring): first
# libsrtp's plain-C API (PJSIP collision), then BoringSSL's bcm.o crypto
# surface (system OpenSSL collision - see that script's docstring for the
# real aesGcmDecrypt() bug this fixes, found 2026-08-06).
set(WEBRTC_SRTP_SAFE_LIB ${CMAKE_CURRENT_BINARY_DIR}/generated/libwebrtc_srtp_safe.a)
set(WEBRTC_PJSIP_SAFE_LIB ${CMAKE_CURRENT_BINARY_DIR}/generated/libwebrtc_pjsip_safe.a)
add_custom_command(
    OUTPUT ${WEBRTC_SRTP_SAFE_LIB}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/generated
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tools/isolate_webrtc_srtp_symbols.py
            ${RINGRTC_DIR}/out/release/obj/libwebrtc.a ${WEBRTC_SRTP_SAFE_LIB}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tools/isolate_webrtc_srtp_symbols.py
            ${RINGRTC_DIR}/out/release/obj/libwebrtc.a
    COMMENT "Isolating WebRTC's vendored libsrtp symbols from PJSIP's"
    VERBATIM
)
add_custom_command(
    OUTPUT ${WEBRTC_PJSIP_SAFE_LIB}
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tools/isolate_webrtc_boringssl_symbols.py
            ${WEBRTC_SRTP_SAFE_LIB} ${WEBRTC_PJSIP_SAFE_LIB}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tools/isolate_webrtc_boringssl_symbols.py
            ${WEBRTC_SRTP_SAFE_LIB}
    COMMENT "Isolating WebRTC's bundled BoringSSL crypto symbols from system OpenSSL's"
    VERBATIM
)
add_custom_target(webrtc_pjsip_safe_gen DEPENDS ${WEBRTC_PJSIP_SAFE_LIB})
add_library(webrtc_pjsip_safe STATIC IMPORTED)
set_target_properties(webrtc_pjsip_safe PROPERTIES IMPORTED_LOCATION ${WEBRTC_PJSIP_SAFE_LIB})
add_dependencies(webrtc_pjsip_safe webrtc_pjsip_safe_gen)

add_library(signal2sip_voip STATIC
    voip/audio_bridge.cpp
    voip/ringrtc_sip_bridge.cpp
)
target_include_directories(signal2sip_voip PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip_voip PUBLIC PkgConfig::PJSIP ringrtc webrtc_pjsip_safe)

add_executable(pjsip_ringrtc_echo_test test/pjsip_ringrtc_echo_test.cpp)
target_include_directories(pjsip_ringrtc_echo_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(pjsip_ringrtc_echo_test PRIVATE signal2sip_voip ringrtc webrtc_pjsip_safe ${CMAKE_DL_LIBS} pthread m stdc++ pulse)
target_link_options(pjsip_ringrtc_echo_test PRIVATE ${PIN_LLD21})

# signal2sip.conf parsing - its own tiny target (not folded into
# signal2sip_daemon below) so gendb (native/gendb/) can read the same
# config/account sections without pulling in RingRTC/WebRTC/PJSIP, none of
# which gendb needs.
add_library(signal2sip_config STATIC
    daemon/Config.cpp
)
target_include_directories(signal2sip_config PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Milestone G: bidirectional bridge between real Signal CallMessage
# protobufs and RingRTC's C ABI - see native/daemon/CallSignaling.h.
add_library(signal2sip_daemon STATIC
    daemon/CallSignaling.cpp
    daemon/ContactResolver.cpp
    daemon/StorageServiceSync.cpp
)
target_include_directories(signal2sip_daemon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip_daemon PUBLIC signal2sip_signal signal2sip_authsocket signal2sip_proto
    signal2sip_voip ringrtc webrtc_pjsip_safe nlohmann_json::nlohmann_json signal2sip_config OpenSSL::Crypto)

# Diagnostic for the aesGcmDecrypt()/BoringSSL-symbol-collision
# investigation - see test/storage_sync_loop_test.cpp's own doc comment.
add_executable(storage_sync_loop_test test/storage_sync_loop_test.cpp)
target_include_directories(storage_sync_loop_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(storage_sync_loop_test PRIVATE signal2sip_daemon signal2sip_signal signal2sip_authsocket
    signal2sip_proto signal2sip_voip ringrtc webrtc_pjsip_safe PkgConfig::PJSIP
    ${CMAKE_DL_LIBS} pthread m stdc++ pulse nlohmann_json::nlohmann_json)
target_link_options(storage_sync_loop_test PRIVATE ${PIN_LLD21} -Wl,--allow-multiple-definition)

add_executable(signal2sip-daemon daemon/main.cpp)
target_include_directories(signal2sip-daemon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
# Rust_rawPcmRecordedDataIsAvailable/Rust_rawPcmNeedMorePlayData are new
# symbols defined in ringrtc/rffi/src/audio_device.cc (§0 AUDIO_TRANSPORT
# fix, fancy-swimming-church.md). audio_device.o is NOT one of the object
# files isolate_webrtc_srtp_symbols.py touches (it only renames libsrtp's
# own vendored .o members - see CANDIDATE_NAMES above), so
# `webrtc_pjsip_safe` already exports these symbols untouched - do NOT
# also link the raw `webrtc` target here. Doing so once before (plus the
# --allow-multiple-definition flag below, needed for an unrelated
# rust_eh_personality clash) silently reintroduced the exact
# PJSIP/libsrtp collision webrtc_pjsip_safe exists to prevent: real calls
# failed applying the local answer SDP with "Failed to setup SRTP crypto
# parameters" (libsrtp err=2/bad_param from srtp_init(), since the raw,
# non-renamed copy came first on the link line again). Confirmed this was
# not a debug-vs-release WebRTC issue (both reproduced it identically).
target_link_libraries(signal2sip-daemon PRIVATE signal2sip_daemon signal2sip_signal signal2sip_authsocket
    signal2sip_proto signal2sip_voip ringrtc webrtc_pjsip_safe PkgConfig::PJSIP
    ${CMAKE_DL_LIBS} pthread m stdc++ pulse nlohmann_json::nlohmann_json)
target_link_options(signal2sip-daemon PRIVATE ${PIN_LLD21})
# libringrtc.a and libsignal_ffi.a are two INDEPENDENT Rust static libs
# (separate `cargo build` invocations, separate crates/workspaces) - each
# embeds its own copy of Rust std's runtime support symbols
# (rust_eh_personality etc), which collide as hard duplicate-definition
# link errors when both land in one binary (unlike the libwebrtc/libsrtp
# collision fixed above, which was a silent wrong-symbol-wins problem -
# this is the opposite: a byte-identical-in-effect symbol that the
# linker refuses to pick between). Turned out NOT safe to just take
# whichever copy lld happens to pick, contrary to what this comment used
# to claim: Debian 12 bookworm's lld 14.0.6 picks a copy that corrupts
# something global before libprotobuf.so's own ELF constructor runs,
# crashing signal2sip-daemon before main() (see PIN_LLD21 above and
# project memory project_signal2sip_debian12_daemon_crash) - lld 19+
# (this project's dev machine, and now the explicit PIN_LLD21 pin) picks
# a working copy instead.
target_link_options(signal2sip-daemon PRIVATE ${PIN_LLD21} -Wl,--allow-multiple-definition)
# Strips ~415MB of unstripped debug info WebRTC/RingRTC/PJSIP's own static
# libs carry (503MB -> ~88MB, measured directly) - Release only, so a
# Debug build (cmake -DCMAKE_BUILD_TYPE=Debug) still keeps symbols for
# local debugging.
target_link_options(signal2sip-daemon PRIVATE $<$<CONFIG:Release>:-s>)

# signal2sip-gendb: standalone companion binary creating a brand-new
# account (Flow A registration or Flow B device-linking) - see
# native/gendb/main.cpp and /home/vlad/.claude/plans/piped-mixing-summit.md.
# Deliberately does NOT link signal2sip_daemon/ringrtc/webrtc/PJSIP - none
# of Milestone C's account-creation flows touch calling or SIP, so this
# stays a small, fast-to-build binary with none of signal2sip-daemon's
# link-line workarounds.
add_library(signal2sip_gendb STATIC
    gendb/ProvisioningCipher.cpp
    gendb/ProvisioningClient.cpp
    gendb/AccountFinisher.cpp
    gendb/DeviceNameCipher.cpp
)
target_include_directories(signal2sip_gendb PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip_gendb PUBLIC signal2sip_signal signal2sip_storage signal2sip_proto
    signal2sip_config PkgConfig::LIBWEBSOCKETS CURL::libcurl OpenSSL::Crypto PkgConfig::QRENCODE)

add_executable(signal2sip-gendb gendb/main.cpp)
target_include_directories(signal2sip-gendb PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip-gendb PRIVATE signal2sip_gendb signal2sip_config signal2sip_signal
    signal2sip_storage signal2sip_authsocket signal2sip_proto CURL::libcurl OpenSSL::Crypto
    PkgConfig::LIBWEBSOCKETS PkgConfig::QRENCODE nlohmann_json::nlohmann_json ${CMAKE_DL_LIBS} pthread m)
# See signal2sip-daemon's own -s comment above - same deal here.
# PIN_LLD21: gendb also links libsignal_ffi_openssl_safe's BoringSSL Rust
# code (via signal2sip_signal), so it hits the same distro-lld eh_frame
# relocation failure signal2sip-daemon does - see PIN_LLD21 above and
# project memory project_signal2sip_debian12_daemon_crash.
target_link_options(signal2sip-gendb PRIVATE ${PIN_LLD21} $<$<CONFIG:Release>:-s>)

# Deliberately does NOT link signal2sip_signal/authsocket/ringrtc/webrtc/
# PJSIP - the TUI only ever reads the database directly (Storage's
# listAllAccounts()/loadAccount(), same as gendb) and shells out to the
# already-built signal2sip-gendb binary for every action (register/link/
# enable/disable/config set/...) instead of duplicating that logic here -
# see project memory project_signal2sip_tui_future.md for why. Keeps this
# a small, fast-to-build binary with none of signal2sip-daemon's
# Rust-FFI/PJSIP link-line workarounds, same reasoning signal2sip_gendb's
# own comment gives for itself above.
add_executable(signal2sip-tui tui/main.cpp)
target_include_directories(signal2sip-tui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip-tui PRIVATE signal2sip_storage signal2sip_config
    ftxui::component ftxui::dom ftxui::screen pthread)
target_link_options(signal2sip-tui PRIVATE ${PIN_LLD21} $<$<CONFIG:Release>:-s>)
