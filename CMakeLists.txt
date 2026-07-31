cmake_minimum_required(VERSION 3.16)
project(signal2sip-native CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLCIPHER REQUIRED IMPORTED_TARGET sqlcipher)
pkg_check_modules(LIBWEBSOCKETS REQUIRED IMPORTED_TARGET libwebsockets)
# Same shared /usr/local install tg2sip-webrtc itself links against (built
# with --disable-sound - fine here too, since the whole point of Milestone
# F's ring-buffer bridge is to never touch PJSIP's own sound-device layer;
# it registers custom virtual pjmedia_port objects via registerMediaPort()
# instead, same proven pattern tg2sip-webrtc uses for its own calls).
pkg_check_modules(PJSIP REQUIRED IMPORTED_TARGET libpjproject)
find_package(Protobuf REQUIRED)
find_package(nlohmann_json REQUIRED)

# Signal's on-the-wire message shapes, unchanged from the Node prototype -
# same .proto sources (pulled from signalapp/Signal-Android, see
# ../PROTOCOL.md), compiled fresh for C++ instead of loaded at runtime via
# protobufjs.
set(SIGNAL_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../proto)
set(SIGNAL_PROTO_FILES
    ${SIGNAL_PROTO_DIR}/SignalService.proto
    ${SIGNAL_PROTO_DIR}/WebSocketResources.proto
    ${SIGNAL_PROTO_DIR}/Provisioning.proto
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
)
target_include_directories(signal2sip_util PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

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
# ~/GIT/vladonv/libsignal checkout. LIBSIGNAL_DIR lets that path be
# overridden; signal_ffi.h is a checked-in generated file in that repo, not
# a build artifact, so it's read straight from its source location.
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
set(LIBSIGNAL_DIR "$ENV{HOME}/GIT/vladonv/libsignal" CACHE PATH "Path to the libsignal checkout")
file(READ ${LIBSIGNAL_DIR}/swift/Sources/SignalFfi/signal_ffi.h SIGNAL_FFI_H_CONTENT)
string(REPLACE "enum SignalFfiPublicKeyType {" "enum SignalFfiPublicKeyType_Tag {" SIGNAL_FFI_H_CONTENT "${SIGNAL_FFI_H_CONTENT}")
string(REPLACE "enum SignalSvr2CredentialsResult {" "enum SignalSvr2CredentialsResult_Tag {" SIGNAL_FFI_H_CONTENT "${SIGNAL_FFI_H_CONTENT}")
set(SIGNAL_FFI_H_CONTENT "#ifdef __cplusplus\nextern \"C\" {\n#endif\n${SIGNAL_FFI_H_CONTENT}\n#ifdef __cplusplus\n}\n#endif\n")
file(WRITE ${CMAKE_CURRENT_BINARY_DIR}/generated/signal_ffi_cxx/signal_ffi.h "${SIGNAL_FFI_H_CONTENT}")

add_library(libsignal_ffi STATIC IMPORTED)
set_target_properties(libsignal_ffi PROPERTIES
    IMPORTED_LOCATION ${LIBSIGNAL_DIR}/target/debug/libsignal_ffi.a
    INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_CURRENT_BINARY_DIR}/generated/signal_ffi_cxx
)

add_library(signal2sip_signal STATIC
    signal/ProtocolStores.cpp
    signal/Crypto.cpp
    signal/PreKeys.cpp
)
target_include_directories(signal2sip_signal PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip_signal PUBLIC signal2sip_storage signal2sip_padding signal2sip_util libsignal_ffi
    ${CMAKE_DL_LIBS} pthread m)

add_executable(signal_roundtrip_test test/signal_roundtrip_test.cpp)
target_link_libraries(signal_roundtrip_test PRIVATE signal2sip_signal signal2sip_authsocket signal2sip_proto
    nlohmann_json::nlohmann_json)

add_executable(refresh_prekeys_test test/refresh_prekeys_test.cpp)
target_link_libraries(refresh_prekeys_test PRIVATE signal2sip_signal signal2sip_authsocket signal2sip_proto
    nlohmann_json::nlohmann_json)

# RingRTC's Milestone D/E C ABI (see /home/vlad/.claude/plans/
# jiggly-mapping-plum.md and this project's memory) - built via `cargo
# build --features native,prebuilt_webrtc` in the sibling
# ~/GIT/vladonv/ringrtc checkout, linking its own prebuilt WebRTC static
# lib (fetched via `bin/fetch-artifact --platform linux-x64`).
# native/ringrtc/signal2sip_ringrtc.h is hand-written (that crate has no
# cbindgen setup) and kept in sync with cpp_ffi.rs manually.
set(RINGRTC_DIR "$ENV{HOME}/GIT/vladonv/ringrtc" CACHE PATH "Path to the ringrtc checkout")
add_library(ringrtc STATIC IMPORTED)
set_target_properties(ringrtc PROPERTIES
    IMPORTED_LOCATION ${RINGRTC_DIR}/target/debug/libringrtc.a
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
target_link_options(ringrtc_two_party_test PRIVATE -fuse-ld=lld)

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
set(WEBRTC_PJSIP_SAFE_LIB ${CMAKE_CURRENT_BINARY_DIR}/generated/libwebrtc_pjsip_safe.a)
add_custom_command(
    OUTPUT ${WEBRTC_PJSIP_SAFE_LIB}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/generated
    COMMAND python3 ${CMAKE_CURRENT_SOURCE_DIR}/tools/isolate_webrtc_srtp_symbols.py
            ${RINGRTC_DIR}/out/release/obj/libwebrtc.a ${WEBRTC_PJSIP_SAFE_LIB}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/tools/isolate_webrtc_srtp_symbols.py
            ${RINGRTC_DIR}/out/release/obj/libwebrtc.a
    COMMENT "Isolating WebRTC's vendored libsrtp symbols from PJSIP's"
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
target_link_options(pjsip_ringrtc_echo_test PRIVATE -fuse-ld=lld)

# Milestone G: bidirectional bridge between real Signal CallMessage
# protobufs and RingRTC's C ABI - see native/daemon/CallSignaling.h.
add_library(signal2sip_daemon STATIC
    daemon/CallSignaling.cpp
    daemon/Config.cpp
)
target_include_directories(signal2sip_daemon PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip_daemon PUBLIC signal2sip_signal signal2sip_authsocket signal2sip_proto
    signal2sip_voip ringrtc webrtc_pjsip_safe nlohmann_json::nlohmann_json)

add_executable(signal2sip-daemon daemon/main.cpp)
target_include_directories(signal2sip-daemon PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(signal2sip-daemon PRIVATE signal2sip_daemon signal2sip_signal signal2sip_authsocket
    signal2sip_proto signal2sip_voip ringrtc webrtc_pjsip_safe PkgConfig::PJSIP
    ${CMAKE_DL_LIBS} pthread m stdc++ pulse nlohmann_json::nlohmann_json)
# libringrtc.a and libsignal_ffi.a are two INDEPENDENT Rust static libs
# (separate `cargo build` invocations, separate crates/workspaces) - each
# embeds its own copy of Rust std's runtime support symbols
# (rust_eh_personality etc), which collide as hard duplicate-definition
# link errors when both land in one binary (unlike the libwebrtc/libsrtp
# collision fixed above, which was a silent wrong-symbol-wins problem -
# this is the opposite: a byte-identical-in-effect symbol that the
# linker refuses to pick between). Safe to just take either copy here -
# same host triple, same ABI, purely a runtime personality routine.
target_link_options(signal2sip-daemon PRIVATE -fuse-ld=lld -Wl,--allow-multiple-definition)
