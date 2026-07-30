cmake_minimum_required(VERSION 3.16)
project(signal2sip-native CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SQLCIPHER REQUIRED IMPORTED_TARGET sqlcipher)
pkg_check_modules(LIBWEBSOCKETS REQUIRED IMPORTED_TARGET libwebsockets)
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
