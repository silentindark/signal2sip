#!/usr/bin/env python3
"""Renames every plain-C global symbol that the REAL system OpenSSL
(libssl.so.3/libcrypto.so.3, queried directly rather than guessed) also
exports - anywhere in ringrtc's prebuilt libwebrtc.a, not just its bcm.o
crypto module (the FIPS "BoringCrypto Module" object, which alone
accounts for ~450 of these) - to a webrtcvendored_ prefix, plus every
other archive member that references any of them, so a binary statically
linking BOTH this archive AND system OpenSSL (dynamically) cannot have
its own OpenSSL-API calls silently resolve into WebRTC's bundled
BoringSSL instead.

Originally only harvested target symbols from bcm.o (crypto primitives:
AES_*, EVP_*, BN_*, ...) - broadened 2026-08-10 after a second, separate
collision hit the SSL/TLS protocol layer instead: PJSIP 2.17 re-enabled a
previously-dead SSL_SESSION_free(ssl_sess) call in ssl_sock_ossl.c's
init_openssl() (commented out in 2.14.1, "reenabled since OpenSSL 1.0.x
has been EOL since 2019" upstream), and SSL_SESSION_free turned out to
still be a plain, un-isolated T symbol in libwebrtc_pjsip_safe.a -
defined in BoringSSL's third_party/boringssl/src/ssl/ (protocol-level
C++ code, e.g. ssl_session.cc), a completely different part of the
vendored copy than bcm.o. `nm` on the same archive turned up dozens more
never-isolated SSL_*/SSL_CTX_*/SSL_SESSION_* names from that same ssl/
directory - not a one-off, a whole uncovered class.

First attempt at broadening this matched against a hand-written list of
OpenSSL API prefixes (SSL_, EVP_, X509_, ...) - wrong approach, proven
live: PJSIP's get_cert_info() calls GENERAL_NAMES_free() (plural - stack
of GENERAL_NAME), which the prefix list's "GENERAL_NAME_" (singular)
entry didn't match, so it stayed un-isolated and PJSIP's call bound
straight into WebRTC's own (self-consistently renamed, but ABI-
incompatible with system OpenSSL) GENERAL_NAMES_free - "free(): invalid
pointer" heap corruption, confirmed via a live debug build's backtrace
(get_cert_info -> GENERAL_NAMES_free -> webrtcvendored_ASN1_item_free ->
glibc malloc detecting the corrupted chunk). A prefix list is exactly as
complete as whoever wrote it remembered to make it, and OpenSSL's real
API surface has too many pluralized/irregular names (GENERAL_NAMES_free,
DIST_POINTS_free, POLICYQUALINFO_free, sk_X509_NAME_free, ...) to
enumerate by hand reliably - already caught missing one on the very
first real test. Fixed properly: query the actual system
libssl.so.3/libcrypto.so.3 (via `nm -D`) for what they really export,
and isolate exactly the WebRTC-archive symbols that are ALSO real system
OpenSSL exports - no guessing, no prefix list to keep in sync, and
structurally can't miss an irregular name the way a hand-written list
can.

Root cause (found 2026-08-06 investigating a real bug: StorageServiceSync.cpp's
aesGcmDecrypt() - plain #include <openssl/evp.h>, EVP_aes_256_gcm() et al. -
intermittently failed to decrypt real StorageService manifests, byte-for-byte
identical key+ciphertext that decrypted correctly 5/5 times standalone in
Python). `nm -D` on the final signal2sip-daemon binary showed EVP_MAC_*
(used elsewhere) correctly listed as dynamic-undefined, @OPENSSL_3.0.0 -
resolved from libcrypto.so.3 at runtime, as intended - but EVP_aes_256_gcm,
EVP_CIPHER_CTX_new/free/ctrl, and EVP_Decrypt{Init_ex,Update,Final_ex} were
ABSENT from the dynamic-undefined list entirely, meaning they were never
going to be satisfied by libcrypto.so.3 at runtime. `nm` on
libwebrtc_pjsip_safe.a confirmed bcm.o globally defines all of them -
BoringSSL's own implementation, statically linked, winning symbol
resolution over the system library. Same root-cause class as this project's
already-known libsrtp collision (see isolate_webrtc_srtp_symbols.py) - just
hitting the AES-GCM/EVP surface instead of libsrtp's.

Unlike the srtp case (17 known, individually-named vendored files),
BoringSSL's public-API-shaped plain-C symbols are spread across a large,
unpredictable set of members - bcm.o alone (BoringSSL's monolithic FIPS
module boundary, one translation unit) exports ~850 global symbols, and
the ssl/asn1/x509 protocol layers add many more from a different set of
members entirely - the C++-mangled bssl::-namespaced ones throughout are
already collision-safe and left alone. Rather than hand-enumerate which
members hold these (fragile - already missed a whole class once, then
missed an irregular name inside that class on the very next attempt),
this scans every one of the archive's ~2700 members unconditionally in a
first pass to collect target symbols (any plain-C name the archive
defines that the real system libssl.so.3/libcrypto.so.3 also exports),
then a second pass to redefine only members that reference or define
one, leaving everything else untouched. Slower than the srtp script's
targeted approach but self-updating and can't drift out of sync with
what system OpenSSL actually exports, since it asks that library
directly instead of trusting a list.

Intended to run AFTER isolate_webrtc_srtp_symbols.py (chained in CMakeLists.txt)
since the two touch an overlapping pair of members (aes_gcm_ossl.o,
aes_icm_ossl.o - libsrtp's own OpenSSL-backed AES wrappers, which get their
own top-level srtp_* symbols renamed by the srtp script AND their internal
EVP_CIPHER_CTX_* references renamed by this one) but operate on disjoint
symbol namespaces, so composition order does not actually matter.

Also reused as-is against libsignal/target/release/libsignal_ffi.a: that
Rust static lib turned out to vendor its OWN separate BoringSSL-family
copy too (aws-lc-rs, itself a BoringSSL fork - its monolithic module
happens to still be named bcm.cc.o, same idea as WebRTC's bcm.o), found
while verifying the WebRTC fix actually worked - `nm -D` on the rebuilt
daemon still didn't show EVP_aes_256_gcm resolving from libcrypto.so.3
after isolating WebRTC's copy, because libsignal_ffi.a's copy - earlier on
the link line than the real -lcrypto - silently took over instead. Same
fix, same script - querying real system OpenSSL's exports finds
aws-lc-rs's plain-C names the same way it finds WebRTC's, no per-archive
special-casing needed.

Usage: isolate_webrtc_boringssl_symbols.py <input .a> <output .a>
"""
import subprocess
import sys
import tempfile
from pathlib import Path

MAGIC = b"!<arch>\n"
HDR_LEN = 60

# The real system libraries a signal2sip binary actually dynamically
# links against for OpenSSL - queried directly (see
# system_openssl_exports() below) rather than guessed, so isolation
# targets are exactly what could really collide, no more and no less.
SYSTEM_OPENSSL_LIBS = ("libssl.so.3", "libcrypto.so.3")


def find_system_lib(soname):
    out = subprocess.run(["ldconfig", "-p"], capture_output=True, text=True, check=True).stdout
    for line in out.splitlines():
        line = line.strip()
        if line.startswith(soname + " ") and "=>" in line:
            return line.split("=>", 1)[1].strip()
    print(f"ERROR: {soname} not found via `ldconfig -p` - is it installed?", file=sys.stderr)
    sys.exit(1)


def system_openssl_exports():
    """Every symbol real system OpenSSL actually exports (defined, dynamic) -
    the true collision surface, instead of a hand-maintained prefix guess."""
    exports = set()
    for soname in SYSTEM_OPENSSL_LIBS:
        path = find_system_lib(soname)
        out = subprocess.run(["nm", "-D", "--defined-only", path],
                             capture_output=True, text=True, check=True).stdout
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] in "TtWwDdBbRr":
                # Versioned symbols look like "ASN1_item_free@@OPENSSL_3.0.0" -
                # strip the version suffix to match the archive's plain names.
                exports.add(parts[2].split("@")[0])
    return exports


def parse_members(data):
    assert data[:8] == MAGIC, "not an ar archive"
    pos = 8
    members = []
    gnu_names = b""
    while pos < len(data):
        if pos + HDR_LEN > len(data):
            break
        hdr = data[pos:pos + HDR_LEN]
        name_field = hdr[0:16].decode("ascii").rstrip()
        size = int(hdr[48:58].decode("ascii").strip())
        data_start = pos + HDR_LEN
        if name_field == "//":
            gnu_names = data[data_start:data_start + size]
            pos = data_start + size + (size % 2)
            continue
        if name_field == "/":
            pos = data_start + size + (size % 2)
            continue
        if name_field.startswith("/") and name_field[1:].isdigit():
            off = int(name_field[1:])
            end = gnu_names.index(b"/\n", off)
            real_name = gnu_names[off:end].decode("ascii")
        else:
            real_name = name_field.rstrip("/")
        members.append({"name": real_name, "offset": data_start, "size": size, "hdr_offset": pos})
        pos = data_start + size + (size % 2)
    return members


def nm_defined_and_undefined(path):
    out = subprocess.run(["nm", str(path)], capture_output=True, text=True, check=True).stdout
    defined, undefined = set(), set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 2 and parts[0] == "U":
            undefined.add(parts[1])
        elif len(parts) == 3 and parts[1] in "TtWwDdBbRr":
            defined.add(parts[2])
    return defined, undefined


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    src_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    data = src_path.read_bytes()
    members = parse_members(data)

    system_syms = system_openssl_exports()
    print(f"{len(system_syms)} symbols exported by real system "
          f"{'/'.join(SYSTEM_OPENSSL_LIBS)}", file=sys.stderr)

    def is_target_symbol(name):
        # Only plain C names collide with system OpenSSL's public API - the
        # C++-mangled bssl::-namespaced symbols are already safe (see
        # isolate_webrtc_srtp_symbols.py's identical skip for the same
        # reason). Isolate exactly what the real system library exports,
        # not a guessed prefix - see this file's top-of-file comment for
        # why a prefix list already proved unreliable.
        return not name.startswith("_Z") and name in system_syms

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # Single pass over every member: extract once, nm once, cache both
        # its (defined, undefined) sets and its extracted path for reuse in
        # the redefine step below - avoids re-extracting/re-nm'ing anything.
        per_member = []
        target_syms = set()
        for i, m in enumerate(members):
            p = tmp / f"mem_{i}.o"
            p.write_bytes(data[m["offset"]:m["offset"] + m["size"]])
            d, u = nm_defined_and_undefined(p)
            per_member.append((m, p, d, u))
            target_syms |= {s for s in d if is_target_symbol(s)}

        print(f"{len(members)} members scanned, {len(target_syms)} plain-C "
              f"OpenSSL/BoringSSL-API-shaped symbols targeted for isolation",
              file=sys.stderr)

        redefine_map = tmp / "redefine.map"
        redefine_map.write_text("".join(f"{s} webrtcvendored_{s}\n" for s in sorted(target_syms)))

        # A member is touched if it references any target symbol - either
        # as the definer (e.g. bcm.o, or an ssl/ member like ssl_session.o)
        # or as an internal undefined reference (WebRTC/BoringSSL code
        # calling its own EVP_*/SSL_* etc. internally) - and gets
        # redefine-syms'd; everything else in the ~2700-member archive
        # stays byte-identical.
        touched = {}
        for m, p, d, u in per_member:
            if (d | u) & target_syms:
                touched[m["hdr_offset"]] = p

        print(f"{len(touched)} of {len(members)} members reference a target symbol - redefining",
              file=sys.stderr)

        for hdr_offset, p in touched.items():
            # See isolate_webrtc_srtp_symbols.py for why llvm-objcopy-19
            # specifically (GNU objcopy corrupts these clang/lld .o files
            # when format-forced; LLVM's own objcopy auto-detects correctly).
            subprocess.run(
                ["llvm-objcopy-19", f"--redefine-syms={redefine_map}", str(p)],
                check=True,
            )

        replacements = {off: path.read_bytes() for off, path in touched.items()}

    out = bytearray()
    out += MAGIC
    pos = 8
    while pos < len(data):
        if pos + HDR_LEN > len(data):
            break
        hdr = bytearray(data[pos:pos + HDR_LEN])
        size = int(bytes(hdr[48:58]).decode("ascii").strip())
        data_start = pos + HDR_LEN
        if pos in replacements:
            new_content = replacements[pos]
            hdr[48:58] = str(len(new_content)).ljust(10).encode("ascii")
            out += hdr
            out += new_content
            if len(new_content) % 2 == 1:
                out += b"\n"
        else:
            out += hdr
            out += data[data_start:data_start + size]
            if size % 2 == 1:
                out += b"\n"
        pos = data_start + size + (size % 2)

    out_path.write_bytes(out)

    # Same staleness hazard as isolate_webrtc_srtp_symbols.py: resized
    # members shift every later member's byte offset, and the archive's own
    # prebuilt symbol index still points at the old offsets. Regenerate it
    # with GNU binutils `ar s` (llvm-ranlib-19 is a silent no-op here, same
    # as observed for the srtp script).
    subprocess.run(["ar", "s", str(out_path)], check=True)

    print(f"Wrote {out_path} ({len(out)} bytes, {len(touched)} members redefined, "
          f"{len(target_syms)} symbols isolated)")


if __name__ == "__main__":
    main()
