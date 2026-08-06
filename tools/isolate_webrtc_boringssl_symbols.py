#!/usr/bin/env python3
"""Renames every plain-C global symbol BoringSSL's monolithic crypto module
(bcm.o - the FIPS "BoringCrypto Module" object, which alone accounts for
~450 of these) exports in ringrtc's prebuilt libwebrtc.a to a
webrtcvendored_ prefix, plus every other archive member that references any
of them, so a binary statically linking BOTH this archive AND system
OpenSSL (libcrypto.so.3, dynamically) cannot have its own OpenSSL-API calls
silently resolve into WebRTC's bundled BoringSSL instead.

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

Unlike the srtp case (17 known, individually-named vendored files), bcm.o
is a single ~1.7MB monolithic object exporting ~850 global symbols (BoringSSL
deliberately compiles its whole FIPS module boundary as one translation
unit), of which ~450 are plain C names that are also real public OpenSSL API
names (AES_*, BN_*, EC_*, EVP_*, DSA_*, DH_*, RSA_*, SHA*, ...) - the
C++-mangled bssl::-namespaced ones are already collision-safe and are left
alone. ~100 other members elsewhere in the archive hold their own internal,
undefined references to these same names (WebRTC/BoringSSL code calling its
own EVP_* etc. internally) and must be redefined in lockstep with bcm.o's
definitions, or the archive becomes internally inconsistent. Rather than
hand-enumerate those ~100 (fragile - would silently rot as ringrtc ships new
webrtc.a builds), this operates on every one of the archive's ~2700 members
unconditionally: extract, nm, redefine only if it references or (unexpectedly)
also defines a target symbol, otherwise leave untouched. Slower than the
srtp script's targeted approach but self-updating.

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
fix, same script: the bcm-module lookup below tries both known member
names, picks whichever one the given archive actually has.

Usage: isolate_webrtc_boringssl_symbols.py <input .a> <output .a>
"""
import subprocess
import sys
import tempfile
from pathlib import Path

MAGIC = b"!<arch>\n"
HDR_LEN = 60

# Both known names for the BoringSSL-family "monolithic crypto module"
# object file - WebRTC's own BoringSSL vendoring names it bcm.o, aws-lc-rs
# (used by libsignal_ffi.a) names its equivalent bcm.cc.o.
BCM_MEMBER_NAME_CANDIDATES = ("bcm.o", "bcm.cc.o")


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

    bcm_candidates = [m for m in members if m["name"] in BCM_MEMBER_NAME_CANDIDATES]
    if len(bcm_candidates) != 1:
        print(f"ERROR: expected exactly 1 member named one of {BCM_MEMBER_NAME_CANDIDATES}, "
              f"found {len(bcm_candidates)}", file=sys.stderr)
        sys.exit(1)
    bcm = bcm_candidates[0]
    bcm_member_name = bcm["name"]

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        bcm_probe = tmp / "bcm_probe.o"
        bcm_probe.write_bytes(data[bcm["offset"]:bcm["offset"] + bcm["size"]])
        bcm_defined, _ = nm_defined_and_undefined(bcm_probe)
        # Only plain C names collide with system OpenSSL's public API - the
        # C++-mangled bssl::-namespaced symbols are already safe (see
        # isolate_webrtc_srtp_symbols.py's identical skip for the same reason).
        target_syms = {s for s in bcm_defined if not s.startswith("_Z")}
        print(f"{bcm_member_name}: {len(bcm_defined)} global symbols, "
              f"{len(target_syms)} plain-C ones targeted for isolation", file=sys.stderr)

        redefine_map = tmp / "redefine.map"
        redefine_map.write_text("".join(f"{s} webrtcvendored_{s}\n" for s in sorted(target_syms)))

        # Scan every member (not just bcm.o) for references to the target
        # symbols - either as the definer (bcm.o itself) or as an internal
        # undefined reference (WebRTC/BoringSSL code calling its own EVP_*
        # etc.) - and redefine-syms only those, leaving everything else in
        # the ~2700-member archive byte-identical.
        touched = {}
        for i, m in enumerate(members):
            p = tmp / f"mem_{i}.o"
            p.write_bytes(data[m["offset"]:m["offset"] + m["size"]])
            d, u = nm_defined_and_undefined(p)
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
