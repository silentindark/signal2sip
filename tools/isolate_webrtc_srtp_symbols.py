#!/usr/bin/env python3
"""Milestone F: produces a copy of ringrtc's prebuilt libwebrtc.a with its
vendored libsrtp's plain-C API symbols (srtp_init, srtp_create, ...)
renamed to a webrtcvendored_ prefix, so a binary that links BOTH this
library AND the system PJSIP (which bundles its own, separately-versioned
copy of the exact same libsrtp API under the exact same symbol names) does
not silently resolve PJSIP's calls into WebRTC's incompatible copy.

Root cause (see this project's memory project_signal2sip_milestone_e_progress,
Milestone F section, 2026-07-31): a test/binary linking both `ringrtc`+`webrtc`
(for RingRTC calling) and PJSIP (for the SIP leg) in one process failed
`pjsua_init()` with a libsrtp "unsupported parameter"/bad_param error
(PJMEDIA_ERRNO_FROM_LIBSRTP, status 259801) - confirmed via `nm` on the
final linked binary that only ONE `srtp_init` existed, and it was WebRTC's
copy (libwebrtc.a is earlier on the link line than PJSIP's own
libsrtp-*.a), silently satisfying PJSIP's calls into an ABI it wasn't
built against. Not a WebRTC or PJSIP bug - a real static-link hazard
whenever two independent libsrtp vendorings coexist in one binary.

libwebrtc.a has ~77 duplicate member basenames (ordinary `ar x <name>`
is ambiguous), so this operates by byte position within the archive, not
name - see the plain `ar` format parser below.

Usage: isolate_webrtc_srtp_symbols.py <input libwebrtc.a> <output .a>
"""
import subprocess
import sys
import tempfile
from pathlib import Path

MAGIC = b"!<arch>\n"
HDR_LEN = 60

# Names of vendored-libsrtp object files, identified once by inspecting
# ringrtc's prebuilt libwebrtc.a (linux-x64 release) - see the memory
# entry above for how these were found. All are uniquely-named in the
# archive except err.o (disambiguated below by symbol content, not
# position, so this keeps working if the webrtc build shifts member
# order in a future artifact refresh).
CANDIDATE_NAMES = [
    "aes_gcm_ossl.o", "aes_icm_ossl.o", "alloc.o", "auth.o", "cipher.o",
    "crypto_kernel.o", "datatypes.o", "err.o", "hmac_ossl.o", "key.o",
    "null_auth.o", "null_cipher.o", "rdb.o", "rdbx.o", "srtp.o",
    "srtp_key_carrier.o", "srtp_session.o",
]
# A symbol only libsrtp's own err.c defines - used to pick the right
# `err.o` out of however many same-named members the archive has (at
# least one is BoringSSL's unrelated ERR_* error-string module).
ERR_O_DISAMBIGUATOR = "srtp_err_report"


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


def nm_globals(path):
    out = subprocess.run(["nm", str(path)], capture_output=True, text=True, check=True).stdout
    syms = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[1] in "TDBRC":
            syms.add(parts[2])
    return syms


def main():
    if len(sys.argv) != 3:
        print(__doc__)
        sys.exit(1)
    src_path, out_path = Path(sys.argv[1]), Path(sys.argv[2])
    data = src_path.read_bytes()
    members = parse_members(data)

    with tempfile.TemporaryDirectory() as tmp:
        tmp = Path(tmp)

        # Resolve candidate names to concrete archive members (byte
        # ranges), disambiguating err.o by content.
        by_name = {}
        for m in members:
            by_name.setdefault(m["name"], []).append(m)

        chosen = []
        for name in CANDIDATE_NAMES:
            occurrences = by_name.get(name, [])
            if not occurrences:
                print(f"WARNING: expected member {name} not found in archive - skipping", file=sys.stderr)
                continue
            if len(occurrences) == 1:
                chosen.append(occurrences[0])
                continue
            # Disambiguate: extract each occurrence, keep the one whose
            # own symbol table actually looks like libsrtp.
            picked = None
            for i, occ in enumerate(occurrences):
                probe = tmp / f"probe_{name}_{i}.o"
                probe.write_bytes(data[occ["offset"]:occ["offset"] + occ["size"]])
                if ERR_O_DISAMBIGUATOR in nm_globals(probe) or name != "err.o":
                    picked = occ
                    break
            if picked is None:
                print(f"WARNING: could not disambiguate {len(occurrences)} copies of {name} - skipping", file=sys.stderr)
                continue
            chosen.append(picked)

        # Build the rename map from every plain-C global symbol these
        # members define (their whole point is to be renamed away from
        # anything a system libsrtp could also define).
        target_syms = set()
        extracted_paths = {}
        for m in chosen:
            p = tmp / f"mem_{id(m)}.o"
            p.write_bytes(data[m["offset"]:m["offset"] + m["size"]])
            extracted_paths[m["hdr_offset"]] = p
            for sym in nm_globals(p):
                if not sym.startswith("_Z"):  # skip C++-mangled (already namespaced)
                    target_syms.add(sym)

        redefine_map = tmp / "redefine.map"
        redefine_map.write_text("".join(f"{s} webrtcvendored_{s}\n" for s in sorted(target_syms)))

        for hdr_offset, p in extracted_paths.items():
            # GNU objcopy can't auto-detect these clang/lld-produced .o
            # files' format ("Cannot determine input file format") -
            # forcing it with -I/-O elf64-x86-64 makes it "succeed" but
            # silently corrupts e_machine to EM_NONE (confirmed live via
            # readelf -h, then confirmed live again as ld.lld rejecting
            # the result with "incompatible with elf64-x86-64"). LLVM's
            # own objcopy auto-detects and rewrites these correctly with
            # no flags needed - use it instead.
            subprocess.run(
                ["llvm-objcopy-19", f"--redefine-syms={redefine_map}", str(p)],
                check=True,
            )

        # Reassemble: byte-identical archive except the chosen members'
        # data (and their header's size field, which may have grown
        # slightly from longer symbol names).
        replacements = {off: path.read_bytes() for off, path in extracted_paths.items()}

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

    # The renamed members are longer than their originals (longer symbol
    # names in the .o's own symtab/strtab), which shifts every later
    # member's byte offset - but the archive's own symbol index (built by
    # whatever tool produced the original libwebrtc.a) still points at the
    # OLD offsets. ld.lld's index-based symbol lookup then reads garbage
    # for any symbol in a member positioned after the first resized one.
    # Found live: this "worked" on lld 19.1.7 (Debian 13) but broke on lld
    # 14.0.6 (Debian 12) with "truncated or malformed archive" - not a
    # platform quirk, a real staleness bug that newer lld apparently
    # tolerates better. Regenerate the index in place, same as running
    # ranlib after hand-editing any archive - `llvm-ranlib-19` was tried
    # first but is a silent no-op on this archive (confirmed live:
    # identical md5sum/mtime before and after); GNU binutils `ar s`
    # actually rewrites it (confirmed live: size changed by the expected
    # few KB) and is already a build-essential dependency, so use that.
    subprocess.run(["ar", "s", str(out_path)], check=True)

    print(f"Wrote {out_path} ({len(out)} bytes, {len(replacements)} members renamed, "
          f"{len(target_syms)} symbols isolated)")


if __name__ == "__main__":
    main()
