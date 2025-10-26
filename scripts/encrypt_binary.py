#!/usr/bin/env python3
"""
Encrypt the __TEXT,__text section of a Mach-O executable using a simple XOR key.

The script parses the Mach-O headers to locate the correct section dynamically,
so no manual offset updates are required.
"""

import argparse
import struct
from pathlib import Path

MH_MAGIC_64 = 0xfeedfacf
LC_SEGMENT_64 = 0x19

SEGMENT_STRUCT = struct.Struct("<II16sQQQQiiII")
SECTION_STRUCT = struct.Struct("<16s16sQQIIIIIIII")
HEADER_STRUCT = struct.Struct("<IiiIIIII")
SECTION_TYPE_MASK = 0xFF
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_LAZY_SYMBOL_POINTERS = 0x7


def xor_encrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def collect_encryption_targets(binary: bytes) -> list[dict]:
    magic, _, _, _, ncmds, _, _, _ = HEADER_STRUCT.unpack_from(binary, 0)
    if magic != MH_MAGIC_64:
        raise ValueError("Only 64-bit Mach-O binaries are supported.")

    offset = HEADER_STRUCT.size
    targets: list[dict] = []
    code_section_names = {
        "__text",
        "__stubs",
        "__stub_helper",
        "__picsymbolstub4",
    }

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", binary, offset)
        if cmd == LC_SEGMENT_64:
            segment = list(SEGMENT_STRUCT.unpack_from(binary, offset))
            segname = segment[2].split(b"\0", 1)[0].decode("ascii", errors="ignore")
            nsects = segment[9]
            section_offset = offset + SEGMENT_STRUCT.size
            for _ in range(nsects):
                section = SECTION_STRUCT.unpack_from(binary, section_offset)
                sectname = section[0].split(b"\0", 1)[0].decode("ascii", errors="ignore")
                sec_segname = section[1].split(b"\0", 1)[0].decode("ascii", errors="ignore")
                size = section[3]
                if size == 0:
                    section_offset += SECTION_STRUCT.size
                    continue

                section_type = section[8] & SECTION_TYPE_MASK
                reason = None
                if sec_segname == "__TEXT" and sectname in code_section_names:
                    reason = "text"
                elif section_type in (S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS):
                    reason = "import"

                if reason is not None:
                    targets.append(
                        {
                            "segname": sec_segname,
                            "sectname": sectname,
                            "file_offset": section[4],
                            "size": size,
                            "segment_offset": offset,
                            "reason": reason,
                        }
                    )
                section_offset += SECTION_STRUCT.size
        offset += cmdsize

    if not targets:
        raise ValueError("No eligible sections found for encryption.")
    return targets


def encrypt_binary_sections(binary_path: Path, output_path: Path, key: int) -> None:
    original = binary_path.read_bytes()
    encrypted = bytearray(original)

    targets = collect_encryption_targets(original)
    segment_offsets = {}

    for target in targets:
        start = target["file_offset"]
        end = start + target["size"]
        segment_offsets[target["segment_offset"]] = target["segname"]
        if target["reason"] == "text":
            encrypted[start:end] = xor_encrypt(original[start:end], key)
            print(
                "[encrypt] Section {seg},{sect} offset=0x{off:x}, size={size} bytes, reason={reason}, key=0x{key:02x}".format(
                    seg=target["segname"],
                    sect=target["sectname"],
                    off=start,
                    size=target["size"],
                    reason=target["reason"],
                    key=key,
                )
            )
        else:
            print(
                "[encrypt] Skipping on-disk XOR for {seg},{sect} (reason={reason}); runtime watcher will handle it.".format(
                    seg=target["segname"],
                    sect=target["sectname"],
                    reason=target["reason"],
                )
            )

    for segment_offset, segname in segment_offsets.items():
        segment = list(SEGMENT_STRUCT.unpack_from(encrypted, segment_offset))
        maxprot = segment[7]
        if (maxprot & 0x2) == 0:
            new_maxprot = maxprot | 0x2
            segment[7] = new_maxprot
            SEGMENT_STRUCT.pack_into(encrypted, segment_offset, *segment)
            print(
                f"[encrypt] Updated {segname} maxprot from 0x{maxprot:x} to 0x{new_maxprot:x}"
            )
        else:
            print(f"[encrypt] {segname} maxprot already writable (0x{maxprot:x})")

    output_path.write_bytes(encrypted)
    print(f"[encrypt] Wrote encrypted binary to {output_path}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Encrypt Mach-O __TEXT,__text section with XOR.")
    parser.add_argument(
        "-i",
        "--input",
        type=Path,
        default=Path("build/parent_binary"),
        help="Path to input Mach-O binary (default: build/parent_binary).",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        default=Path("build/parent_binary_encrypted"),
        help="Path to output encrypted binary (default: build/parent_binary_encrypted).",
    )
    parser.add_argument(
        "-k",
        "--key",
        type=lambda value: int(value, 0),
        default=0x55,
        help="XOR key as integer (supports 0x prefix). Default: 0x55.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    encrypt_binary_sections(args.input, args.output, args.key)


if __name__ == "__main__":
    main()
