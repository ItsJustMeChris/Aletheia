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


def xor_encrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def find_text_section(binary: bytes) -> tuple[int, int, int]:
    magic, _, _, _, ncmds, _, _, _ = HEADER_STRUCT.unpack_from(binary, 0)
    if magic != MH_MAGIC_64:
        raise ValueError("Only 64-bit Mach-O binaries are supported.")

    offset = HEADER_STRUCT.size
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
                if sec_segname == "__TEXT" and sectname == "__text":
                    return section[4], section[3], offset
                section_offset += SECTION_STRUCT.size
        offset += cmdsize

    raise ValueError("Unable to locate __TEXT,__text section in Mach-O binary.")


def encrypt_text_segment(binary_path: Path, output_path: Path, key: int) -> None:
    data = binary_path.read_bytes()
    text_offset, text_size, segment_offset = find_text_section(data)

    print(f"[encrypt] __text offset=0x{text_offset:x}, size={text_size} bytes, key=0x{key:02x}")

    encrypted = bytearray(data)
    encrypted[text_offset:text_offset + text_size] = xor_encrypt(
        data[text_offset:text_offset + text_size], key
    )

    segment = list(SEGMENT_STRUCT.unpack_from(encrypted, segment_offset))
    maxprot = segment[7]
    if (maxprot & 0x2) == 0:
        new_maxprot = maxprot | 0x2
        segment[7] = new_maxprot
        SEGMENT_STRUCT.pack_into(encrypted, segment_offset, *segment)
        print(f"[encrypt] Updated __TEXT maxprot from 0x{maxprot:x} to 0x{new_maxprot:x}")
    else:
        print(f"[encrypt] __TEXT maxprot already writable (0x{maxprot:x})")

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
    encrypt_text_segment(args.input, args.output, args.key)


if __name__ == "__main__":
    main()
