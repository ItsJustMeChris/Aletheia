#!/usr/bin/env python3
"""
Encrypt the __TEXT,__text section of a Mach-O executable using a simple XOR key and
emit runtime import metadata for automatic resolution.
"""

import argparse
import struct
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

MH_MAGIC_64 = 0xfeedfacf
LC_SEGMENT_64 = 0x19
LC_SYMTAB = 0x2
LC_DYSYMTAB = 0xB
LC_DYLD_CHAINED_FIXUPS = 0x80000034
LC_NOTE = 0x31

SEGMENT_STRUCT = struct.Struct("<II16sQQQQiiII")
SECTION_STRUCT = struct.Struct("<16s16sQQIIIIIIII")
HEADER_STRUCT = struct.Struct("<IiiIIIII")
SYMTAB_STRUCT = struct.Struct("<IIIIII")
NLIST_64_STRUCT = struct.Struct("<IbbHQ")
SECTION_TYPE_MASK = 0xFF
S_NON_LAZY_SYMBOL_POINTERS = 0x6
S_LAZY_SYMBOL_POINTERS = 0x7
S_REGULAR = 0x0
IMPORT_NAME_KEY = 0x5A
INDIRECT_SYMBOL_LOCAL = 0x80000000
INDIRECT_SYMBOL_ABS = 0x40000000
INDIRECT_SYMBOL_LOCAL_END = 0xFFFFFFFF


@dataclass
class ImportEntry:
    name: str
    vmaddr: int


def xor_encrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ key for b in data)


def sanitize_symbol(name: str) -> str:
    base = ["sym"]
    for ch in name:
        if ch.isalnum() or ch == "_":
            base.append(ch)
        else:
            base.append(f"_{ord(ch):02x}")
    sanitized = "".join(base)
    if sanitized[0].isdigit():
        sanitized = f"sym_{sanitized}"
    return sanitized


def read_c_string(blob: bytes, offset: int, limit: int) -> str:
    end = offset
    while end < limit and blob[end] != 0:
        end += 1
    return blob[offset:end].decode("ascii", errors="ignore")


def collect_encryption_targets(binary: bytes) -> list[dict]:
    magic, _, _, _, ncmds, _, _, _ = HEADER_STRUCT.unpack_from(binary, 0)
    if magic != MH_MAGIC_64:
        raise ValueError("Only 64-bit Mach-O binaries are supported.")

    offset = HEADER_STRUCT.size
    targets: list[dict] = []
    code_section_names = {"__text", "__stubs", "__stub_helper", "__picsymbolstub4"}

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


def collect_import_entries(binary: bytes) -> tuple[list[ImportEntry], dict]:
    magic, _, _, _, ncmds, _, _, _ = HEADER_STRUCT.unpack_from(binary, 0)
    if magic != MH_MAGIC_64:
        return [], {
            "section_offsets": [],
            "indirect_offsets": [],
            "symtab_offset": None,
            "stroff": 0,
            "strsize": 0,
            "dysymtab_offset": None,
            "chained_fixups_offsets": [],
        }

    offset = HEADER_STRUCT.size
    import_sections = []
    symtab_offset = None
    dysymtab_offset = None
    chained_fixups_offsets: list[int] = []

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", binary, offset)
        if cmd == LC_SEGMENT_64:
            segment = SEGMENT_STRUCT.unpack_from(binary, offset)
            nsects = segment[9]
            section_offset = offset + SEGMENT_STRUCT.size
            for _ in range(nsects):
                current_section_offset = section_offset
                section = SECTION_STRUCT.unpack_from(binary, section_offset)
                section_type = section[8] & SECTION_TYPE_MASK
                if section_type in (S_NON_LAZY_SYMBOL_POINTERS, S_LAZY_SYMBOL_POINTERS):
                    import_sections.append(
                        {
                            "section_offset": current_section_offset,
                            "addr": section[2],
                            "size": section[3],
                            "reserved1": section[9],
                            "reserved2": section[10],
                        }
                    )
                section_offset += SECTION_STRUCT.size
        elif cmd == LC_SYMTAB:
            symtab_offset = offset
        elif cmd == LC_DYSYMTAB:
            dysymtab_offset = offset
        elif cmd == LC_DYLD_CHAINED_FIXUPS:
            chained_fixups_offsets.append(offset)
        offset += cmdsize

    if not import_sections or symtab_offset is None or dysymtab_offset is None:
        return [], {
            "section_offsets": [section["section_offset"] for section in import_sections],
            "indirect_offsets": [],
            "symtab_offset": symtab_offset,
            "stroff": 0,
            "strsize": 0,
            "dysymtab_offset": dysymtab_offset,
            "chained_fixups_offsets": chained_fixups_offsets,
        }

    _, _, symoff, nsyms, stroff, strsize = SYMTAB_STRUCT.unpack_from(binary, symtab_offset)
    cmd, cmdsize = struct.unpack_from("<II", binary, dysymtab_offset)
    (ilocalsym, nlocalsym, iextdefsym, nextdefsym, iundefsym, nundefsym,
     tocoff, ntoc, modtaboff, nmodtab, extrefsymoff, nextrefsyms,
     indirectsymoff, nindirectsyms, extreloff, nextrel, locreloff, nlocrel) = struct.unpack_from(
        "<18I", binary, dysymtab_offset + 8
    )

    string_table_start = stroff
    string_table_limit = stroff + strsize

    unique: OrderedDict[str, ImportEntry] = OrderedDict()
    section_offsets = [section["section_offset"] for section in import_sections]
    indirect_offsets: list[int] = []
    nlist_size = NLIST_64_STRUCT.size

    for section in import_sections:
        pointer_count = section["size"] // 8
        base_index = section["reserved1"]
        for i in range(pointer_count):
            table_index = base_index + i
            if table_index >= nindirectsyms:
                continue
            indirect_offset = indirectsymoff + table_index * 4
            if indirect_offset + 4 > len(binary):
                continue
            symbol_index = struct.unpack_from("<I", binary, indirect_offset)[0]
            if symbol_index in (INDIRECT_SYMBOL_ABS, INDIRECT_SYMBOL_LOCAL, INDIRECT_SYMBOL_LOCAL_END):
                continue
            nlist_offset = symoff + symbol_index * nlist_size
            if nlist_offset + nlist_size > len(binary):
                continue
            n_strx, _, _, _, _ = NLIST_64_STRUCT.unpack_from(binary, nlist_offset)
            if n_strx == 0:
                continue
            string_offset = string_table_start + n_strx
            if string_offset >= string_table_limit:
                continue
            name = read_c_string(binary, string_offset, string_table_limit)
            if not name:
                continue
            if name not in unique:
                vmaddr = section["addr"] + i * 8
                unique[name] = ImportEntry(name=name, vmaddr=vmaddr)
            indirect_offsets.append(indirect_offset)

    metadata = {
        "section_offsets": section_offsets,
        "indirect_offsets": indirect_offsets,
        "symtab_offset": symtab_offset,
        "stroff": stroff,
        "strsize": strsize,
        "dysymtab_offset": dysymtab_offset,
        "chained_fixups_offsets": chained_fixups_offsets,
    }

    return list(unique.values()), metadata


def write_manifest_and_wrappers(entries: list[ImportEntry], output_dir: Path) -> None:
    if not entries:
        print("[encrypt] No imports discovered; manifest not generated.")
        return

    manifest_path = output_dir / "import_manifest.h"
    wrappers_path = output_dir / "import_wrappers.h"

    sanitized_map: dict[str, str] = {}
    used_names: set[str] = set()
    anonymised_names = OrderedDict()
    counter = 0
    for entry in entries:
        if entry.name not in anonymised_names:
            anonymised_names[entry.name] = f"sym_{counter:04x}"
            counter += 1
        sanitized_map[entry.name] = anonymised_names[entry.name]

    name_blob = bytearray()
    offsets: dict[str, tuple[int, int]] = {}
    for entry in entries:
        if entry.name in offsets:
            continue
        encoded = bytes((ord(ch) ^ IMPORT_NAME_KEY) & 0xFF for ch in entry.name)
        offsets[entry.name] = (len(name_blob), len(encoded))
        name_blob.extend(encoded)

    manifest_entries = []
    for entry in entries:
        offset, length = offsets[entry.name]
        manifest_entries.append((entry.vmaddr, offset, length, sanitized_map[entry.name], entry.name))

    with manifest_path.open("w", encoding="utf-8") as header:
        header.write("// Auto-generated by encrypt_binary.py; do not edit.\n")
        header.write("#pragma once\n")
        header.write("#include <stddef.h>\n")
        header.write("#include <stdint.h>\n\n")
        header.write(f"#define IMPORT_NAME_KEY 0x{IMPORT_NAME_KEY:02X}\n\n")
        header.write("struct import_manifest_entry {\n")
        header.write("    uint64_t vmaddr;\n")
        header.write("    uint32_t name_offset;\n")
        header.write("    uint32_t name_length;\n")
        header.write("    uint32_t padding;\n")
        header.write("};\n\n")

        header.write("static const uint8_t import_name_blob[] = {\n")
        for index, byte in enumerate(name_blob):
            sep = "," if index + 1 < len(name_blob) else ""
            header.write(f"    0x{byte:02X}{sep}\n")
        header.write("};\n\n")

        header.write("static const struct import_manifest_entry import_manifest[] = {\n")
        for vmaddr, offset, length, _, original in manifest_entries:
            header.write(f"    {{0x{vmaddr:016x}ULL, {offset}, {length}, 0x{offset ^ length:08x}}},\n")
        header.write("};\n\n")
        header.write("#define IMPORT_MANIFEST_COUNT (sizeof(import_manifest) / sizeof(import_manifest[0]))\n")
        header.write("static const size_t import_manifest_count = IMPORT_MANIFEST_COUNT;\n\n")

        header.write("enum import_symbol_id {\n")
        for index, (_, _, _, sanitized, original) in enumerate(manifest_entries):
            header.write(f"    import_symbol_{sanitized} = {index}, /* {original} */\n")
        header.write(f"    import_symbol_count = {len(manifest_entries)}\n")
        header.write("};\n")

    with wrappers_path.open("w", encoding="utf-8") as header:
        header.write("// Auto-generated by encrypt_binary.py; do not edit.\n")
        header.write("#pragma once\n\n")
        header.write("#if __has_include(\"import_manifest.h\") && import_manifest_count > 0\n")
        header.write("#include \"import_runtime.h\"\n\n")
        for _, _, _, sanitized, original in manifest_entries:
            header.write(f"#undef {original}\n")
            header.write(f"static inline __typeof__({original}) *import_ptr_{sanitized}(void) {{\n")
            header.write(f"    return (__typeof__({original}) *)import_runtime_get(import_symbol_{sanitized});\n")
            header.write("}\n")
            header.write(f"#define {original} (*import_ptr_{sanitized}())\n\n")
        header.write("#endif\n")

    print(f"[encrypt] Wrote import manifest to {manifest_path}")
    print(f"[encrypt] Wrote import wrappers to {wrappers_path}")


def scrub_import_metadata(encrypted: bytearray, metadata: dict) -> None:
    for section_offset in metadata.get("section_offsets", []):
        section = list(SECTION_STRUCT.unpack_from(encrypted, section_offset))
        section[9] = 0
        section[10] = 0
        section_flags = section[8]
        section_flags = (section_flags & ~SECTION_TYPE_MASK) | S_REGULAR
        section[8] = section_flags
        SECTION_STRUCT.pack_into(encrypted, section_offset, *section)

    for indirect_offset in metadata.get("indirect_offsets", []):
        if 0 <= indirect_offset <= len(encrypted) - 4:
            struct.pack_into("<I", encrypted, indirect_offset, INDIRECT_SYMBOL_LOCAL_END)

    stroff = metadata.get("stroff")
    strsize = metadata.get("strsize")
    if stroff is not None and strsize:
        end = min(stroff + strsize, len(encrypted))
        for i in range(stroff, end):
            encrypted[i] = 0

    symtab_offset = metadata.get("symtab_offset")
    if symtab_offset is not None:
        cmd, cmdsize, _, _, _, _ = SYMTAB_STRUCT.unpack_from(encrypted, symtab_offset)
        SYMTAB_STRUCT.pack_into(encrypted, symtab_offset, cmd, cmdsize, 0, 0, 0, 0)

    dys_offset = metadata.get("dysymtab_offset")
    if dys_offset is not None:
        cmd, cmdsize = struct.unpack_from("<II", encrypted, dys_offset)
        zeros = [0] * 18
        struct.pack_into("<II18I", encrypted, dys_offset, cmd, cmdsize, *zeros)

    # Preserve chained fixups command to avoid dyld complaints; names are already removed elsewhere.


def encrypt_binary_sections(binary_path: Path, output_path: Path, key: int, manifest_only: bool) -> None:
    original = binary_path.read_bytes()

    entries, metadata = collect_import_entries(original)
    write_manifest_and_wrappers(entries, output_path.parent)

    if manifest_only:
        return

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
            print(f"[encrypt] Updated {segname} maxprot from 0x{maxprot:x} to 0x{new_maxprot:x}")
        else:
            print(f"[encrypt] {segname} maxprot already writable (0x{maxprot:x})")

    scrub_import_metadata(encrypted, metadata)

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
    parser.add_argument(
        "--manifest-only",
        action="store_true",
        help="Only emit import manifest/wrappers; skip writing the encrypted binary.",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    encrypt_binary_sections(args.input, args.output, args.key, manifest_only=args.manifest_only)


if __name__ == "__main__":
    main()
