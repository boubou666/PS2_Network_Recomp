"""Synthetic inputs for the tests: ELF files, IRX tables, ISO9660 images. No game data."""
from __future__ import annotations

import struct


def build_elf(sections: list[tuple[str, int, int, int, bytes]], symbols: list[tuple[str, int, int, int]] = (),
              entry: int = 0) -> bytes:
    """sections: (name, type, flags, addr, data); symbols: (name, value, size, section index, 1-based)."""
    names = [""] + [s[0] for s in sections]
    if symbols:
        names += [".symtab", ".strtab"]
    names.append(".shstrtab")
    shstr = b"\0"
    name_off = {"": 0}
    for n in names[1:]:
        name_off[n] = len(shstr)
        shstr += n.encode() + b"\0"

    blobs = [s[4] for s in sections]
    headers = [(name_off[s[0]], s[1], s[2], s[3]) for s in sections]
    links = [0] * len(sections)
    if symbols:
        strtab = b"\0"
        symtab = b"\0" * 16
        for name, value, size, shndx in symbols:
            symtab += struct.pack("<IIIBBH", len(strtab), value, size, 0x12, 0, shndx)
            strtab += name.encode() + b"\0"
        sym_index = len(sections) + 1
        blobs += [symtab, strtab]
        headers += [(name_off[".symtab"], 2, 0, 0), (name_off[".strtab"], 3, 0, 0)]
        links += [sym_index + 1, 0]
    blobs.append(shstr)
    headers.append((name_off[".shstrtab"], 3, 0, 0))
    links.append(0)

    data = bytearray(52)
    offsets = []
    for blob in blobs:
        while len(data) % 4:
            data.append(0)
        offsets.append(len(data))
        data += blob
    while len(data) % 4:
        data.append(0)
    shoff = len(data)
    data += b"\0" * 40
    for (name, typ, flags, addr), off, blob, link in zip(headers, offsets, blobs, links):
        data += struct.pack("<10I", name, typ, flags, addr, off, len(blob), link, 0, 4, 16 if typ == 2 else 0)
    shnum = len(headers) + 1
    data[0:52] = (b"\x7fELF\x01\x01\x01" + b"\0" * 9
                  + struct.pack("<HHIIIIIHHHHHH", 2, 8, 1, entry, 0, shoff, 0, 52, 32, 0, 40, shnum, shnum - 1))
    return bytes(data)


def import_table(name: str, version: int, ordinals: list[int]) -> bytes:
    out = struct.pack("<IIHH", 0x41E00000, 0, version, 0) + name.encode().ljust(8, b"\0")
    for o in ordinals:
        out += struct.pack("<II", 0x03E00008, 0x24000000 | o)
    return out + b"\0" * 8


def export_table(name: str, version: int, count: int) -> bytes:
    out = struct.pack("<IIHH", 0x41C00000, 0, version, 0) + name.encode().ljust(8, b"\0")
    return out + b"".join(struct.pack("<I", 0x1000 + 4 * i) for i in range(count)) + b"\0" * 4


def iopmod(name: str, version: int) -> bytes:
    return struct.pack("<6IH", 0, 0, 0, 0, 0, 0, version) + name.encode() + b"\0"


def _dir_record(name: bytes, lba: int, size: int, is_dir: bool) -> bytes:
    length = 33 + len(name) + (1 - len(name) % 2)
    rec = bytearray(length)
    rec[0] = length
    struct.pack_into("<I", rec, 2, lba)
    struct.pack_into(">I", rec, 6, lba)
    struct.pack_into("<I", rec, 10, size)
    struct.pack_into(">I", rec, 14, size)
    rec[25] = 2 if is_dir else 0
    rec[32] = len(name)
    rec[33:33 + len(name)] = name
    return bytes(rec)


def build_iso(files: dict[str, bytes]) -> bytes:
    """A 2048-byte-sector ISO9660 image with one level of folders: {"SYSTEM.CNF": ..., "NET/INET.IRX": ...}."""
    folders: dict[str, dict[str, bytes]] = {"": {}}
    for path, data in files.items():
        folder, _, name = path.rpartition("/")
        folders.setdefault(folder, {})[name] = data
        folders.setdefault("", {})
    lba = 18  # 16 = PVD, 17 = terminator
    dir_lba = {}
    for folder in folders:
        dir_lba[folder] = lba
        lba += 1
    file_lba = {}
    for folder, entries in folders.items():
        for name, data in entries.items():
            file_lba[(folder, name)] = lba
            lba += max(1, (len(data) + 2047) // 2048)
    image = bytearray(lba * 2048)
    for folder, entries in folders.items():
        recs = _dir_record(b"\0", dir_lba[folder], 2048, True) + _dir_record(b"\1", dir_lba[""], 2048, True)
        if folder == "":
            for sub in folders:
                if sub:
                    recs += _dir_record(sub.encode(), dir_lba[sub], 2048, True)
        for name, data in entries.items():
            recs += _dir_record(f"{name};1".encode(), file_lba[(folder, name)], len(data), False)
            start = file_lba[(folder, name)] * 2048
            image[start:start + len(data)] = data
        image[dir_lba[folder] * 2048:dir_lba[folder] * 2048 + len(recs)] = recs
    pvd = bytearray(2048)
    pvd[0], pvd[1:6], pvd[6] = 1, b"CD001", 1
    pvd[40:72] = b"TESTDISC".ljust(32)
    pvd[156:156 + 34] = _dir_record(b"\0", dir_lba[""], 2048, True)
    image[16 * 2048:17 * 2048] = pvd
    image[17 * 2048] = 255
    image[17 * 2048 + 1:17 * 2048 + 6] = b"CD001"
    return bytes(image)


def iso_to_mode2(iso: bytes) -> bytes:
    """Wrap 2048-byte sectors in raw 2352-byte MODE2 form 1 sectors (sync, header, subheader, data, EDC/ECC)."""
    out = bytearray()
    for i in range(len(iso) // 2048):
        out += b"\x00" + b"\xff" * 10 + b"\x00" + bytes([0, 2, 0, 2]) + b"\0" * 8 + iso[i * 2048:(i + 1) * 2048] + b"\0" * 280
    return bytes(out)
