"""ELF32 little-endian reader for PS2 executables and IOP modules (IRX), plus IOPRP (ROMDIR) images."""
from __future__ import annotations

import re
import struct
from dataclasses import dataclass, field

SHT_SYMTAB = 2
SHT_NOBITS = 8
SHT_IOPMOD = 0x70000080
SHF_EXECINSTR = 0x4
PT_LOAD = 1

IMPORT_MAGIC = 0x41E00000
EXPORT_MAGIC = 0x41C00000


class ElfError(Exception):
    pass


@dataclass
class Section:
    name: str
    type: int
    flags: int
    addr: int
    offset: int
    size: int
    link: int = 0

    @property
    def executable(self) -> bool:
        return bool(self.flags & SHF_EXECINSTR)


@dataclass
class Symbol:
    name: str
    addr: int
    size: int


@dataclass
class Elf:
    data: bytes
    entry: int
    sections: list[Section]
    segments: list[tuple[int, int, int]]  # (vaddr, file offset, file size)

    def section(self, name: str) -> Section | None:
        return next((s for s in self.sections if s.name == name), None)

    def section_bytes(self, sec: Section) -> bytes:
        if sec.type == SHT_NOBITS:
            return b""
        return self.data[sec.offset:sec.offset + sec.size]

    def code_sections(self) -> list[Section]:
        """Executable sections. ELFs without section headers fall back to their first loadable segment."""
        secs = [s for s in self.sections if s.executable and s.size and s.type != SHT_NOBITS and s.addr]
        if secs or not self.segments:
            return secs
        vaddr, off, size = self.segments[0]
        return [Section("<segment0>", 1, SHF_EXECINSTR, vaddr, off, size)]

    def file_offset(self, vaddr: int) -> int | None:
        for sec in self.sections:
            if sec.addr and sec.type != SHT_NOBITS and sec.addr <= vaddr < sec.addr + sec.size:
                return sec.offset + vaddr - sec.addr
        for seg_vaddr, off, size in self.segments:
            if seg_vaddr <= vaddr < seg_vaddr + size:
                return off + vaddr - seg_vaddr
        return None

    def vaddr(self, file_offset: int) -> int | None:
        for sec in self.sections:
            if sec.addr and sec.type != SHT_NOBITS and sec.offset <= file_offset < sec.offset + sec.size:
                return sec.addr + file_offset - sec.offset
        for seg_vaddr, off, size in self.segments:
            if off <= file_offset < off + size:
                return seg_vaddr + file_offset - off
        return None

    def read32(self, vaddr: int) -> int:
        off = self.file_offset(vaddr)
        if off is None:
            raise ElfError(f"0x{vaddr:08x} is not in the file")
        return struct.unpack_from("<I", self.data, off)[0]

    def function_symbols(self) -> list[Symbol]:
        """Function symbols from .symtab: FUNC entries, plus sized NOTYPE labels in code (hand-written assembly)."""
        symtab = next((s for s in self.sections if s.type == SHT_SYMTAB), None)
        if symtab is None:
            return []
        strtab = self.sections[symtab.link]
        code = [s for s in self.sections if s.executable]
        out: dict[int, Symbol] = {}
        raw = self.section_bytes(symtab)
        for i in range(0, len(raw) - 15, 16):
            name_off, value, size, info, _, shndx = struct.unpack_from("<IIIBBH", raw, i)
            kind = info & 0xF
            if kind not in (0, 2) or not value or shndx == 0 or shndx >= len(self.sections):
                continue
            if self.sections[shndx] not in code or (kind == 0 and not size):
                continue
            end = self.data.index(b"\0", strtab.offset + name_off)
            name = self.data[strtab.offset + name_off:end].decode("ascii", "replace")
            if not name or name.startswith("$") or name.startswith(".L"):
                continue
            current = out.get(value)
            if current is None or (kind == 2 and size >= current.size):
                out[value] = Symbol(name, value, size)
        return sorted(out.values(), key=lambda s: s.addr)

    def strings(self, minlen: int = 5) -> list[tuple[int, str]]:
        """Printable ASCII runs as (file offset, text)."""
        return [(m.start(), m.group().decode("ascii")) for m in re.finditer(rb"[\x20-\x7e]{%d,}" % minlen, self.data)]


def parse_elf(data: bytes) -> Elf:
    if data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    if data[4] != 1 or data[5] != 1:
        raise ElfError("not a 32-bit little-endian ELF")
    entry, phoff, shoff = struct.unpack_from("<III", data, 0x18)
    phentsize, phnum, shentsize, shnum, shstrndx = struct.unpack_from("<HHHHH", data, 0x2A)
    segments = []
    for i in range(phnum if phoff else 0):
        p_type, p_offset, p_vaddr, _, p_filesz = struct.unpack_from("<IIIII", data, phoff + i * phentsize)
        if p_type == PT_LOAD and p_filesz:
            segments.append((p_vaddr, p_offset, p_filesz))
    sections = []
    if shoff and shnum and shoff + shnum * shentsize <= len(data):
        headers = [struct.unpack_from("<10I", data, shoff + i * shentsize) for i in range(shnum)]
        names_off = headers[shstrndx][4] if shstrndx < shnum else 0
        for h in headers:
            name = ""
            if names_off:
                end = data.find(b"\0", names_off + h[0])
                name = data[names_off + h[0]:end].decode("ascii", "replace")
            sections.append(Section(name, h[1], h[2], h[3], h[4], h[5], h[6]))
    return Elf(data, entry, sections, segments)


# --- IOP modules ---------------------------------------------------------------------------------------------


@dataclass
class IrxLibrary:
    name: str
    version: int
    ordinals: list[int] = field(default_factory=list)  # imported function indices, or export count

    @property
    def version_text(self) -> str:
        return f"{self.version >> 8}.{self.version & 0xFF:02d}"


@dataclass
class IrxInfo:
    name: str | None
    version: int | None
    imports: list[IrxLibrary]
    exports: list[IrxLibrary]

    @property
    def version_text(self) -> str:
        return "?" if self.version is None else f"{self.version >> 8}.{self.version & 0xFF:02d}"


def _lib_name(data: bytes, off: int) -> str:
    return data[off + 12:off + 20].split(b"\0")[0].decode("ascii", "replace")


def irx_info(data: bytes) -> IrxInfo:
    """Module name and version (.iopmod), imported libraries with the ordinals called, exported libraries."""
    name = version = None
    try:
        elf = parse_elf(data)
        mod = next((s for s in elf.sections if s.type == SHT_IOPMOD), None)
        if mod is not None and mod.size > 26:
            version = struct.unpack_from("<H", data, mod.offset + 24)[0]
            name = data[mod.offset + 26:mod.offset + mod.size].split(b"\0")[0].decode("ascii", "replace")
            if len(name) < 2 or not name.isprintable():
                name = None
    except ElfError:
        pass

    imports: list[IrxLibrary] = []
    exports: list[IrxLibrary] = []
    for m in re.finditer(rb"\x00\x00\xe0\x41\x00\x00\x00\x00", data):
        off = m.start()
        if off % 4:
            continue
        lib = IrxLibrary(_lib_name(data, off), struct.unpack_from("<H", data, off + 8)[0])
        cursor = off + 20
        while cursor + 8 <= len(data):
            jr, addiu = struct.unpack_from("<II", data, cursor)
            if jr != 0x03E00008 or addiu >> 16 != 0x2400:
                break
            lib.ordinals.append(addiu & 0xFFFF)
            cursor += 8
        if lib.name:
            imports.append(lib)
    for m in re.finditer(rb"\x00\x00\xc0\x41\x00\x00\x00\x00", data):
        off = m.start()
        if off % 4:
            continue
        lib = IrxLibrary(_lib_name(data, off), struct.unpack_from("<H", data, off + 8)[0])
        cursor = off + 20
        while cursor + 4 <= len(data) and struct.unpack_from("<I", data, cursor)[0] != 0 and len(lib.ordinals) < 1024:
            lib.ordinals.append(len(lib.ordinals))
            cursor += 4
        if lib.name and lib.name.isprintable():
            exports.append(lib)
    return IrxInfo(name, version, imports, exports)


def romdir_entries(data: bytes) -> list[tuple[str, bytes]]:
    """Files of an IOPRP image (ROMDIR: RESET, ROMDIR, EXTINFO, then modules), as (name, bytes)."""
    start = data.find(b"RESET\0")
    if start < 0:
        return []
    entries = []
    pos = start
    while pos + 16 <= len(data):
        raw_name, _, size = struct.unpack_from("<10sHI", data, pos)
        name = raw_name.split(b"\0")[0].decode("ascii", "replace")
        if not name:
            break
        entries.append((name, size))
        pos += 16
    out, offset = [], 0
    for name, size in entries:
        out.append((name, data[offset:offset + size]))
        offset += (size + 15) & ~15
    return out
