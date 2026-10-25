"""Name SCE SDK functions in a stripped ELF with the PS2Recomp fork's signature database.

The database (from sce-symbol-scanner) is embedded in the fork as JSON inside
ps2xAnalyzer/include/ps2recomp/sce_symbol_database_data.h: per symbol, the SHA-1 of its bytes with relocated
fields cleared, and a prefix tree of first instruction words to find candidates. This mirrors the fork's
SceSymbolScanner (ps2xAnalyzer/src/sce_symbol_scanner.cpp), so results match what ps2_analyzer finds, and
keeps only unambiguous matches the same way.
"""
from __future__ import annotations

import hashlib
import json
import re
import struct
from dataclasses import dataclass
from pathlib import Path

DB_HEADER = Path("ps2xAnalyzer/include/ps2recomp/sce_symbol_database_data.h")

# Mask of the bits a relocation leaves untouched (relocationMask in the fork).
MASKS = {"none": 0xFFFFFFFF, "MIPS_26": 0xFC000000, "MIPS_LO16": 0xFFFF0000, "MIPS_HI16": 0xFFFF0000,
         "MIPS_GPREL16": 0xFFFF0000, "MIPS_LITERAL": 0xFFFF0000, "MIPS_32": 0}
# Bits the fork counts as relocated when it scores how distinctive a signature is (staticBitCount).
RELOCATED_BITS = {"none": 32, "MIPS_26": 6, "MIPS_LO16": 16, "MIPS_HI16": 16, "MIPS_GPREL16": 16, "MIPS_LITERAL": 16,
                  "MIPS_32": 0}
MIN_STATIC_BITS = 256

NET_LIBRARIES = {"libinsck", "netglue_insck", "netcnfif", "ent_smap", "libeenet", "eenetctl", "libhttps",
                 "netglue_eenet", "libnet", "libmrpc", "base64"}
NET_NAME_RE = re.compile(r"(?i)inet|insck|libnet|dnas|netcnf|socket|eenet|http|smap|mrpc")


def _reloc_type(text: str | None) -> str:
    t = (text or "none").upper().replace("MIPSLO16", "MIPS_LO16").replace("MIPSHI16", "MIPS_HI16")
    if t in ("LO16", "HI16"):
        t = "MIPS_" + t
    return t if t in MASKS else "none"


@dataclass
class SdkSymbol:
    library: str
    name: str
    sha1: bytes
    size: int
    relocations: list[tuple[int, str]]

    def static_bits(self) -> int:
        relocated = sum(RELOCATED_BITS[t] for _, t in self.relocations)
        total = self.size * 8
        return 0 if relocated >= total else total - relocated


class Node:
    __slots__ = ("offset", "symbols", "edges")

    def __init__(self, offset: int):
        self.offset = offset
        self.symbols: list[tuple] = []
        self.edges: dict[int, dict[int, list[Node]]] = {}  # mask -> masked value -> children


@dataclass
class Database:
    symbols: dict[tuple, SdkSymbol]
    root: Node


def _chunks(text: str, array: str) -> str:
    start = text.index(array)
    end = text.index("};", start)
    return "".join(re.findall(r'R"PS2SDB\((.*?)\)PS2SDB"', text[start:end], re.S))


def load_database(fork_root: str | Path) -> Database:
    header = Path(fork_root) / DB_HEADER
    if not header.exists():
        raise FileNotFoundError(f"{header} not found: --fork must point at a PS2Recomp checkout")
    text = header.read_text(encoding="utf-8")
    symbols: dict[tuple, SdkSymbol] = {}
    for library, names in json.loads(_chunks(text, "kSymbolsJsonChunks")).items():
        for name, hashes in names.items():
            for sha, variants in hashes.items():
                for variant, sym in variants.items():
                    if sym.get("type", "FUNCTION") != "FUNCTION" or not sym.get("size"):
                        continue
                    relocs = [(int(off, 0), _reloc_type(r.get("type"))) for off, r in sym.get("relocations", {}).items()]
                    symbols[(library, name, sha, int(variant, 16))] = SdkSymbol(
                        library, name, bytes.fromhex(sha), sym["size"], relocs)

    def build(j: dict) -> Node:
        node = Node(j.get("offset", 0))
        node.symbols = [(s.get("library", ""), s.get("name", ""), s.get("hash", ""), s.get("variant", 0))
                        for s in j.get("symbols", [])]
        for edge in j.get("next", []):
            match = edge["match"]
            mask = MASKS[_reloc_type(match.get("relocation", {}).get("type"))]
            node.edges.setdefault(mask, {}).setdefault(match.get("value", 0) & mask, []).append(build(edge["child"]))
        return node

    return Database(symbols, build(json.loads(_chunks(text, "kTreeJsonChunks"))))


def _matches(code: bytes, offset: int, sym: SdkSymbol) -> bool:
    body = bytearray(code[offset:offset + sym.size])
    for rel_off, rel_type in sym.relocations:
        if rel_off + 4 <= len(body):
            value = struct.unpack_from("<I", body, rel_off)[0]
            struct.pack_into("<I", body, rel_off, value & MASKS[rel_type])
    return hashlib.sha1(body).digest() == sym.sha1


def scan_elf(elf, db: Database) -> list[dict]:
    """Unambiguous SDK function matches: [{address, size, name, library}] sorted by address."""
    found: dict[int, dict[tuple, tuple[SdkSymbol, int]]] = {}
    for sec in elf.code_sections():
        code = elf.section_bytes(sec)
        words = struct.unpack_from(f"<{len(code) // 4}I", code)
        n = len(words)
        for i in range(n):
            stack = [db.root]
            while stack:
                node = stack.pop()
                j = i + node.offset // 4
                if j >= n:
                    continue
                value = words[j]
                for mask, table in node.edges.items():
                    for child in table.get(value & mask, ()):
                        for key in child.symbols:
                            sym = db.symbols.get(key)
                            if sym is None or sym.size > len(code) - i * 4 or not _matches(code, i * 4, sym):
                                continue
                            actual = sym.size
                            while i * 4 + actual + 4 <= len(code) and words[(i * 4 + actual) // 4] == 0:
                                actual += 4
                            found.setdefault(sec.addr + i * 4, {})[key] = (sym, actual)
                        if child.edges:
                            stack.append(child)
    out = []
    for addr, candidates in found.items():
        viable = [(s, a) for s, a in candidates.values() if s.static_bits() >= MIN_STATIC_BITS]
        if not viable or len({(s.library, s.name) for s, _ in viable}) != 1:
            continue
        sym, actual = max(viable, key=lambda c: (c[1], c[0].static_bits()))
        out.append({"address": addr, "size": actual, "name": sym.name, "library": sym.library})
    return sorted(out, key=lambda m: m["address"])


def network_only(matches: list[dict]) -> list[dict]:
    return [m for m in matches if m["library"] in NET_LIBRARIES or NET_NAME_RE.search(m["name"])]
