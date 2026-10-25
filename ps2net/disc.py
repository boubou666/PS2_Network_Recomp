"""Read files from a PS2 disc: a 2048-byte ISO, a raw 2352-byte BIN (MODE1 or MODE2 form 1), a CUE sheet,
or a folder the disc was already extracted to.

Every disc exposes the same interface: `files()` maps an upper-case path ("NET/INET.IRX") to its size, and
`read(path)` returns the file's bytes.
"""
from __future__ import annotations

import os
import re
import struct
from pathlib import Path

SYNC = b"\x00" + b"\xff" * 10 + b"\x00"


class DiscError(Exception):
    pass


def _norm(path: str) -> str:
    return path.replace("\\", "/").strip("/").split(";")[0].upper()


class ImageDisc:
    """An ISO9660 file system inside a disc image."""

    def __init__(self, path: Path, track_offset: int = 0):
        self.path = Path(path)
        self._f = open(self.path, "rb")
        self.sector_size, self.data_offset = self._detect_layout(track_offset)
        self.track_offset = track_offset
        self._entries: dict[str, tuple[int, int]] = {}
        pvd = self._sectors(16)
        if pvd[1:6] != b"CD001":
            raise DiscError(f"{self.path.name}: no ISO9660 volume descriptor at sector 16")
        self.volume_id = pvd[40:72].decode("ascii", "replace").strip()
        root = pvd[156:156 + 34]
        self._walk(struct.unpack_from("<I", root, 2)[0], struct.unpack_from("<I", root, 10)[0], "")

    def _detect_layout(self, track_offset: int) -> tuple[int, int]:
        self._f.seek(track_offset)
        head = self._f.read(16)
        if head[:12] == SYNC:
            mode = head[15]
            if mode == 1:
                return 2352, 16
            if mode == 2:
                return 2352, 24
            raise DiscError(f"{self.path.name}: unsupported sector mode {mode}")
        return 2048, 0

    def _sectors(self, lba: int, count: int = 1) -> bytes:
        if self.sector_size == 2048:
            self._f.seek(self.track_offset + lba * 2048)
            return self._f.read(count * 2048)
        out = bytearray()
        for i in range(count):
            self._f.seek(self.track_offset + (lba + i) * self.sector_size + self.data_offset)
            out += self._f.read(2048)
        return bytes(out)

    def _walk(self, lba: int, size: int, prefix: str, depth: int = 0) -> None:
        if depth > 16:
            return
        data = self._sectors(lba, (size + 2047) // 2048)
        pos = 0
        while pos < size:
            length = data[pos]
            if length == 0:
                pos = (pos // 2048 + 1) * 2048
                continue
            record = data[pos:pos + length]
            pos += length
            name = record[33:33 + record[32]]
            if name in (b"\x00", b"\x01"):
                continue
            entry_lba, entry_size = struct.unpack_from("<I", record, 2)[0], struct.unpack_from("<I", record, 10)[0]
            path = f"{prefix}/{_norm(name.decode('ascii', 'replace'))}".lstrip("/")
            if record[25] & 2:
                self._walk(entry_lba, entry_size, path, depth + 1)
            else:
                self._entries[path] = (entry_lba, entry_size)

    def files(self) -> dict[str, int]:
        return {path: size for path, (_, size) in sorted(self._entries.items())}

    def read(self, path: str) -> bytes:
        lba, size = self._entries[_norm(path)]
        return self._sectors(lba, (size + 2047) // 2048)[:size]

    def lba(self, path: str) -> int:
        return self._entries[_norm(path)][0]

    def close(self) -> None:
        self._f.close()


class FolderDisc:
    """A disc already extracted to a folder."""

    def __init__(self, path: Path):
        self.path = Path(path)
        self.volume_id = self.path.name
        self._entries: dict[str, Path] = {}
        for root, _, names in os.walk(self.path):
            for name in names:
                full = Path(root) / name
                self._entries[_norm(str(full.relative_to(self.path)))] = full

    def files(self) -> dict[str, int]:
        return {path: full.stat().st_size for path, full in sorted(self._entries.items())}

    def read(self, path: str) -> bytes:
        return self._entries[_norm(path)].read_bytes()

    def close(self) -> None:
        pass


def _from_cue(cue: Path) -> ImageDisc:
    text = cue.read_text(errors="replace")
    match = re.search(r'FILE\s+"([^"]+)"', text) or re.search(r"FILE\s+(\S+)", text)
    if not match:
        raise DiscError(f"{cue.name}: no FILE line")
    return ImageDisc(cue.parent / match.group(1))


def open_disc(path: str | os.PathLike) -> ImageDisc | FolderDisc:
    path = Path(path)
    if path.is_dir():
        return FolderDisc(path)
    if path.suffix.lower() == ".cue":
        return _from_cue(path)
    return ImageDisc(path)


def system_cnf(disc) -> dict[str, str]:
    """SYSTEM.CNF as a dict (BOOT2, VER, VMODE...). Empty when the disc has none."""
    try:
        text = disc.read("SYSTEM.CNF").decode("ascii", "replace")
    except KeyError:
        return {}
    out = {}
    for line in text.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            out[key.strip().upper()] = value.strip()
    return out


def boot_elf_path(disc) -> str | None:
    """Disc path of the boot executable named by BOOT2 ("cdrom0:\\SCES_514.80;1" -> "SCES_514.80")."""
    boot = system_cnf(disc).get("BOOT2") or system_cnf(disc).get("BOOT")
    if not boot:
        return None
    return _norm(boot.split(":", 1)[-1])


def extract(disc, out_dir: Path, patterns: list[str] | None = None) -> list[str]:
    """Copy files whose path contains one of the patterns (all files when none) to out_dir."""
    written = []
    wanted = [p.upper() for p in patterns or []]
    for path in disc.files():
        if wanted and not any(p in path for p in wanted):
            continue
        dest = Path(out_dir) / path
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(disc.read(path))
        written.append(path)
    return written
