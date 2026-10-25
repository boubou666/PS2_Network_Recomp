import struct
import tempfile
import unittest
from pathlib import Path

from ps2net import disc, elf
from tests.builders import build_elf, build_iso, export_table, import_table, iopmod, iso_to_mode2

FILES = {
    "SYSTEM.CNF": b"BOOT2 = cdrom0:\\SLUS_123.45;1\r\nVER = 1.00\r\nVMODE = NTSC\r\n",
    "SLUS_123.45": b"\x7fELF" + b"\0" * 60,
    "NET/INET.IRX": b"inet" * 1000,
}


class DiscTests(unittest.TestCase):
    def check(self, d):
        self.assertEqual(set(d.files()), set(FILES))
        self.assertEqual(d.read("net/inet.irx"), FILES["NET/INET.IRX"])
        self.assertEqual(disc.boot_elf_path(d), "SLUS_123.45")
        self.assertEqual(disc.system_cnf(d)["VMODE"], "NTSC")

    def test_iso_bin_cue_and_folder(self):
        iso = build_iso(FILES)
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "game.iso").write_bytes(iso)
            (tmp / "game.bin").write_bytes(iso_to_mode2(iso))
            (tmp / "game.cue").write_text('FILE "game.bin" BINARY\n  TRACK 01 MODE2/2352\n    INDEX 01 00:00:00\n')
            for name in ("game.iso", "game.bin", "game.cue"):
                d = disc.open_disc(tmp / name)
                self.check(d)
                d.close()
            raw = disc.open_disc(tmp / "game.bin")
            self.assertEqual((raw.sector_size, raw.data_offset), (2352, 24))
            raw.close()
            out = tmp / "out"
            self.assertEqual(sorted(disc.extract(disc.open_disc(tmp / "game.iso"), out, ["NET/"])), ["NET/INET.IRX"])
            self.check(disc.FolderDisc(_copy_all(tmp / "game.iso", tmp / "all")))


def _copy_all(image, out):
    disc.extract(disc.open_disc(image), out)
    return out


class ElfTests(unittest.TestCase):
    def test_sections_and_function_symbols(self):
        text = struct.pack("<8I", *([0x03E00008, 0] * 4))
        data = build_elf([(".text", 1, 6, 0x100000, text), (".data", 1, 3, 0x200000, b"hello world\0")],
                         [("first", 0x100000, 8, 1), ("second", 0x100008, 24, 1), ("var", 0x200000, 12, 2)],
                         entry=0x100000)
        e = elf.parse_elf(data)
        self.assertEqual(e.entry, 0x100000)
        self.assertEqual([s.name for s in e.function_symbols()], ["first", "second"])
        self.assertEqual(e.read32(0x100000), 0x03E00008)
        self.assertEqual(e.vaddr(e.file_offset(0x200004)), 0x200004)
        self.assertIn("hello world", [s for _, s in e.strings()])

    def test_irx_tables(self):
        body = import_table("thbase", 0x0102, [4, 6, 33]) + export_table("smap", 0x0101, 5) + import_table("dev9", 0x104, [4])
        data = build_elf([(".iopmod", 0x70000080, 0, 0, iopmod("INET_SMAP_driver", 0x0141)), (".text", 1, 6, 0, body)])
        info = elf.irx_info(data)
        self.assertEqual((info.name, info.version_text), ("INET_SMAP_driver", "1.65"))
        self.assertEqual([(i.name, i.version_text, i.ordinals) for i in info.imports],
                         [("thbase", "1.02", [4, 6, 33]), ("dev9", "1.04", [4])])
        self.assertEqual([(x.name, len(x.ordinals)) for x in info.exports], [("smap", 5)])

    def test_romdir(self):
        # As in real IOPRP images: RESET is empty, so the ROMDIR table itself is the file at offset 0.
        mod = b"\x7fELF" + b"x" * 20
        names = [("RESET", 0), ("ROMDIR", 80), ("EXTINFO", 0), ("CDVDMAN", len(mod))]
        romdir = b"".join(struct.pack("<10sHI", n.encode(), 0, size) for n, size in names) + b"\0" * 16
        image = romdir + mod
        entries = elf.romdir_entries(image)
        self.assertEqual([n for n, _ in entries], ["RESET", "ROMDIR", "EXTINFO", "CDVDMAN"])
        self.assertEqual(entries[3][1], mod)


if __name__ == "__main__":
    unittest.main()
