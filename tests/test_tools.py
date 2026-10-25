import struct
import unittest

from ps2net import knowledge, porter
from ps2net.elf import parse_elf
from ps2net.iopcompat import _body, _ordinals
from ps2net.scan import needs, survey_strings
from tests.builders import build_elf

JR_RA, NOP = 0x03E00008, 0


def jal(target: int) -> int:
    return 0x0C000000 | ((target >> 2) & 0x03FFFFFF)


def lui(rt: int, value: int) -> int:
    return 0x3C000000 | (rt << 16) | value


def addiu(rt: int, rs: int, imm: int) -> int:
    return 0x24000000 | (rs << 21) | (rt << 16) | (imm & 0xFFFF)


def build_program(base: int, order: list[str], padding: int = 0) -> tuple[bytes, dict[str, int]]:
    """Five small functions; `main` calls the others; `say` loads the address of a string.
    `padding` words of filler code are inserted first so every address moves."""
    bodies = {
        "main": lambda a: [addiu(29, 29, -16), jal(a["init"]), NOP, jal(a["update"]), NOP, jal(a["say"]), NOP, JR_RA, NOP],
        "init": lambda a: [addiu(2, 0, 1), addiu(3, 0, 2), addiu(4, 0, 3), JR_RA, addiu(2, 2, 7)],
        "update": lambda a: [addiu(2, 0, 9), addiu(5, 0, 5), addiu(6, 0, 6), addiu(7, 0, 7), JR_RA, NOP],
        "say": lambda a: [lui(4, a["@str"] >> 16), addiu(4, 4, a["@str"] & 0xFFFF), jal(a["update"]), NOP, JR_RA, NOP],
        "pad": lambda a: [addiu(8, 8, 1)] * padding + [JR_RA, NOP],
    }
    names = (["pad"] if padding else []) + order
    addr, layout = base, {}
    for n in names:
        layout[n] = addr
        addr += 4 * len(bodies[n]({k: 0 for k in names + ["@str"]}))
    layout["@str"] = 0x300000
    words = []
    for n in names:
        words += bodies[n](layout)
    return struct.pack(f"<{len(words)}I", *words), layout


def make_elf(order, padding=0, with_symbols=True):
    code, layout = build_program(0x100000, order, padding)
    syms = [(n, a, 0, 1) for n, a in layout.items() if not n.startswith("@") and n != "pad"] if with_symbols else []
    return parse_elf(build_elf([(".text", 1, 6, 0x100000, code), (".rodata", 1, 2, 0x300000, b"Hello, network!\0")],
                               syms, entry=layout[order[0]])), layout


class PorterTests(unittest.TestCase):
    def test_names_follow_moved_code(self):
        order = ["main", "init", "update", "say"]
        source, _ = make_elf(order)
        target, layout = make_elf(order, padding=7, with_symbols=False)
        result = porter.port(source, target, min_size=4)
        named = {result.name_of(layout[n]): n for n in order}
        for n in order:
            self.assertEqual(named.get(n), n, porter.render_csv(result))
        csv_text = porter.render_csv(result)
        self.assertTrue(csv_text.startswith("name,start,end,size"))
        self.assertIn(f"say,0x{layout['say']:08x}", csv_text)

    def test_strings_are_fingerprinted(self):
        target, layout = make_elf(["main", "init", "update", "say"])
        ranges = porter.code_ranges_of(target)
        funcs = porter.analyze(target, porter.discover_starts(target, ranges), ranges)
        self.assertEqual(funcs[layout["say"]].strings, frozenset({"Hello, network!"}))
        self.assertEqual(funcs[layout["main"]].calls, [layout["init"], layout["update"], layout["say"]])

    def test_monotonic_chain(self):
        chain = porter._monotonic([(1, 10), (2, 5), (3, 20), (4, 30), (5, 25), (6, 1)])
        self.assertEqual(len(chain), 3)  # several chains of 3 exist; any one will do
        self.assertTrue(all(a[0] < b[0] and a[1] < b[1] for a, b in zip(chain, chain[1:])))


class IopCompatParsingTests(unittest.TestCase):
    def test_case_labels_with_names(self):
        code = """
        bool X::dispatchImport(uint16_t ordinal) {
            // don't count the brace in this comment: {
            const char *s = "}";
            switch (ordinal) {
            case 4: // CreateThread(param)
            case 5:
                return true;
            case 20: // AddDrv
                if (ordinal == 33u) {}
                return true;
            }
            return false;
        }
        int after() { return 0; }
        """
        body = _body(code, code.index("dispatchImport"))
        self.assertNotIn("after", body)
        self.assertEqual(_ordinals(body), {4: "CreateThread", 5: "", 20: "AddDrv", 33: ""})


class KnowledgeTests(unittest.TestCase):
    def test_hosts_and_ips(self):
        self.assertEqual(knowledge.HOST_RE.search("master server tmbol-master.online.scee.com ok").group(),
                         "tmbol-master.online.scee.com")
        self.assertTrue(knowledge.NOT_HOSTS.search("net/inet.irx"))
        self.assertTrue(knowledge.is_private_ip((10, 0, 0, 1)))
        self.assertFalse(knowledge.is_private_ip((192, 60, 22, 2)))

    def test_survey_and_needs(self):
        strings = b"\0".join([b"Medius Client Library Version 1.40.PRE8", b"PsIIlibinsck2430",
                              b"tmbol-master.online.scee.com", b"cdrom0:\\NET\\INET.IRX;1",
                              b"AUTHENTICATING DNAS DATA", b"Attempting to connect to Peer 2 Peer Server", b"[MEDIUS_SERVER] %s"])
        e = parse_elf(build_elf([(".rodata", 1, 2, 0x300000, strings)]))
        s = survey_strings(e)
        self.assertEqual(s["middleware"]["Medius"]["versions"], ["1.40.PRE8"])
        self.assertEqual([h["host"] for h in s["hosts"]], ["tmbol-master.online.scee.com"])
        self.assertEqual(s["settings"], ["MEDIUS_SERVER"])
        self.assertEqual(s["loads"][0]["path"], "cdrom0:\\NET\\INET.IRX")
        self.assertTrue(s["sdk"][0]["network"])
        report = {"modules": [{"key": "dev9"}, {"key": "inet_smap_driver"}], "strings": s}
        text = "\n".join(needs(report))
        for expected in ("DEV9 + SMAP", "DNAS", "DNS overrides", "peer to peer"):
            self.assertIn(expected, text)


if __name__ == "__main__":
    unittest.main()
