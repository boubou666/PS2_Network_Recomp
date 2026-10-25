"""Carry function names from an ELF that has symbols to a stripped build of the same engine.

Typical use: an offline release ships with its symbol table and the online release (or another region,
a demo, a sequel on the same engine) is stripped. The functions mostly keep their code; only addresses move.

Passes, repeated until nothing changes:
  exact    same instructions once addresses are masked (jal targets, lui/addiu pairs, gp-relative offsets),
           unique on both sides
  strings  same set of referenced strings (debug messages, file names), unique on both sides
  callee   the n-th call of two matched functions goes to two unmatched functions of similar shape
  caller   the only unmatched caller of two matched functions, if similar
  order    the same number of unmatched functions between two matched ones, in the same order, similar sizes
  align    otherwise, the functions between two matched ones aligned by instruction-shape similarity, in order
Each name records the pass that found it; exact and strings are reliable, the others are good guesses.
"""
from __future__ import annotations

import bisect
import csv
import difflib
import hashlib
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass, field

JR_RA = 0x03E00008
OP_J, OP_JAL, OP_LUI = 2, 3, 15
# I-type opcodes whose immediate is an address offset when the base register holds a lui'd high half.
ADDRESS_IMM_OPS = {8, 9, 13, 24, 25, 26, 27, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47,
                   49, 54, 55, 57, 62, 63}
# Opcodes that write no general register through rt: branches, stores, coprocessor ops, cache.
NO_RT_WRITE = {1, 4, 5, 6, 7, 16, 17, 18, 19, 20, 21, 22, 23, 29, 31, 40, 41, 42, 43, 44, 45, 46, 47, 57, 58, 61, 62, 63}
GP = 28
METHOD_RANK = {"sdk": -1, "exact": 0, "strings": 1, "callee": 2, "caller": 3, "align": 4, "order": 5}
ALIGN_MIN_SIMILARITY = 0.75
ALIGN_MARGIN = 0.05  # a pair must beat every other candidate in its row and column by this much
ALIGN_MIN_SIZE = 32  # small wrappers look alike; leave them to the other passes
ALIGN_MAX_CELLS = 40_000  # gaps bigger than this (rows x columns) are left alone


@dataclass
class Func:
    start: int
    end: int
    name: str = ""
    hash: bytes = b""
    shape: bytes = b""  # opcode sequence, for similarity
    calls: list[int] = field(default_factory=list)  # jal targets, in order
    strings: frozenset = frozenset()

    @property
    def size(self) -> int:
        return self.end - self.start


def _read_string(elf, addr: int) -> str | None:
    off = elf.file_offset(addr)
    if off is None:
        return None
    end = elf.data.find(b"\0", off, off + 256)
    if end - off < 4:
        return None
    raw = elf.data[off:end]
    if not all(32 <= b < 127 or b in (9, 10, 13) for b in raw):
        return None
    return raw.decode("ascii")


def analyze(elf, starts: list[int], code_ranges: list[tuple[int, int, bytes]]) -> dict[int, Func]:
    """Fingerprint each function [start, next start) inside the code sections."""
    funcs: dict[int, Func] = {}
    starts = sorted(set(starts))
    for (base, limit, code) in code_ranges:
        local = [s for s in starts if base <= s < limit]
        for k, start in enumerate(local):
            end = local[k + 1] if k + 1 < len(local) else limit
            # Trailing zero padding belongs to nobody.
            while end - 4 > start and struct.unpack_from("<I", code, end - 4 - base)[0] == 0:
                end -= 4
            words = struct.unpack_from(f"<{(end - start) // 4}I", code, start - base)
            norm, shape, calls, strings = [], [], [], set()
            hi: dict[int, int] = {}  # register -> lui value
            for i, w in enumerate(words):
                op, rs, rt = w >> 26, (w >> 21) & 31, (w >> 16) & 31
                shape.append(op if op else 64 + (w & 63))
                if op == OP_LUI:
                    norm.append(w & 0xFFFF0000)
                    hi[rt] = (w & 0xFFFF) << 16
                    continue
                if op in (OP_J, OP_JAL):
                    norm.append(w & 0xFC000000)
                    if op == OP_JAL:
                        calls.append(((start + i * 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2))
                elif op in ADDRESS_IMM_OPS and (rs in hi or rs == GP):
                    norm.append(w & 0xFFFF0000)
                    if rs in hi and op in (9, 13):  # addiu / ori complete an address
                        imm = w & 0xFFFF
                        addr = (hi[rs] + (imm - 0x10000 if op == 9 and imm & 0x8000 else imm)) & 0xFFFFFFFF
                        if s := _read_string(elf, addr):
                            strings.add(s)
                else:
                    norm.append(w)
                # Once a register is written by anything else, it no longer holds a lui'd high half.
                # `addiu rX, rX, lo` keeps it: the low half often goes into the same register.
                if op in (0, 28):
                    dest = (w >> 11) & 31
                elif op == OP_JAL:
                    dest = 31
                elif op in NO_RT_WRITE or op == OP_J:
                    dest = None
                else:
                    dest = rt
                if dest is not None and dest in hi and not (op == 9 and rs == dest):
                    del hi[dest]
            funcs[start] = Func(start, end, hash=hashlib.sha1(struct.pack(f"<{len(norm)}I", *norm)).digest(),
                                shape=bytes(shape), calls=calls, strings=frozenset(strings))
    return funcs


BRANCH_OPS = {4, 5, 6, 7, 20, 21, 22, 23}  # beq bne blez bgtz and their -likely forms
REGIMM, COP1, COP2 = 1, 17, 18


def _branch_target(w: int, pc: int) -> int | None:
    op = w >> 26
    if op in BRANCH_OPS or op == REGIMM or (op in (COP1, COP2) and (w >> 21) & 31 == 8):
        imm = w & 0xFFFF
        return pc + 4 + ((imm - 0x10000 if imm & 0x8000 else imm) << 2)
    if op == OP_J:
        return (pc & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
    return None


def discover_starts(elf, code_ranges) -> list[int]:
    """Function starts in a stripped ELF: the entry point, jal targets, code addresses stored in data
    (function pointers, vtables), and code after `jr ra` + delay slot + padding unless a branch from
    before it lands there (an early return inside a function)."""
    starts = {elf.entry}
    in_code = lambda a: any(b <= a < l for b, l, _ in code_ranges)
    returns = set()
    branched_from_before = set()
    for base, limit, code in code_ranges:
        words = struct.unpack_from(f"<{len(code) // 4}I", code)
        for i, w in enumerate(words):
            pc = base + i * 4
            if w >> 26 == OP_JAL:
                target = (pc & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
                if in_code(target):
                    starts.add(target)
            elif w == JR_RA:
                j = i + 2
                while j < len(words) and words[j] == 0:
                    j += 1
                if j < len(words):
                    returns.add(base + j * 4)
            elif (target := _branch_target(w, pc)) is not None and target > pc:
                branched_from_before.add(target)
    starts |= returns - branched_from_before
    for sec in elf.sections:
        if sec.executable or not sec.size or sec.type == 8:
            continue
        data = elf.section_bytes(sec)
        for (value,) in struct.iter_unpack("<I", data[:len(data) // 4 * 4]):
            if value % 4 == 0 and in_code(value) and value in returns:
                starts.add(value)
    return sorted(starts)


def code_ranges_of(elf) -> list[tuple[int, int, bytes]]:
    return [(s.addr, s.addr + s.size, elf.section_bytes(s)) for s in elf.code_sections() if s.name != ".vutext"]


def _shape_similarity(a: Func, b: Func) -> float:
    """0..1 similarity of two instruction-shape sequences, 0 when the sizes are too far apart."""
    if a.hash == b.hash:
        return 1.0
    small, big = sorted((a.size, b.size))
    # A missed function start merges two functions into one bigger block: sizes must stay close.
    if small < ALIGN_MIN_SIZE or small / big < 0.8:
        return 0.0
    m = difflib.SequenceMatcher(None, a.shape, b.shape, autojunk=False)
    if m.real_quick_ratio() < ALIGN_MIN_SIMILARITY or m.quick_ratio() < ALIGN_MIN_SIMILARITY:
        return 0.0
    return m.ratio()


def _align(gs: list[Func], gt: list[Func]) -> list[tuple[Func, Func]]:
    """Order-preserving alignment of two function lists maximizing total shape similarity."""
    n, m = len(gs), len(gt)
    raw = [[_shape_similarity(a, b) for b in gt] for a in gs]
    # Keep only clear mutual best pairs: near-identical wrappers would otherwise be paired by position.
    sim = [[0.0] * m for _ in range(n)]
    for i in range(n):
        for j in range(m):
            s = raw[i][j]
            if s < ALIGN_MIN_SIMILARITY:
                continue
            others = [raw[i][k] for k in range(m) if k != j] + [raw[k][j] for k in range(n) if k != i]
            if all(s - o >= ALIGN_MARGIN for o in others):
                sim[i][j] = s
    score =[[0.0] * (m + 1) for _ in range(n + 1)]
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            best = max(score[i - 1][j], score[i][j - 1])
            s = sim[i - 1][j - 1]
            if s >= ALIGN_MIN_SIMILARITY:
                best = max(best, score[i - 1][j - 1] + s)
            score[i][j] = best
    pairs, i, j = [], n, m
    while i and j:
        s = sim[i - 1][j - 1]
        if s >= ALIGN_MIN_SIMILARITY and score[i][j] == score[i - 1][j - 1] + s:
            pairs.append((gs[i - 1], gt[j - 1]))
            i, j = i - 1, j - 1
        elif score[i][j] == score[i - 1][j]:
            i -= 1
        else:
            j -= 1
    return pairs[::-1]


def _similar(a: Func, b: Func, ratio: float = 0.75) -> bool:
    if a.hash == b.hash:
        return True
    small, big = sorted((a.size, b.size))
    if small == 0 or small / big < ratio:
        return False
    if a.strings and b.strings and not (a.strings & b.strings):
        return False
    return True


@dataclass
class PortResult:
    source: dict[int, Func]
    target: dict[int, Func]
    matches: dict[int, tuple[int, str]]  # target start -> (source start, method)
    extra: dict[int, str] = field(default_factory=dict)  # seed names the source does not have

    def name_of(self, target_start: int) -> str | None:
        m = self.matches.get(target_start)
        return self.source[m[0]].name if m else self.extra.get(target_start)


def port(source_elf, target_elf, source_map: str | None = None, min_size: int = 8,
         seeds: dict[int, str] | None = None) -> PortResult:
    """`seeds` maps target addresses to names known from elsewhere (SDK signature matches): those whose name
    exists once in the source are matched first, as anchors for the other passes."""
    src_ranges, tgt_ranges = code_ranges_of(source_elf), code_ranges_of(target_elf)
    if source_map:
        with open(source_map, newline="") as f:
            rows = list(csv.reader(f))[1:]
        names = {int(r[1], 0): r[0] for r in rows if len(r) >= 4}
    else:
        names = {s.addr: s.name for s in source_elf.function_symbols()}
    if not names:
        raise ValueError("the source has no function symbols (no .symtab, and no --source-map)")
    source = analyze(source_elf, list(names), src_ranges)
    for start, func in source.items():
        func.name = names[start]
    target = analyze(target_elf, discover_starts(target_elf, tgt_ranges), tgt_ranges)

    matches: dict[int, tuple[int, str]] = {}  # target -> (source, method)
    used: set[int] = set()  # matched source starts

    def accept(t: int, s: int, method: str) -> bool:
        if t in matches or s in used:
            return False
        matches[t] = (s, method)
        used.add(s)
        return True

    def unique_pairs(key) -> list[tuple[int, int]]:
        src, tgt = defaultdict(list), defaultdict(list)
        for f in source.values():
            if f.start not in used and (k := key(f)):
                src[k].append(f.start)
        for f in target.values():
            if f.start not in matches and (k := key(f)):
                tgt[k].append(f.start)
        return [(tgt[k][0], src[k][0]) for k in src.keys() & tgt.keys() if len(src[k]) == 1 and len(tgt[k]) == 1]

    if seeds:
        by_name = Counter(f.name for f in source.values())
        source_by_name = {f.name: f.start for f in source.values() if by_name[f.name] == 1}
        for t, name in seeds.items():
            if t in target and name in source_by_name:
                accept(t, source_by_name[name], "sdk")
    for t, s in unique_pairs(lambda f: f.hash if f.size >= min_size else None):
        accept(t, s, "exact")
    for t, s in unique_pairs(lambda f: f.strings if len(f.strings) >= 1 else None):
        if _similar(source[s], target[t], 0.5):
            accept(t, s, "strings")

    src_callers, tgt_callers = defaultdict(set), defaultdict(set)
    for f in source.values():
        for c in f.calls:
            src_callers[c].add(f.start)
    for f in target.values():
        for c in f.calls:
            tgt_callers[c].add(f.start)

    changed = True
    while changed:
        changed = False
        # callee: walk call lists of matched pairs in parallel.
        for t, (s, _) in list(matches.items()):
            sc, tc = source[s].calls, target[t].calls
            if len(sc) != len(tc):
                continue
            for cs, ct in zip(sc, tc):
                if cs in source and ct in target and _similar(source[cs], target[ct]) and accept(ct, cs, "callee"):
                    changed = True
        # caller: the single unmatched caller on both sides.
        for t, (s, _) in list(matches.items()):
            us = [c for c in src_callers[s] if c not in used and c in source]
            ut = [c for c in tgt_callers[t] if c not in matches and c in target]
            if len(us) == 1 and len(ut) == 1 and _similar(source[us[0]], target[ut[0]]) and accept(ut[0], us[0], "caller"):
                changed = True
        # order: fill gaps between consecutive anchors that keep the same order on both sides.
        anchors = _monotonic(sorted((s, t) for t, (s, _) in matches.items()))
        src_sorted, tgt_sorted = sorted(source), sorted(target)
        for (s0, t0), (s1, t1) in zip(anchors, anchors[1:]):
            gs = [a for a in src_sorted[bisect.bisect_right(src_sorted, s0):bisect.bisect_left(src_sorted, s1)] if a not in used]
            gt = [a for a in tgt_sorted[bisect.bisect_right(tgt_sorted, t0):bisect.bisect_left(tgt_sorted, t1)] if a not in matches]
            if not gs or not gt:
                continue
            if len(gs) == len(gt) and all(_similar(source[a], target[b], 0.7) for a, b in zip(gs, gt)):
                for a, b in zip(gs, gt):
                    changed |= accept(b, a, "order")
            elif len(gs) * len(gt) <= ALIGN_MAX_CELLS:
                for a, b in _align([source[a] for a in gs], [target[b] for b in gt]):
                    changed |= accept(b.start, a.start, "align")
    extra = {t: name for t, name in (seeds or {}).items() if t in target and t not in matches}
    return PortResult(source, target, matches, extra)


def _monotonic(pairs: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Longest chain of (source, target) pairs increasing on both sides (patience sorting on targets)."""
    tails, tails_idx, prev = [], [], [-1] * len(pairs)
    for i, (_, t) in enumerate(pairs):
        k = bisect.bisect_left(tails, t)
        if k == len(tails):
            tails.append(t)
            tails_idx.append(i)
        else:
            tails[k] = t
            tails_idx[k] = i
        prev[i] = tails_idx[k - 1] if k else -1
    out, i = [], tails_idx[-1] if tails_idx else -1
    while i >= 0:
        out.append(pairs[i])
        i = prev[i]
    return out[::-1]


def render_csv(result: PortResult, with_unmatched: bool = False) -> str:
    """The recompiler's function map format (name,start,end,size), plus the pass and the source address.
    ps2_recomp reads the first four columns (`ghidra_output` in the config)."""
    lines = ["name,start,end,size,method,source"]
    for t in sorted(result.target):
        f = result.target[t]
        if t in result.matches:
            s, method = result.matches[t]
            lines.append(f"{result.source[s].name},0x{f.start:08x},0x{f.end:08x},{f.size},{method},0x{s:08x}")
        elif t in result.extra:
            lines.append(f"{result.extra[t]},0x{f.start:08x},0x{f.end:08x},{f.size},sdk,")
        elif with_unmatched:
            lines.append(f"sub_{f.start:08X},0x{f.start:08x},0x{f.end:08x},{f.size},,")
    return "\n".join(lines) + "\n"


def render_summary(result: PortResult) -> str:
    methods = Counter(m for _, m in result.matches.values())
    named_bytes = sum(result.target[t].size for t in result.matches)
    total_bytes = sum(f.size for f in result.target.values()) or 1
    order = sorted(methods, key=METHOD_RANK.get)
    text = (f"source: {len(result.source)} named functions; target: {len(result.target)} functions found\n"
            f"ported {len(result.matches)} names ({100 * named_bytes / total_bytes:.1f}% of the target's code): "
            + ", ".join(f"{methods[m]} {m}" for m in order))
    if result.extra:
        extra_bytes = sum(result.target[t].size for t in result.extra)
        text += (f"\nplus {len(result.extra)} SDK names the source does not have "
                 f"({100 * (named_bytes + extra_bytes) / total_bytes:.1f}% of the code named in all)")
    return text
