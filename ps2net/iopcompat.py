"""Check a disc's IOP modules against what the PS2Recomp fork's virtual IOP kernel provides.

The fork runs IRX modules on an R3000A interpreter. Kernel libraries (thbase, sysclib, intrman...) are
implemented in C++ and dispatched per ordinal in ps2xIOP/src/emulator/iop_emulator.cpp; libraries exported by
other IRX modules are linked to the guest code. This module reads those sources to learn which ordinals are
handled (from the `case N: // Name` labels of each dispatch function) and reports, per module, every import
that would end up as "[IOP] unhandled import".

Reading C++ with regexes is approximate: a dispatch function that handles ordinals without `case` labels shows
as "provided, ordinals not listed".
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from . import knowledge as kb


@dataclass
class ForkIop:
    root: Path
    handled: dict[str, dict[int, str]] = field(default_factory=dict)  # library -> {ordinal: name}
    unlisted: set[str] = field(default_factory=set)  # provided, but no ordinals could be read
    builtin_hle: set[str] = field(default_factory=set)  # module keys the module manager can fake


TOKEN_RE = re.compile(r"//[^\n]*|/\*.*?\*/|\"(?:\\.|[^\"\\\n])*\"|'(?:\\.|[^'\\\n])*'", re.S)


def _body(code: str, start: int) -> str:
    """The brace-delimited block that opens at or after `start`, comments kept. Braces inside comments and
    literals do not count; both are blanked in one pass so an apostrophe in a comment is not a char literal."""
    clean = TOKEN_RE.sub(lambda m: " " * len(m.group()), code)
    open_at = clean.find("{", start)
    if open_at < 0:
        return ""
    depth = 0
    for i in range(open_at, len(clean)):
        if clean[i] == "{":
            depth += 1
        elif clean[i] == "}":
            depth -= 1
            if depth == 0:
                return code[open_at:i + 1]
    return code[open_at:]


CASE_RE = re.compile(r"case\s+(\d+)u?\s*:[ \t]*(?://[ \t]*([^\n]*))?")
ORDINAL_EQ_RE = re.compile(r"ordinal\s*==\s*(\d+)u?")


def _ordinals(block: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for m in CASE_RE.finditer(block):
        name = (m.group(2) or "").strip()
        name = re.split(r"[\s,:;(.]", name, maxsplit=1)[0] if name else ""
        out.setdefault(int(m.group(1)), name)
    for m in ORDINAL_EQ_RE.finditer(block):
        out.setdefault(int(m.group(1)), "")
    return out


def load_fork(root: str | Path) -> ForkIop:
    root = Path(root)
    iop = root / "ps2xIOP" / "src"
    emulator_cpp = iop / "emulator" / "iop_emulator.cpp"
    if not emulator_cpp.exists():
        raise FileNotFoundError(f"{emulator_cpp} not found: --fork must point at a PS2Recomp checkout")
    sources = {p: p.read_text(encoding="utf-8", errors="replace") for p in iop.rglob("*.cpp")}
    headers = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in iop.rglob("*.h"))
    emulator = sources[emulator_cpp]
    fork = ForkIop(root)

    def definition(func: str, var: str | None) -> str:
        """Body of `Class::func`, picking the class from the member variable's declaration when needed."""
        candidates = []
        for text in sources.values():
            for m in re.finditer(r"\b(\w+)::" + re.escape(func) + r"\s*\(", text):
                candidates.append((m.group(1), text, m.end()))
        if var and len(candidates) > 1:
            decl = re.search(r"\b(\w+)\s+" + re.escape(var) + r"\s*[;{(=]", emulator + headers)
            if decl:
                candidates = [c for c in candidates if c[0] == decl.group(1)] or candidates
        if not candidates:
            # A member function of the emulator itself, defined inline.
            m = re.search(r"\b(?:bool|void|int|uint32_t)\s+" + re.escape(func) + r"\s*\([^;{]*\)\s*\{", emulator)
            return _body(emulator, m.end() - 1) if m else ""
        _, text, pos = candidates[0]
        body = _body(text, pos)
        if re.search(r"m_impl->" + re.escape(func) + r"\s*\(", body):
            # pimpl forwarder: the real switch is in the Impl's inline member of the same name.
            inline = re.search(r"(?<!::)\b(?:bool|void|int|uint32_t)\s+" + re.escape(func) + r"\s*\([^;{]*\)\s*\{", text)
            if inline:
                body = _body(text, inline.end() - 1)
        return body

    marks = [(m.start(), m.group(1).lower()) for m in re.finditer(r'iequals\(call\.library,\s*"(\w+)"\)', emulator)]
    end_of_chain = emulator.find("imports.resolve(")
    for i, (pos, lib) in enumerate(marks):
        nxt = marks[i + 1][0] if i + 1 < len(marks) else end_of_chain
        chunk = emulator[pos:nxt if nxt > pos else pos + 2000]
        # Several libraries can share one chunk (`thbase || threadman`): the dispatch belongs to all of them.
        ordinals: dict[int, str] = {}
        dispatched = False
        for m in re.finditer(r"(?:\b(\w+)\.)?(dispatch\w*)\s*\(", chunk):
            dispatched = True
            ordinals.update(_ordinals(definition(m.group(2), m.group(1))))
        condition = chunk.split("\n", 1)[0]
        inline = _ordinals(chunk if not dispatched else condition)
        if not dispatched and not inline:
            continue
        ordinals.update(inline)
        lib = {"threadman": "thbase"}.get(lib, lib)
        entry = fork.handled.setdefault(lib, {})
        for ordinal, name in ordinals.items():
            if name or ordinal not in entry:
                entry[ordinal] = name
        if not entry:
            fork.unlisted.add(lib)
    for lib, entry in fork.handled.items():
        if entry:
            fork.unlisted.discard(lib)

    manager = iop / "iop_module_manager.cpp"
    if manager.exists():
        block = _body(manager.read_text(encoding="utf-8", errors="replace"),
                      manager.read_text(encoding="utf-8", errors="replace").find("modules[]"))
        fork.builtin_hle = set(re.findall(r'"(\w+)"', block))
    return fork


@dataclass
class ImportCheck:
    library: str
    version: str
    ordinals: list[int]
    provider: str  # "fork", "module:<path>", "missing"
    missing: list[int] = field(default_factory=list)
    names: dict[int, str] = field(default_factory=dict)
    note: str = ""


def check(modules: list[dict], fork_root: str | Path, include_all: bool = False) -> dict:
    fork = load_fork(fork_root)
    exporters: dict[str, list[tuple[str, str]]] = {}
    for m in modules:
        if m["container"]:
            continue  # IOPRP images replace kernel modules the fork provides itself
        for e in m["exports"]:
            exporters.setdefault(e["library"], []).append((m["path"], e["version"]))

    results = []
    for m in modules:
        if m["container"] or (not include_all and m["layer"] is None):
            continue
        checks = []
        for imp in m["imports"]:
            lib = imp["library"]
            ordinals = sorted(set(imp["ordinals"]))
            if lib in exporters:
                path, version = exporters[lib][0]
                note = ""
                if version.split(".")[0] != imp["version"].split(".")[0]:
                    note = f"export version {version} vs import {imp['version']}: loadcore wants the same major"
                checks.append(ImportCheck(lib, imp["version"], ordinals, f"module:{path}", note=note))
            elif lib in fork.handled or lib in fork.unlisted:
                handled = fork.handled.get(lib, {})
                missing = [o for o in ordinals if o not in handled] if handled else []
                note = "ordinals not listed in the fork's source; check by running" if lib in fork.unlisted else ""
                checks.append(ImportCheck(lib, imp["version"], ordinals, "fork", missing, handled, note))
            else:
                checks.append(ImportCheck(lib, imp["version"], ordinals, "missing", ordinals))
        key = (m["key"] or "").lower()
        stem = m["path"].rsplit("/", 1)[-1].split(".")[0].lower()
        results.append({
            "module": m,
            "imports": checks,
            "hle_fallback": stem in fork.builtin_hle or key in fork.builtin_hle,
        })
    return {"fork": fork, "results": results}


def render_markdown(report: dict) -> str:
    fork: ForkIop = report["fork"]
    lines = ["# IOP compatibility", "",
             f"Fork: `{fork.root}`. Kernel libraries it implements: "
             + ", ".join(f"{lib} ({len(o)})" if o else lib for lib, o in sorted(fork.handled.items())), ""]
    missing_libs: dict[str, set[str]] = {}
    gaps: dict[str, set[int]] = {}
    hardware = []
    for r in report["results"]:
        m = r["module"]
        bad = [c for c in r["imports"] if c.provider == "missing" or c.missing or c.note]
        status = "ok" if not bad else "needs work"
        lines.append(f"## `{m['path']}`: {m['name'] or '?'} {m['version']} ({status})")
        if m["role"]:
            lines.append(f"{m['role']}.")
        if m["hardware"]:
            lines.append(f"Hardware it drives: {m['hardware']}.")
            hardware.append(f"`{m['path']}`: {m['hardware']}")
        if r["hle_fallback"]:
            lines.append("The fork's module manager lists this module as a built-in HLE key: if the real module fails to "
                         "start, the load is reported as a success and nothing provides its exports.")
        lines += ["", "| Library | Version | Provided by | Ordinals used | Not handled |", "|---|---|---|---|---|"]
        for c in r["imports"]:
            provider = c.provider.replace("module:", "disc `") + ("`" if c.provider.startswith("module:") else "")
            if c.provider == "missing":
                provider = "**nothing**"
                missing_libs.setdefault(c.library, set()).add(m["path"])
            used = ", ".join(f"{o} {c.names[o]}".strip() if c.names.get(o) else str(o) for o in c.ordinals)
            not_handled = ", ".join(str(o) for o in c.missing) if c.provider == "fork" else ("all" if c.provider == "missing" else "")
            if c.provider == "fork" and c.missing:
                gaps.setdefault(c.library, set()).update(c.missing)
            if c.note:
                not_handled = (not_handled + " " if not_handled else "") + f"({c.note})"
            lines.append(f"| {c.library} | {c.version} | {provider} | {used} | {not_handled} |")
        lines.append("")
    lines += ["## Summary", ""]
    if missing_libs:
        lines += [f"- Library **{lib}** is not implemented, needed by " + ", ".join(f"`{p}`" for p in sorted(paths))
                  for lib, paths in sorted(missing_libs.items())]
    if gaps:
        lines += [f"- **{lib}** ordinals to add: " + ", ".join(str(o) for o in sorted(ords)) for lib, ords in sorted(gaps.items())]
    if hardware:
        lines += [f"- Hardware: {h}" for h in hardware]
    if not (missing_libs or gaps or hardware):
        lines.append("- Every import is provided.")
    return "\n".join(lines) + "\n"
