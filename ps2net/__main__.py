"""Command line: python -m ps2net <command> ..."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__


def _write(text: str, out: str | None) -> None:
    if out:
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text(text, encoding="utf-8")
        print(f"wrote {out}", file=sys.stderr)
    else:
        sys.stdout.write(text)


def cmd_files(args) -> None:
    from .disc import open_disc
    disc = open_disc(args.disc)
    for path, size in disc.files().items():
        print(f"{size:12,d}  {path}")


def cmd_extract(args) -> None:
    from .disc import extract, open_disc
    written = extract(open_disc(args.disc), Path(args.out), args.only)
    print(f"extracted {len(written)} files to {args.out}", file=sys.stderr)


def cmd_scan(args) -> None:
    from .disc import boot_elf_path, open_disc
    from .scan import render_markdown, render_profile, scan_disc
    disc = open_disc(args.disc)
    sdk = None
    if args.fork:
        from .elf import parse_elf
        from .sdksyms import load_database, network_only, scan_elf
        boot = boot_elf_path(disc)
        if boot:
            sdk = network_only(scan_elf(parse_elf(disc.read(boot)), load_database(args.fork)))
    report = scan_disc(disc, sdk)
    if args.profile:
        _write(render_profile(report), args.profile)
    _write(json.dumps(report, indent=2) + "\n" if args.json else render_markdown(report), args.out)


def cmd_iop_compat(args) -> None:
    from .disc import open_disc
    from .iopcompat import check, render_markdown
    from .scan import collect_modules
    modules, _ = collect_modules(open_disc(args.disc))
    _write(render_markdown(check(modules, args.fork, args.all)), args.out)


def cmd_sdk_symbols(args) -> None:
    from .elf import parse_elf
    from .sdksyms import load_database, network_only, scan_elf
    matches = scan_elf(parse_elf(Path(args.elf).read_bytes()), load_database(args.fork))
    if not args.all:
        matches = network_only(matches)
    lines = ["name,start,end,size,library"]
    lines += [f"{m['name']},0x{m['address']:08x},0x{m['address'] + m['size']:08x},{m['size']},{m['library']}" for m in matches]
    _write("\n".join(lines) + "\n", args.out)
    print(f"{len(matches)} functions", file=sys.stderr)


def cmd_port_symbols(args) -> None:
    from .elf import parse_elf
    from .porter import port, render_csv, render_summary
    source = parse_elf(Path(args.source).read_bytes())
    target = parse_elf(Path(args.target).read_bytes())
    seeds = None
    if args.fork:
        from .sdksyms import load_database, scan_elf
        seeds = {m["address"]: m["name"] for m in scan_elf(target, load_database(args.fork))}
    result = port(source, target, source_map=args.source_map, min_size=args.min_size, seeds=seeds)
    _write(render_csv(result, args.with_unmatched), args.out)
    print(render_summary(result), file=sys.stderr)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="ps2net", description="Tooling for recompiling PS2 online games.")
    parser.add_argument("--version", action="version", version=f"ps2net {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("files", help="list the files on a disc (ISO, BIN/CUE or folder)")
    p.add_argument("disc")
    p.set_defaults(func=cmd_files)

    p = sub.add_parser("extract", help="extract files from a disc")
    p.add_argument("disc")
    p.add_argument("out")
    p.add_argument("--only", nargs="*", help="path fragments to keep, e.g. NET/ .IRX SYSTEM.CNF")
    p.set_defaults(func=cmd_extract)

    p = sub.add_parser("scan", help="survey a disc's network stack and write a report")
    p.add_argument("disc")
    p.add_argument("-o", "--out", help="report file (default: stdout)")
    p.add_argument("--json", action="store_true", help="JSON instead of Markdown")
    p.add_argument("--profile", help="also write a game profile (TOML) to this file")
    p.add_argument("--fork", help="PS2Recomp checkout: adds network SDK functions found by its signature database")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("iop-compat", help="check the disc's IOP modules against the fork's virtual IOP kernel")
    p.add_argument("disc")
    p.add_argument("--fork", required=True, help="PS2Recomp checkout")
    p.add_argument("--all", action="store_true", help="every module, not only the network ones")
    p.add_argument("-o", "--out")
    p.set_defaults(func=cmd_iop_compat)

    p = sub.add_parser("sdk-symbols", help="name SCE SDK functions in a stripped ELF with the fork's signature database")
    p.add_argument("elf")
    p.add_argument("--fork", required=True, help="PS2Recomp checkout")
    p.add_argument("--all", action="store_true", help="every library, not only the network ones")
    p.add_argument("-o", "--out", help="CSV in the recompiler's function map format (default: stdout)")
    p.set_defaults(func=cmd_sdk_symbols)

    p = sub.add_parser("port-symbols", help="carry function names from an ELF with symbols to a stripped build of the same engine")
    p.add_argument("source", help="ELF with a symbol table")
    p.add_argument("target", help="stripped ELF")
    p.add_argument("--source-map", help="names for the source from a function map CSV (name,start,end,size) instead of .symtab")
    p.add_argument("--min-size", type=int, default=8, help="smallest function, in bytes, matched on its own (default 8)")
    p.add_argument("--with-unmatched", action="store_true", help="also list target functions left unnamed")
    p.add_argument("--fork", help="PS2Recomp checkout: SDK functions it recognizes in the target become anchors")
    p.add_argument("-o", "--out", help="CSV in the recompiler's function map format (default: stdout)")
    p.set_defaults(func=cmd_port_symbols)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
