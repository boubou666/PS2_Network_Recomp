"""Network stack survey of a PS2 disc: which IOP modules, SDK libraries, middleware, servers and
authentication a game uses, and what a recomp has to provide for its online mode."""
from __future__ import annotations

import re
from collections import defaultdict

from . import knowledge as kb
from .disc import boot_elf_path, system_cnf
from .elf import SHT_SYMTAB, ElfError, irx_info, parse_elf, romdir_entries

P2P_RE = re.compile(r"(?i)peer ?(?:2|to) ?peer|\bP2P\b|HostChange|host migration|NetHost")


def _serial(boot: str | None) -> str | None:
    m = re.match(r"([A-Z]{4})_(\d{3})\.(\d{2})", boot or "")
    return f"{m.group(1)}-{m.group(2)}{m.group(3)}" if m else None


def _module_entry(path: str, data: bytes, container: str | None = None) -> dict:
    info = irx_info(data)
    key, role = kb.module_role(info.name, path)
    return {
        "path": path,
        "container": container,
        "name": info.name,
        "version": info.version_text,
        "key": key,
        "layer": role.layer if role else None,
        "role": role.role if role else None,
        "hardware": role.hardware if role else "",
        "imports": [{"library": lib.name, "version": lib.version_text, "ordinals": lib.ordinals} for lib in info.imports],
        "exports": [{"library": lib.name, "version": lib.version_text, "count": len(lib.ordinals)} for lib in info.exports],
    }


def collect_modules(disc) -> tuple[list[dict], list[dict]]:
    """IRX files on the disc and modules inside IOPRP images."""
    modules, images = [], []
    for path in disc.files():
        if path.endswith(".IRX"):
            modules.append(_module_entry(path, disc.read(path)))
        elif path.endswith(".IMG"):
            data = disc.read(path)
            entries = romdir_entries(data)
            if not entries:
                continue
            names = []
            for name, blob in entries:
                if blob[:4] == b"\x7fELF":
                    entry = _module_entry(f"{path}:{name}", blob, container=path)
                    names.append(f"{name} ({entry['name'] or '?'} {entry['version']})")
                    modules.append(entry)
            images.append({"path": path, "modules": names})
    return modules, images


def survey_strings(elf) -> dict:
    """Middleware, SDK stamps, hosts, addresses and settings found in the executable's strings."""
    found = defaultdict(list)
    middleware: dict[str, dict] = {}
    for off, text in elf.strings(4):
        addr = elf.vaddr(off)
        where = f"0x{addr:08x}" if addr is not None else f"file+0x{off:x}"
        for m in kb.SDK_STAMP_RE.finditer(text):
            found["sdk"].append((m.group(1), m.group(2)))
        for mw in kb.MIDDLEWARE:
            for pattern in mw.patterns:
                m = re.search(pattern, text)
                if not m:
                    continue
                entry = middleware.setdefault(mw.name, {"kind": mw.kind, "notes": mw.notes, "versions": [], "evidence": []})
                if m.groups() and m.group(1) and m.group(1) not in entry["versions"]:
                    entry["versions"].append(m.group(1))
                if len(entry["evidence"]) < 6:
                    entry["evidence"].append(f"{where} {text[:100]}")
                break
        is_path = ":\\" in text or text.lower().startswith(("cdrom", "host", "mc0", "mc1", "rom0"))
        emails = kb.EMAIL_RE.findall(text)
        found["emails"] += [(e, where) for e in emails]
        for url in kb.URL_RE.findall(text):
            found["urls"].append((url, where))
        if not is_path:
            for m in kb.HOST_RE.finditer(text):
                host = m.group().lower()
                if kb.NOT_HOSTS.search(host) or any(host in e.lower() for e in emails):
                    continue
                found["hosts"].append((host, where))
        for m in kb.IPV4_RE.finditer(text):
            octets = tuple(int(x) for x in m.groups())
            if all(o <= 255 for o in octets) and octets != (0, 0, 0, 0):
                found["ips"].append((m.group(), where, kb.is_private_ip(octets)))
        for m in kb.SETTING_KEY_RE.finditer(text):
            found["settings"].append(m.group(1))
        if re.search(r"(?i)^(cdrom0|rom0|host0?):.*\.(irx|img)", text):
            found["loads"].append((text.split(";")[0], where))
        if P2P_RE.search(text) and len(found["p2p"]) < 6:
            found["p2p"].append(f"{where} {text[:100]}")

    def uniq(items, key=lambda x: x):
        seen, out = set(), []
        for item in items:
            if key(item) not in seen:
                seen.add(key(item))
                out.append(item)
        return out

    sdk = {}
    for lib, ver in found["sdk"]:
        sdk.setdefault(lib, f"{ver[0]}.{ver[1]}.{ver[2:]}")
    return {
        "sdk": [{"library": lib, "version": ver, "network": lib in kb.NET_SDK_LIBS,
                 "role": kb.NET_SDK_LIBS.get(lib, "")} for lib, ver in sorted(sdk.items())],
        "middleware": middleware,
        "hosts": [{"host": h, "at": w} for h, w in uniq(found["hosts"], key=lambda x: x[0])],
        "urls": [{"url": u, "at": w} for u, w in uniq(found["urls"], key=lambda x: x[0])],
        "emails": [{"email": e, "at": w} for e, w in uniq(found["emails"], key=lambda x: x[0])],
        "ips": [{"ip": ip, "at": w, "private": p} for ip, w, p in uniq(found["ips"], key=lambda x: x[0])],
        "settings": uniq(found["settings"]),
        "loads": [{"path": p, "at": w} for p, w in uniq(found["loads"], key=lambda x: x[0].upper())],
        "p2p": found["p2p"],
    }


def needs(report: dict) -> list[str]:
    """What a recomp has to provide for the online mode, derived from the survey."""
    keys = {m["key"] for m in report["modules"] if m["key"]}
    out = []
    if {"dev9", "inet_smap_driver"} <= keys:
        out.append("Ethernet adapter: emulate DEV9 + SMAP under the IOP so the disc's own DEV9/SMAP/INET modules run "
                   "(or replace the INET stack with HLE).")
    elif "dev9" in keys:
        out.append("DEV9 is loaded without SMAP: check whether it is only for the HDD.")
    if "inet_an986_driver" in keys:
        out.append("USB Ethernet (AN986): needs a USB host controller and the adapter emulated.")
    if "inet_pppoe_driver" in keys or "inet_ppp" in keys:
        out.append("PPP/PPPoE modules are present; DHCP over Ethernet is usually enough, PPPoE can stay unused.")
    if keys & {"net_configuration", "eznetcnf"}:
        out.append("Network configuration: the game reads a configuration file (memory card BWNETCNF or HDD); "
                   "provide one or synthesize what netcnf returns.")
    if keys & {"libnet", "iop_msif_rpc_interface"}:
        out.append("libnet over mSIF RPC: the EE talks to LIBNETB.IRX through MSIFRPC.IRX (IOP kernel needs thmsgbx).")
    mw = report["strings"]["middleware"]
    if "DNAS" in mw:
        out.append("DNAS: skip the authentication with a function override, or point it to a revival DNAS server.")
    for name, entry in mw.items():
        if name not in ("DNAS",) and entry.get("notes"):
            out.append(f"{name}: {entry['notes']}")
    public = [h["host"] for h in report["strings"]["hosts"]]
    if public:
        out.append("DNS overrides for the original servers: " + ", ".join(public[:8]) + (" ..." if len(public) > 8 else ""))
    if report["strings"]["p2p"]:
        out.append("Players host matches (peer to peer): the host needs inbound connectivity, so the NAT layer must "
                   "forward ports and the address the game reports may need fixing.")
    if keys & {"hdd", "atad", "pfs"}:
        out.append("HDD modules are present (optional for most games; some read the network configuration there).")
    return out


def scan_disc(disc, sdk_symbols: list[dict] | None = None) -> dict:
    cnf = system_cnf(disc)
    boot = boot_elf_path(disc)
    modules, images = collect_modules(disc)
    report = {
        "disc": {"volume_id": getattr(disc, "volume_id", ""), "serial": _serial(boot), "boot": boot,
                 "vmode": cnf.get("VMODE"), "version": cnf.get("VER"), "files": len(disc.files())},
        "modules": modules,
        "iop_images": images,
        "executable": None,
        "strings": {"sdk": [], "middleware": {}, "hosts": [], "urls": [], "emails": [], "ips": [], "settings": [],
                    "loads": [], "p2p": []},
        "sdk_symbols": sdk_symbols,
    }
    if boot and boot in disc.files():
        try:
            elf = parse_elf(disc.read(boot))
            report["executable"] = {
                "entry": f"0x{elf.entry:08x}",
                "text_size": sum(s.size for s in elf.code_sections()),
                "symbols": len(elf.function_symbols()),
                "stripped": not any(s.type == SHT_SYMTAB for s in elf.sections),
            }
            report["strings"] = survey_strings(elf)
        except ElfError as exc:
            report["executable"] = {"error": str(exc)}
    report["needs"] = needs(report)
    report["online"] = bool(
        {m["key"] for m in modules} & {"inet_service", "inet_smap_driver", "netman", "ps2ip", "inet_an986_driver"}
        or any(lib["network"] for lib in report["strings"]["sdk"]))
    return report


# --- output ----------------------------------------------------------------------------------------------------


def render_markdown(r: dict) -> str:
    d, s, x = r["disc"], r["strings"], r["executable"] or {}
    lines = [f"# Network survey: {d['serial'] or d['volume_id']}", ""]
    lines += ["| | |", "|---|---|",
              f"| Volume | {d['volume_id']} |",
              f"| Boot executable | `{d['boot']}` |",
              f"| Video mode | {d['vmode'] or '?'} |"]
    if x and "error" not in x:
        symbols = "stripped" if x["stripped"] else "{:,} function symbols".format(x["symbols"])
        lines.append(f"| Executable | entry {x['entry']}, {x['text_size']:,} bytes of code, {symbols} |")
    lines.append(f"| Online stack | {'yes' if r['online'] else 'none found'} |")

    lines += ["", "## What the online mode needs", ""]
    lines += [f"- {n}" for n in r["needs"]] or ["- Nothing: no network stack found."]

    net_modules = [m for m in r["modules"] if m["layer"]]
    if net_modules:
        lines += ["", "## Network and DEV9 modules", "", "| File | Module | Version | Role | Imports |", "|---|---|---|---|---|"]
        for m in net_modules:
            imports = ", ".join(i["library"] for i in m["imports"])
            lines.append(f"| `{m['path']}` | {m['name'] or '?'} | {m['version']} | {m['role']} | {imports} |")
    other = [m for m in r["modules"] if m not in net_modules and not m["container"]]
    if other:
        lines += ["", "Other IOP modules: " + ", ".join(f"`{m['path']}` ({m['name'] or '?'} {m['version']})" for m in other)]
    for img in r["iop_images"]:
        lines += ["", f"IOPRP image `{img['path']}`: " + ", ".join(img["modules"])]

    if s["sdk"]:
        lines += ["", "## EE SDK libraries", ""]
        lines.append(", ".join(f"**{l['library']} {l['version']}**" if l["network"] else f"{l['library']} {l['version']}"
                               for l in s["sdk"]))
    if s["middleware"]:
        lines += ["", "## Middleware and authentication", ""]
        for name, mw in s["middleware"].items():
            ver = f" {', '.join(mw['versions'])}" if mw["versions"] else ""
            lines.append(f"- **{name}**{ver} ({mw['kind']})")
            lines += [f"  - `{e}`" for e in mw["evidence"][:3]]
    if s["hosts"] or s["urls"] or s["ips"]:
        lines += ["", "## Servers and addresses", ""]
        lines += [f"- `{h['host']}` at {h['at']}" for h in s["hosts"]]
        lines += [f"- `{u['url']}` at {u['at']}" for u in s["urls"]]
        lines += [f"- `{i['ip']}` at {i['at']}{' (private: dev or LAN)' if i['private'] else ''}" for i in s["ips"]]
    if s["settings"]:
        lines += ["", "Settings keys that look like server configuration: " + ", ".join(f"`[{k}]`" for k in s["settings"])]
    if s["p2p"]:
        lines += ["", "Peer-to-peer hints: " + "; ".join(f"`{p}`" for p in s["p2p"][:4])]
    if s["loads"]:
        lines += ["", "Modules the executable loads: " + ", ".join(f"`{l['path']}`" for l in s["loads"])]
    if r.get("sdk_symbols"):
        lines += ["", "## Network SDK functions (signature matches)", "", "| Address | Function | Library |", "|---|---|---|"]
        lines += [f"| 0x{f['address']:08x} | `{f['name']}` | {f['library']} |" for f in r["sdk_symbols"]]
    return "\n".join(lines) + "\n"


def _toml_str(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def render_profile(r: dict) -> str:
    """A starting game profile: servers to redirect, modules, auth. Contains no game data, only names."""
    d, s = r["disc"], r["strings"]
    keys = [m["key"] for m in r["modules"] if m["key"]]
    lines = ["# ps2net game profile, generated by `ps2net scan --profile`. Edit freely.", "",
             "[game]", f"serial = {_toml_str(d['serial'] or '')}", f"boot = {_toml_str(d['boot'] or '')}",
             f"volume_id = {_toml_str(d['volume_id'] or '')}", "",
             "[network]", f"online = {'true' if r['online'] else 'false'}",
             f"adapter = {_toml_str('smap' if 'inet_smap_driver' in keys else 'an986' if 'inet_an986_driver' in keys else '')}",
             "stack_modules = [" + ", ".join(_toml_str(m["path"]) for m in r["modules"] if m["layer"] in ("hardware", "driver", "stack", "config", "rpc")) + "]",
             "middleware = [" + ", ".join(_toml_str(f"{n} {' '.join(mw['versions'])}".strip()) for n, mw in s["middleware"].items() if n != "DNAS") + "]",
             f"dnas = {'true' if 'DNAS' in s['middleware'] else 'false'}",
             f"peer_to_peer = {'true' if s['p2p'] else 'false'}", "",
             "[dns]", "# Original server = replacement host or IP. Empty keeps the original."]
    lines += [f"{_toml_str(h['host'])} = \"\"" for h in s["hosts"]]
    if r.get("sdk_symbols"):
        lines += ["", "[sdk_functions]", "# Network SDK functions found by signature: candidates for overrides."]
        lines += [f"{_toml_str(f['name'])} = 0x{f['address']:08x}" for f in r["sdk_symbols"]]
    return "\n".join(lines) + "\n"
