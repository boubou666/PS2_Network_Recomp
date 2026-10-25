<div align="center">

# PS2 Network Recomp

**Tooling for recompiling the online features of PlayStation 2 games with [PS2Recomp](https://github.com/boubou666/PS2Recomp).**<br>
Find out what a game's network stack is made of, what the recompiler's runtime is missing to run it, and name
the functions you will need to override in a stripped executable.

![Python](https://img.shields.io/badge/python-3.10%2B-1b8cff)
![Dependencies](https://img.shields.io/badge/dependencies-none-17a35b)
![Status](https://img.shields.io/badge/status-analysis%20tools-d0a01f)

</div>

> [!IMPORTANT]
> No game data is included or ever committed: no disc images, executables, modules or anything extracted from
> them. Every tool reads **your own** disc. `.gitignore` excludes images and the `out/` folder.

## What it does

| Command | Answers |
|---|---|
| `ps2net scan <disc>` | Which network modules, SDK libraries, middleware (Medius, GameSpy, DirtySock...), DNAS, servers and peer-to-peer hosting a game uses, and what its online mode needs from a recomp. Writes a report and a game profile. |
| `ps2net iop-compat <disc> --fork <PS2Recomp>` | For each IOP module on the disc, every import the fork's virtual IOP kernel does not handle yet, per function, and the hardware the module drives. |
| `ps2net sdk-symbols <elf> --fork <PS2Recomp>` | The SCE SDK functions in a stripped executable (network libraries by default), using the fork's own signature database. |
| `ps2net port-symbols <with-symbols.elf> <stripped.elf>` | Names for a stripped executable, carried over from a build of the same engine that kept its symbols. Output is the recompiler's function map. |
| `ps2net files` / `extract` | List or extract files from an ISO, a raw BIN/CUE (MODE1 or MODE2) or a folder. |

## Install

Python 3.10 or newer, nothing else.

```bash
pip install -e .
```

Or run without installing: `python -m ps2net ...` from the repository root.

## Examples

Survey a disc and write a profile:

```bash
ps2net scan "Twisted Metal - Black Online (Europe).cue" -o out/scan.md --profile out/profile.toml --fork ../PS2Recomp
```

```text
## What the online mode needs
- Ethernet adapter: emulate DEV9 + SMAP under the IOP so the disc's own DEV9/SMAP/INET modules run ...
- libnet over mSIF RPC: the EE talks to LIBNETB.IRX through MSIFRPC.IRX (IOP kernel needs thmsgbx).
- DNAS: skip the authentication with a function override, or point it to a revival DNAS server.
- DNS overrides for the original servers: tmbonline.scea.com, tmbol-master.online.scee.com
- Players host matches (peer to peer): the host needs inbound connectivity ...
```

Check the disc's IOP modules against the fork:

```bash
ps2net iop-compat "Twisted Metal - Black Online (Europe).cue" --fork ../PS2Recomp -o out/iop.md
```

```text
- Library **thmsgbx** is not implemented, needed by `NET/MSIFRPC.IRX`
- **ioman** ordinals to add: 4, 5, 6, 7, 8, 10, 11, 12, 13, 14, 15, 16, 25, 27, 31, 34
- Hardware: `NET/SMAP.IRX`: SMAP: EMAC3 MAC, PHY over MDIO, TX/RX buffer descriptors and FIFOs
```

Name a stripped executable from a symbolized build of the same engine, with SDK signatures as anchors, and give
the result to the recompiler:

```bash
ps2net extract "Twisted Metal - Black Online (Europe).cue" out/tmbo --only SCES_514.80
ps2net port-symbols TMB_Recomp/game/SCES_503.60 out/tmbo/SCES_514.80 --fork ../PS2Recomp -o out/tmbo_functions.csv
```

```text
source: 3571 named functions; target: 7592 functions found
ported 2624 names (42.3% of the target's code): 459 sdk, 392 exact, 65 strings, 221 callee, 235 caller, 547 align, 705 order
plus 611 SDK names the source does not have (50.3% of the code named in all)
```

In the recompiler config:

```toml
[general]
ghidra_output = "out/tmbo_functions.csv"   # name,start,end,size (extra columns are ignored)
```

## How reliable the names are

`port-symbols` records the pass that found each name (`method` column):

| Pass | How | Checked on |
|---|---|---|
| `sdk` | The fork's signature database | Exact by construction |
| `exact` | Same instructions once addresses are masked, unique on both sides | 309/309 agree with SDK signatures on TMBO |
| `strings` | Same set of referenced strings, unique on both sides | 29/29 |
| `callee` | n-th call of two matched functions | 30/30 |
| `caller` | Only unmatched caller of two matched functions | 10/12 |
| `align` | Gap between matched functions aligned by instruction-shape similarity | 4/5 |
| `order` | Same number of functions between matched ones, similar sizes | 21/21 |

Porting Twisted Metal: Black onto itself, with its symbols hidden, gets 98.6% of the code named with 18 wrong
names out of 3,419 (0.5%), mostly where a function start was not found and two functions merged.

## How it fits with PS2Recomp

```
disc ──► ps2net scan ──► report + profile (servers, modules, DNAS, P2P)
     └─► ps2net iop-compat --fork ──► what ps2xIOP lacks for the network modules
ELF  ──► ps2net sdk-symbols / port-symbols ──► function map CSV ──► ps2_recomp (ghidra_output)
                                                              └──► names for overrides (DNAS, certificates)
```

The runtime side (DEV9/SMAP emulation, the host network backend) belongs in the fork, shared by every game;
see [docs/ROADMAP.md](docs/ROADMAP.md). [docs/NETWORK_STACK.md](docs/NETWORK_STACK.md) describes the layers and
where a recomp can cut them.

## Repository layout

| Path | Contents |
|---|---|
| `ps2net/disc.py` | ISO9660 from ISO, BIN (MODE1/MODE2), CUE, folders |
| `ps2net/elf.py` | ELF32, symbols, IRX module info and import/export tables, IOPRP (ROMDIR) images |
| `ps2net/knowledge.py` | What the analyzer recognizes: modules, SDK libraries, middleware, hostnames |
| `ps2net/scan.py` | The survey and its Markdown/JSON/profile output |
| `ps2net/iopcompat.py` | Reads the fork's ps2xIOP sources to know which imports are handled |
| `ps2net/sdksyms.py` | The fork's SCE signature database, in Python |
| `ps2net/porter.py` | Function discovery, fingerprints and the matching passes |
| `docs/` | Network stack notes, roadmap, surveys of discs |
| `profiles/` | Game profiles (names and hostnames only) |
| `tests/` | Unit tests on synthetic discs and ELFs (`python -m unittest discover -s tests -t .`) |

## Credits

- [PS2Recomp](https://github.com/ran-j/PS2Recomp) by ran-j and contributors, and its SCE symbol database from
  sce-symbol-scanner, which `sdk-symbols` reads from your checkout of the fork.
- Unofficial fan tooling, not affiliated with or endorsed by Sony Interactive Entertainment.
