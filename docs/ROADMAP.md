# Roadmap

What exists today is the analysis side. The runtime side lives in the PS2Recomp fork, because every game
recompiled with it shares it.

## Done

- `files` / `extract`: ISO, raw BIN (MODE1/MODE2), CUE, extracted folders.
- `scan`: network stack survey, Markdown/JSON report, game profile (servers to redirect, modules, DNAS, P2P).
- `iop-compat`: per-ordinal check of the disc's IOP modules against the fork's virtual IOP kernel.
- `sdk-symbols`: the fork's SCE signature database, from Python, filtered to network libraries.
- `port-symbols`: function names from a symbolized build to a stripped one, as a recompiler function map.

## Next, in the fork (`boubou666/PS2Recomp`)

1. **IOP kernel gaps** reported by `iop-compat` for network modules: `thmsgbx`, IOP-side `ioman` file calls
   (open/close/read/write/lseek/ioctl/dopen...), `modload` 16/26/27, `dmacman` 16/17, `cdvdman` 22/24.
2. **DEV9 + SMAP emulation** (`ps2xNet` or inside ps2xIOP): SPEED registers, SMAP EMAC3 + PHY over MDIO,
   TX/RX buffer descriptors and FIFOs, DMA channel 8, the DEV9 interrupt. PCSX2's DEV9 (GPLv3) is a reference.
3. **Host backend:** user-mode NAT (libslirp or a small one) with DHCP and a DNS that applies the profile's
   `[dns]` table; optional TAP/pcap bridge; a pcap writer for every frame.
4. **The fork's module manager** lists `dev9`, `netman` and `ps2ip` as built-in HLE keys: a failed physical
   load is reported as a success. Fine for games that only probe DEV9; misleading for SMAP, which needs its
   exports. Make the fallback visible or opt-in.

## Next, here

- **Network configuration generator:** write the memory card files netcnf expects (format to document from
  NETCNF.IRX), from a profile: DHCP, Ethernet, the DNS of the host backend.
- **Override recipes:** from `sdk-symbols` and `port-symbols` output, emit the TOML stubs and C++ override
  skeletons the fork's config takes (DNAS skip, certificate check bypass).
- **Dissectors:** Wireshark Lua for Medius/SCE-RT and DNAS, to read the pcaps of the host backend.
- **Porter:** recover starts after tail-call `j` without the false starts (about 44 true for 128 false today);
  read the target's function list from `ps2_analyzer` instead of discovering it.
- **More surveys:** SOCOM, Ratchet & Clank, an EA title, a GameSpy title, a Quazal title, to grow
  `knowledge.py` and the signature coverage of libinsck/libnet.
