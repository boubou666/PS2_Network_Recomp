# The PS2 network stack, as a recomp sees it

What an online PS2 game is made of, layer by layer, and where a static recompilation (PS2Recomp) can cut it.
`ps2net scan` reports each of these layers for a disc.

```
EE (recompiled to C++)
  game code
    middleware        Medius + SCE-RT/DME, GameSpy, EA DirtySock/ProtoSSL, Quazal, PlayOnline...
    auth              DNAS (libdnas / libdnas2, on top of libhttps' SSL)
    SDK network libs  libinsck + netglue (sockets), libnet + libmrpc (sceInet* over mSIF RPC),
                      libeenet (TCP/IP on the EE), netcnfif / ezNetCnf client
        │ SIF RPC
IOP (the fork runs the disc's own IRX on an R3000A interpreter)
    RPC servers       LIBNETB.IRX + MSIFRPC.IRX (libnet), INSOCK (libinsck), EZNETCNF/EZNETCTL
    TCP/IP            INET.IRX (SCE INET), INETCTL.IRX (interfaces, events), INETLOG.IRX
    configuration     NETCNF.IRX: reads the "Your Network Configuration" files (memory card BWNETCNF, HDD)
    link              SMAP.IRX (Ethernet), PPP.IRX / PPPOE.IRX, AN986 (USB Ethernet)
    bus               DEV9.IRX (expansion bay: SPEED chip, power, interrupts)
        │
hardware              SPEED + SMAP (EMAC3 MAC, PHY) on the network adapter, DMA channel 8, IOP interrupt
```

## Where to cut

| Cut | What the recomp provides | For | Against |
|---|---|---|---|
| Hardware | DEV9/SPEED + SMAP emulation in ps2xIOP, a host network backend (user-mode NAT with DHCP and DNS, or TAP) | Every SCE INET game works the same way; the game's traffic is byte-identical to a real PS2 or PCSX2 player, so revival servers just work; pcap of every frame | IOP-side work: SMAP registers, buffer descriptors, PHY, interrupts; IOP kernel gaps (see `ps2net iop-compat`) |
| IOP RPC | Host implementations of the INET/libnet/ezNetCnf RPC servers | No IOP network modules to run | RPC formats change with the SDK version; mSIF RPC is its own protocol |
| EE functions | Overrides of `sceInsock*`, `sceInet*` or the middleware's own functions | Very flexible; the right place for DNAS and certificate checks | Needs names in stripped executables (`sdk-symbols`, `port-symbols`); per library version |

**Recommended for the PS2Recomp fork:** cut at the hardware for transport, so the disc's own modules run, and
use EE function overrides only for what must change: DNAS, certificate checks, server addresses that DNS
cannot redirect.

## Pieces a recomp has to handle, whatever the cut

- **Network configuration.** NETCNF reads a configuration file from the memory card (`BWNETCNF`) or the HDD.
  Without one, ezNetCtl has nothing to bring up. Either provide a valid file or answer netcnf's requests.
- **DNAS.** The official DNAS servers are gone. A recomp skips the check (override the DNAS state machine with
  names from `sdk-symbols`/`port-symbols`) or points the DNAS hostnames to a revival DNAS server.
- **Servers.** Hostnames are compiled in (`ps2net scan` lists them). DNS overrides in the host backend redirect
  them to revival servers without touching code; some games also keep server settings in a save file.
- **IOP reboot images.** Many online games reboot the IOP with an IOPRP image (`DNAS243.IMG`, `IOPRP2xx.IMG`):
  kernel modules of a given SDK version, which the fork's HLE kernel stands in for.
- **Peer-to-peer matches.** When a player hosts, other players connect to them: behind the NAT the host
  needs forwarded ports, and the address the game reports to the lobby server may need rewriting.

## Notes from Twisted Metal: Black Online (SCES-51480)

The first disc surveyed; the full report is in [surveys/SCES-51480.md](surveys/SCES-51480.md).

- SCE INET 1.50 over SMAP 1.65 on DEV9 2.02; PPP/PPPoE present but DHCP over Ethernet is the normal path.
- The EE uses libnet (`LIBNETB.IRX` through `MSIFRPC.IRX`), libinsck 2.4.30 and ezNetCnf/ezNetCtl 1.08.
- Medius client 1.40.PRE8, Medius Game Communication Library 1.40.0004, rt_msg_client 1.06.0063.
- DNAS2 with libhttps (the SSL library is 478 of the 1,108 SDK functions the signature database recognizes).
- Servers: `tmbol-master.online.scee.com` (Europe), `tmbonline.scea.com`; dev addresses `10.0.0.x`.
- Matches are hosted by a player (peer to peer, host migration).
- The executable is stripped; the offline Twisted Metal: Black (SCES-50360) has symbols, and `port-symbols`
  carries 72% of its function names over (42% of TMBO's code, 50% with the SDK signatures).
- IOP gaps in the fork today: no `thmsgbx` (MSIFRPC), no IOP-side `ioman` file calls (NETCNF opens files),
  a few `modload`, `dmacman` and `cdvdman` ordinals, and no DEV9/SMAP hardware.
