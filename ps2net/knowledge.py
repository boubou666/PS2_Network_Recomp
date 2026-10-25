"""What the analyzer knows about PS2 network stacks: IOP modules, EE SDK libraries, middleware and auth.

Entries are matched against module names (.iopmod), file names and strings in the executable. Add to these
tables as new games are surveyed; docs/NETWORK_STACK.md explains the layers.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ModuleRole:
    layer: str  # hardware, driver, stack, config, rpc, auth, storage
    role: str
    hardware: str = ""  # what a recomp must emulate (or replace) for the module to run


# Keyed by .iopmod module name (lower case); FILE_KEYS maps file names for modules without .iopmod.
IOP_MODULES: dict[str, ModuleRole] = {
    "dev9": ModuleRole("hardware", "DEV9 expansion bay driver (SPEED chip, power, interrupts)",
                       "DEV9/SPEED registers at 0x10000000 (IOP 0xB0000000), DEV9 interrupt, DMA channel 8"),
    "inet_smap_driver": ModuleRole("driver", "Ethernet driver for the network adapter (SMAP)",
                                   "SMAP: EMAC3 MAC, PHY over MDIO, TX/RX buffer descriptors and FIFOs"),
    "smap_driver": ModuleRole("driver", "Ethernet driver for the network adapter (SMAP, PS2SDK)",
                              "SMAP: EMAC3 MAC, PHY over MDIO, TX/RX buffer descriptors and FIFOs"),
    "inet_an986_driver": ModuleRole("driver", "USB Ethernet adapter driver (AN986)", "USB host controller (OHCI)"),
    "inet_ppp": ModuleRole("driver", "PPP link layer (modem or PPPoE)"),
    "inet_pppoe_driver": ModuleRole("driver", "PPPoE over the Ethernet adapter"),
    "inet_service": ModuleRole("stack", "SCE INET TCP/IP stack"),
    "inet_control": ModuleRole("stack", "INET control: interface up/down, events, routing"),
    "inet_log": ModuleRole("stack", "INET log reader"),
    "net_configuration": ModuleRole("config", "netcnf: reads network configuration files (memory card or HDD)"),
    "eznetcnf": ModuleRole("config", "ezNetCnf: simplified network configuration access"),
    "eznetctl": ModuleRole("config", "ezNetCtl: brings the configured interface up with one call"),
    "libnet": ModuleRole("rpc", "libnet IOP side (LIBNETB): INET calls served to the EE over mSIF RPC"),
    "iop_msif_rpc_interface": ModuleRole("rpc", "mSIF RPC: multi-threaded SIF RPC used by libnet"),
    "inet_insock": ModuleRole("rpc", "INSOCK: INET socket calls served to the EE (libinsck)"),
    "netman": ModuleRole("stack", "PS2SDK network manager (homebrew stack)"),
    "ps2ip": ModuleRole("stack", "PS2SDK lwIP TCP/IP stack (homebrew)"),
    "hdd": ModuleRole("storage", "HDD (ATA) driver on DEV9", "ATA controller behind DEV9"),
    "atad": ModuleRole("storage", "ATA driver on DEV9", "ATA controller behind DEV9"),
    "pfs": ModuleRole("storage", "PFS file system on the HDD"),
}

FILE_KEYS: dict[str, str] = {
    "DEV9": "dev9", "SMAP": "inet_smap_driver", "ENT_SMAP": "inet_smap_driver", "NETCNF": "net_configuration",
    "INET": "inet_service", "INETCTL": "inet_control", "PPP": "inet_ppp", "PPPOE": "inet_pppoe_driver",
    "EZNETCNF": "eznetcnf", "EZNETCTL": "eznetctl", "LIBNETB": "libnet", "MSIFRPC": "iop_msif_rpc_interface",
    "AN986": "inet_an986_driver", "NETMAN": "netman", "PS2IP": "ps2ip", "INSOCK": "inet_insock",
}

# EE SDK library version stamps ("PsIIlibinsck2430"). Libraries that matter for networking:
NET_SDK_LIBS: dict[str, str] = {
    "libinsck": "INET sockets on the EE (sceInsock*, BSD-like)",
    "netglue": "netglue: BSD socket names over libinsck or libnet",
    "libnet": "libnet: INET calls over mSIF RPC (sceLibnet*, sceInet*)",
    "libmrpc": "mSIF RPC client (used by libnet)",
    "libdnas": "DNAS authentication (v1)",
    "dnas2": "DNAS authentication (v2)",
    "dnas2no": "DNAS authentication (v2)",
    "libeenet": "EE-side TCP/IP stack (libeenet)",
    "netcnfif": "network configuration interface (netcnf over SIF)",
}


@dataclass(frozen=True)
class Middleware:
    name: str
    kind: str
    patterns: tuple[str, ...]  # regexes over executable strings; group 1, when present, is the version
    notes: str = ""


MIDDLEWARE: tuple[Middleware, ...] = (
    Middleware("Medius", "lobby/matchmaking (SCE/SOE)", (
        r"Medius Client Library Version ([\w.]+)",
        r"Medius Game Communication Library Version ([\w.]+)",
        r"\bMedius[A-Z]\w+",
    ), "Revival servers exist for several Medius titles; the wire protocol is the same for every game."),
    Middleware("SCE-RT (rt_msg / DME)", "transport under Medius", (
        r"rt_msg_client version: ([\w.]+)",
        r"\bSCE-?RT\b",
    )),
    Middleware("GameSpy", "lobby/matchmaking/stats", (
        r"(?i)\b[\w.%-]*gamespy\.(?:com|net)\b",
        r"\bGameSpy\b",
    ), "OpenSpy reimplements the GameSpy services."),
    Middleware("EA DirtySock", "EA online (lobby, ProtoSSL, ProtoHttp)", (
        r"\bDirtySock\b", r"\bProtoSSL\b", r"\bProtoHttp\b", r"\bProtoAries\b",
    )),
    Middleware("Quazal Rendez-Vous / Net-Z", "Ubisoft lobby and replication", (
        r"\bQuazal\b", r"\bRendez-?Vous\b", r"\bNet-Z\b",
    )),
    Middleware("PlayOnline", "Square Enix online service", (r"\bPlayOnline\b",)),
    Middleware("DNAS", "Sony disc/network authentication", (
        r"PsIIdnas\w*", r"\bDNAS\b", r"\bDNAS\d",
    ), "The official DNAS servers are gone: a recomp skips the check or points it to a revival DNAS server."),
    Middleware("SSL/TLS", "encrypted connections (old ciphers, expired certificates)", (
        r"\bnsCertType\b", r"BEGIN CERTIFICATE", r"\bSSLeay\b", r"\bOpenSSL\b", r"\bVeriSign\b", r"\bThawte\b",
    ), "Expect certificate checks to need a bypass or a local TLS terminator."),
)

HOST_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|jp|co\.jp|ne\.jp|co\.uk|uk|eu|fr|de|it|es|kr|tv)\b",
    re.IGNORECASE)
URL_RE = re.compile(r"\b(?:https?|ftp)://[\x21-\x7e]+", re.IGNORECASE)
EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?![\d.])")
SDK_STAMP_RE = re.compile(r"PsII([a-z][a-z0-9_]*?)\s*\.*\s*(\d{4})")
SETTING_KEY_RE = re.compile(r"\[([A-Z][A-Z0-9_]*(?:SERVER|PORT|DNS|_IP|GATEWAY|SUBNET|HOST|URL)[A-Z0-9_]*)\]")
# Things that look like hostnames but are file names in disc paths or code.
NOT_HOSTS = re.compile(r"(?i)\.(irx|img|elf|pss|tex|ngp|bnk|vag|ico|txt|dat|bin|cnf)$")


def module_role(name: str | None, file_name: str) -> tuple[str | None, ModuleRole | None]:
    key = (name or "").lower()
    if key in IOP_MODULES:
        return key, IOP_MODULES[key]
    stem = file_name.rsplit("/", 1)[-1].split(".")[0].upper()
    key = FILE_KEYS.get(stem)
    return key, IOP_MODULES.get(key) if key else None


def is_private_ip(octets: tuple[int, ...]) -> bool:
    a, b = octets[0], octets[1]
    return a == 10 or a == 127 or (a == 172 and 16 <= b <= 31) or (a == 192 and b == 168) or a == 0
