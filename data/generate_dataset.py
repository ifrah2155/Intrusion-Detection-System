#!/usr/bin/env python3
"""Generate the labelled traffic dataset used by the detector.

Every capture is synthesised with Scapy so that the dataset is fully
reproducible from a single seed and contains *known* ground truth for every
flow. The generator emits ``<scenario>.pcap`` plus ``<scenario>.csv`` where the
CSV maps each bidirectional flow key to an attack label.

Scenarios
---------
1. ``scenario_1_benign``       normal office traffic, no attacks
2. ``scenario_2_port_scan``    vertical + horizontal + NULL scans
3. ``scenario_3_dos``          SYN flood (distributed), UDP flood, ICMP flood
4. ``scenario_4_brute_force``  SSH and RDP credential brute force
5. ``scenario_5_ambiguous``    authorised scanner, slow scan, bulk backup
6. ``scenario_6_mitm_arp``     ARP cache poisoning / man-in-the-middle

Usage
-----
    python data/generate_dataset.py            # build every scenario
    python data/generate_dataset.py --only scenario_3_dos
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import random
import sys
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: E402
from scapy.layers.l2 import ARP, Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from nids.config import DEFAULT_SCENARIOS, LABEL_DIR, PCAP_DIR  # noqa: E402
from nids.constants import BENIGN, BRUTE_FORCE, DOS, MITM, PORT_SCAN  # noqa: E402
from nids.features import canonical_key  # noqa: E402

BASE_TS = 1735689600.0          # 2025-01-01 00:00:00 UTC

# --------------------------------------------------------------------------
# Topology
# --------------------------------------------------------------------------
GATEWAY = "10.0.0.1"
DNS_SERVER = "10.0.0.53"
WEB_SERVER = "10.0.0.10"
DB_SERVER = "10.0.0.11"
AUDIT_STATION = "10.0.0.200"
ATTACKER = "10.0.0.66"
ATTACKER_2 = "10.0.0.67"
SLOW_SCANNER = "10.0.0.77"
EXTERNAL_WEB = "93.184.216.34"
EXTERNAL_API = "203.0.113.5"

CLIENTS = ["10.0.0.21", "10.0.0.22", "10.0.0.23", "10.0.0.24",
           "10.0.0.31", "10.0.0.32", "10.0.0.33"]

GW_MAC = "00:11:22:33:44:01"
ATTACKER_MAC = "aa:bb:cc:dd:ee:ff"
BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


def host_mac(ip: str) -> str:
    """Deterministic, injective MAC address for an IP (02:00:xx:xx:xx:xx)."""
    n = int(ipaddress.IPv4Address(ip))
    return "02:00:%02x:%02x:%02x:%02x" % (
        (n >> 24) & 0xFF, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF,
    )


def eth_mac(ip: str) -> str:
    """On-link hosts use their own MAC; everything else is reached via the router."""
    return host_mac(ip) if ip.startswith("10.0.0.") else GW_MAC


# --------------------------------------------------------------------------
# Capture builder
# --------------------------------------------------------------------------
class CaptureBuilder:
    """Accumulates packets and the ground-truth label of every flow."""

    def __init__(self, scenario: str, seed: int = 7):
        self.scenario = scenario
        self.rng = random.Random(seed)
        self.packets: List = []
        self.labels: Dict[str, str] = {}
        self.current_label: str = BENIGN

    # -- emission ------------------------------------------------------
    def emit(self, pkt, ts: float) -> None:
        # ``ts`` is scenario-relative; shift it onto a realistic wall clock so
        # the resulting pcaps open sensibly in Wireshark.
        pkt.time = BASE_TS + float(ts)
        self.packets.append(pkt)

        proto, src, sport, dst, dport = _flow_tuple(pkt)
        if proto is None:
            return
        key = canonical_key(proto, src, sport, dst, dport)
        self.labels.setdefault(key, self.current_label)

    def set_label(self, label: str) -> None:
        self.current_label = label

    # -- output --------------------------------------------------------
    def write(self) -> Tuple[Path, Path]:
        self.packets.sort(key=lambda p: p.time)
        PCAP_DIR.mkdir(parents=True, exist_ok=True)
        LABEL_DIR.mkdir(parents=True, exist_ok=True)

        pcap_path = PCAP_DIR / f"{self.scenario}.pcap"
        label_path = LABEL_DIR / f"{self.scenario}.csv"
        wrpcap(str(pcap_path), self.packets)

        lines = ["flow_key,label"]
        for key, label in sorted(self.labels.items()):
            lines.append(f"{key},{label}")
        label_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return pcap_path, label_path


def _flow_tuple(pkt) -> Tuple[Optional[int], str, int, str, int]:
    if pkt.haslayer(ARP) or not pkt.haslayer(IP):
        return None, "", 0, "", 0
    ip = pkt[IP]
    if pkt.haslayer(TCP):
        return int(ip.proto), ip.src, int(pkt[TCP].sport), ip.dst, int(pkt[TCP].dport)
    if pkt.haslayer(UDP):
        return int(ip.proto), ip.src, int(pkt[UDP].sport), ip.dst, int(pkt[UDP].dport)
    return int(ip.proto), ip.src, 0, ip.dst, 0


# --------------------------------------------------------------------------
# Low level packet helpers
# --------------------------------------------------------------------------
def _frame(src_ip: str, dst_ip: str, l4) -> Ether:
    return Ether(src=eth_mac(src_ip), dst=eth_mac(dst_ip)) / IP(src=src_ip, dst=dst_ip) / l4


def _payload(size: int, seed: int = 0) -> bytes:
    return bytes(0x41 + ((seed + i) % 26) for i in range(size))


def tcp_session(
    b: CaptureBuilder,
    src: str, sport: int, dst: str, dport: int, t0: float,
    n_up: int = 2, n_down: int = 2,
    up_size: int = 180, down_size: int = 1200,
    gap: float = 0.03, close: bool = True, keepalive: float = 0.0,
) -> float:
    """A complete, well-formed TCP session (handshake -> data -> teardown)."""
    rng = b.rng
    seq_c = rng.randrange(1, 2 ** 31)
    seq_s = rng.randrange(1, 2 ** 31)
    t = t0

    b.emit(_frame(src, dst, TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=64240)), t)
    t += 0.008
    b.emit(_frame(dst, src, TCP(sport=dport, dport=sport, flags="SA", seq=seq_s,
                               ack=seq_c + 1, window=65535)), t)
    t += 0.008
    b.emit(_frame(src, dst, TCP(sport=sport, dport=dport, flags="A", seq=seq_c + 1, ack=seq_s + 1)), t)
    seq_c += 1
    seq_s += 1

    for i in range(max(n_up, n_down)):
        if i < n_up:
            t += gap
            data = _payload(up_size, i)
            b.emit(_frame(src, dst, TCP(sport=sport, dport=dport, flags="PA",
                                        seq=seq_c, ack=seq_s) / Raw(data)), t)
            seq_c += len(data)
            b.emit(_frame(dst, src, TCP(sport=dport, dport=sport, flags="A",
                                        seq=seq_s, ack=seq_c)), t + 0.002)
        if keepalive:
            t += keepalive
        if i < n_down:
            t += gap
            data = _payload(down_size, i + 7)
            b.emit(_frame(dst, src, TCP(sport=dport, dport=sport, flags="PA",
                                        seq=seq_s, ack=seq_c) / Raw(data)), t)
            seq_s += len(data)
            b.emit(_frame(src, dst, TCP(sport=sport, dport=dport, flags="A",
                                        seq=seq_c, ack=seq_s)), t + 0.002)

    if close:
        t += gap
        b.emit(_frame(src, dst, TCP(sport=sport, dport=dport, flags="FA",
                                    seq=seq_c, ack=seq_s)), t)
        t += 0.01
        b.emit(_frame(dst, src, TCP(sport=dport, dport=sport, flags="FA",
                                    seq=seq_s, ack=seq_c + 1)), t)
        t += 0.01
        b.emit(_frame(src, dst, TCP(sport=sport, dport=dport, flags="A",
                                    seq=seq_c + 1, ack=seq_s + 1)), t)
    return t


def syn_probe(
    b: CaptureBuilder,
    src: str, sport: int, dst: str, dport: int, t0: float,
    respond: bool = False, rst: bool = True,
) -> float:
    """A single TCP SYN probe. ``respond`` adds a SYN/ACK, else a RST or silence."""
    seq_c = b.rng.randrange(1, 2 ** 31)
    b.emit(_frame(src, dst, TCP(sport=sport, dport=dport, flags="S", seq=seq_c, window=1024)), t0)
    if respond:
        b.emit(_frame(dst, src, TCP(sport=dport, dport=sport, flags="SA",
                                    seq=b.rng.randrange(1, 2 ** 31), ack=seq_c + 1)), t0 + 0.004)
        return t0 + 0.004
    if rst:
        b.emit(_frame(dst, src, TCP(sport=dport, dport=sport, flags="RA",
                                    seq=0, ack=seq_c + 1)), t0 + 0.004)
        return t0 + 0.004
    return t0


def flag_probe(b: CaptureBuilder, src: str, sport: int, dst: str, dport: int,
               t0: float, flags: str) -> float:
    """Probe with an arbitrary (often illegal) TCP flag combination."""
    b.emit(_frame(src, dst, TCP(sport=sport, dport=dport, flags=flags,
                                seq=b.rng.randrange(1, 2 ** 31), window=1024)), t0)
    return t0


def udp_exchange(b: CaptureBuilder, src: str, sport: int, dst: str, dport: int,
                 t0: float, req: bytes = b"query", resp: bytes = b"answer") -> float:
    b.emit(_frame(src, dst, UDP(sport=sport, dport=dport) / Raw(req)), t0)
    b.emit(_frame(dst, src, UDP(sport=dport, dport=sport) / Raw(resp)), t0 + 0.02)
    return t0 + 0.02


def udp_flood_packet(b: CaptureBuilder, src: str, sport: int, dst: str, dport: int,
                     t0: float, size: int = 512) -> None:
    b.emit(_frame(src, dst, UDP(sport=sport, dport=dport) / Raw(_payload(size))), t0)


def icmp_ping(b: CaptureBuilder, src: str, dst: str, t0: float,
              count: int = 4, gap: float = 1.0) -> float:
    ident = b.rng.randrange(1, 65535)
    t = t0
    for seq in range(1, count + 1):
        b.emit(_frame(src, dst, ICMP(type=8, id=ident, seq=seq) / Raw(_payload(56))), t)
        b.emit(_frame(dst, src, ICMP(type=0, id=ident, seq=seq) / Raw(_payload(56))), t + 0.004)
        t += gap
    return t


def arp_announce(b: CaptureBuilder, sender_mac: str, sender_ip: str,
                 target_mac: str, target_ip: str, t0: float, op: int = 2) -> None:
    """Craft an ARP reply/request claiming ``sender_ip`` belongs to ``sender_mac``."""
    pkt = Ether(src=sender_mac, dst=target_mac) / ARP(
        op=op, hwsrc=sender_mac, psrc=sender_ip, hwdst=target_mac, pdst=target_ip,
    )
    b.emit(pkt, t0)


def _eph(b: CaptureBuilder) -> int:
    return b.rng.randrange(32768, 60999)


# --------------------------------------------------------------------------
# Benign traffic
# --------------------------------------------------------------------------
def generate_benign(b: CaptureBuilder, t_start: float, t_end: float) -> float:
    """Background office traffic: web, DNS, admin SSH, monitoring, NTP."""
    b.set_label(BENIGN)
    t = t_start
    while t < t_end:
        client = b.rng.choice(CLIENTS)
        kind = b.rng.choices(
            ["http", "https", "dns", "ssh", "ping", "ntp", "db"],
            weights=[28, 24, 18, 8, 8, 6, 8],
        )[0]

        if kind == "http":
            t = tcp_session(b, client, _eph(b), EXTERNAL_WEB, 80, t,
                            n_up=2, n_down=2, up_size=320, down_size=1400)
        elif kind == "https":
            t = tcp_session(b, client, _eph(b), WEB_SERVER, 443, t,
                            n_up=3, n_down=3, up_size=420, down_size=1360)
        elif kind == "dns":
            t = udp_exchange(b, client, _eph(b), DNS_SERVER, 53, t,
                             req=b"\x12\x34\x01\x00query", resp=b"\x12\x34\x81\x80answer-payload")
        elif kind == "ssh":
            # Long-lived interactive admin session: many packets over several seconds.
            t = tcp_session(b, client, _eph(b), WEB_SERVER, 22, t,
                            n_up=5, n_down=5, up_size=96, down_size=220, gap=0.45)
        elif kind == "ping":
            t = icmp_ping(b, client, GATEWAY, t, count=4, gap=0.6)
        elif kind == "ntp":
            t = udp_exchange(b, client, _eph(b), GATEWAY, 123, t,
                             req=b"\x1b" + b"\x00" * 47, resp=b"\x1b" + b"\x00" * 47)
        else:  # db
            t = tcp_session(b, client, _eph(b), DB_SERVER, 3306, t,
                            n_up=2, n_down=2, up_size=240, down_size=900)

        t += b.rng.uniform(0.35, 1.8)
    return t


# --------------------------------------------------------------------------
# Attack generators
# --------------------------------------------------------------------------
def attack_port_scan(b: CaptureBuilder) -> None:
    """Vertical SYN scan, horizontal sweep and a NULL scan."""
    b.set_label(PORT_SCAN)

    # --- Vertical scan of the web server: 120 ports, filtered (no reply) ---
    t = 20.0
    sport = _eph(b)
    for port in range(1, 121):
        syn_probe(b, ATTACKER, sport + port, WEB_SERVER, port, t, rst=False)
        t += 0.025

    # --- Horizontal scan: port 80 across 40 hosts (some reply with RST) ---
    t = 45.0
    for i in range(40):
        target = f"10.0.0.{100 + i}"
        syn_probe(b, ATTACKER, _eph(b), target, 80, t, rst=(i % 2 == 0))
        t += 0.08

    # --- NULL scan: no flags at all, against a handful of ports ---
    t = 70.0
    for port in (21, 22, 25, 80, 139, 443, 445, 8080):
        flag_probe(b, ATTACKER, _eph(b), WEB_SERVER, port, t, flags="")
        t += 0.05

    # --- XMAS scan: FIN+PSH+URG ---
    t = 72.0
    for port in (21, 23, 80, 443):
        flag_probe(b, ATTACKER, _eph(b), WEB_SERVER, port, t, flags="FPU")
        t += 0.05


def attack_dos(b: CaptureBuilder) -> None:
    """Distributed SYN flood plus single-source UDP and ICMP floods."""
    # --- Distributed SYN flood: 60 spoofed sources -> web server:80 ---
    b.set_label(DOS)
    t = 25.0
    for round_idx in range(30):
        for i in range(60):
            spoofed = f"10.0.0.{150 + i}"
            sport = 1024 + (i * 7 + round_idx) % 60000
            b.emit(
                _frame(spoofed, WEB_SERVER,
                       TCP(sport=sport, dport=80, flags="S",
                           seq=b.rng.randrange(1, 2 ** 31), window=512)),
                t + b.rng.uniform(0, 0.02),
            )
        t += 0.1

    # --- UDP flood from a single host ---
    b.set_label(DOS)
    t = 55.0
    for i in range(400):
        udp_flood_packet(b, ATTACKER, 40000 + (i % 1000), WEB_SERVER, 53, t, size=512)
        t += 0.003

    # --- ICMP flood ---
    b.set_label(DOS)
    t = 75.0
    for i in range(300):
        b.emit(_frame(ATTACKER_2, WEB_SERVER,
                      ICMP(type=8, id=0x1D, seq=i % 65535) / Raw(_payload(64))), t)
        t += 0.003


def attack_brute_force(b: CaptureBuilder) -> None:
    """Repeated failed SSH logins followed by RDP attempts."""
    b.set_label(BRUTE_FORCE)

    # --- 18 failed SSH logins, ~0.3s apart ---
    t = 30.0
    for i in range(18):
        sport = _eph(b)
        seq_c = b.rng.randrange(1, 2 ** 31)
        seq_s = b.rng.randrange(1, 2 ** 31)

        b.emit(_frame(ATTACKER, WEB_SERVER,
                      TCP(sport=sport, dport=22, flags="S", seq=seq_c, window=64240)), t)
        b.emit(_frame(WEB_SERVER, ATTACKER,
                      TCP(sport=22, dport=sport, flags="SA", seq=seq_s, ack=seq_c + 1)), t + 0.01)
        b.emit(_frame(ATTACKER, WEB_SERVER,
                      TCP(sport=sport, dport=22, flags="A", seq=seq_c + 1, ack=seq_s + 1)), t + 0.02)
        # server banner
        b.emit(_frame(WEB_SERVER, ATTACKER,
                      TCP(sport=22, dport=sport, flags="PA", seq=seq_s + 1, ack=seq_c + 1)
                      / Raw(b"SSH-2.0-OpenSSH_8.9p1")), t + 0.03)
        # client sends a credential then gives up
        b.emit(_frame(ATTACKER, WEB_SERVER,
                      TCP(sport=sport, dport=22, flags="PA", seq=seq_c + 1, ack=seq_s + 25)
                      / Raw(b"root:" + str(i).encode())), t + 0.08)
        # server rejects -> RST from client
        b.emit(_frame(ATTACKER, WEB_SERVER,
                      TCP(sport=sport, dport=22, flags="R", seq=seq_c + 15, ack=0)), t + 0.14)
        t += 0.30

    # --- 12 failed RDP attempts ---
    t = 50.0
    for i in range(12):
        sport = _eph(b)
        seq_c = b.rng.randrange(1, 2 ** 31)
        b.emit(_frame(ATTACKER_2, WEB_SERVER,
                      TCP(sport=sport, dport=3389, flags="S", seq=seq_c, window=8192)), t)
        b.emit(_frame(WEB_SERVER, ATTACKER_2,
                      TCP(sport=3389, dport=sport, flags="SA", seq=1234, ack=seq_c + 1)), t + 0.01)
        b.emit(_frame(ATTACKER_2, WEB_SERVER,
                      TCP(sport=sport, dport=3389, flags="R", seq=seq_c + 1, ack=0)), t + 0.09)
        t += 0.35


def attack_ambiguous(b: CaptureBuilder) -> None:
    """Three deliberately hard cases.

    * an **authorised** vulnerability scanner that looks exactly like R-001
    * a **slow** scan that stays under every window threshold
    * a legitimate **bulk backup** with flood-like throughput
    """
    # --- 1. Authorised audit scan from the dedicated audit station ----------
    # Ground truth is BENIGN: this traffic *is* a port scan, but it is an
    # approved audit. It exists to measure the false-positive cost of R-001.
    b.set_label(BENIGN)
    t = 20.0
    sport = _eph(b)
    for port in range(1, 41):
        syn_probe(b, AUDIT_STATION, sport + port, WEB_SERVER, port, t, rst=False)
        t += 0.05

    # --- 2. Slow scan: one port every 3s, never > 4 ports per 10s window ----
    b.set_label(PORT_SCAN)
    t = 30.0
    for port in range(1, 26):
        syn_probe(b, SLOW_SCANNER, _eph(b), WEB_SERVER, port, t, rst=False)
        t += 3.0

    # --- 3. Legitimate bulk backup: 1800 packets in ~2s to SMB ------------
    b.set_label(BENIGN)
    t = 90.0
    sport = _eph(b)
    seq_c = b.rng.randrange(1, 2 ** 31)
    seq_s = b.rng.randrange(1, 2 ** 31)
    b.emit(_frame(CLIENTS[6], WEB_SERVER, TCP(sport=sport, dport=445, flags="S", seq=seq_c)), t)
    b.emit(_frame(WEB_SERVER, CLIENTS[6], TCP(sport=445, dport=sport, flags="SA",
                                              seq=seq_s, ack=seq_c + 1)), t + 0.005)
    b.emit(_frame(CLIENTS[6], WEB_SERVER, TCP(sport=sport, dport=445, flags="A",
                                              seq=seq_c + 1, ack=seq_s + 1)), t + 0.01)
    seq_c += 1
    seq_s += 1
    t += 0.01
    for i in range(900):
        b.emit(_frame(CLIENTS[6], WEB_SERVER,
                      TCP(sport=sport, dport=445, flags="PA", seq=seq_c, ack=seq_s)
                      / Raw(_payload(1460, i))), t)
        seq_c += 1460
        b.emit(_frame(WEB_SERVER, CLIENTS[6],
                      TCP(sport=445, dport=sport, flags="A", seq=seq_s, ack=seq_c)), t + 0.001)
        t += 0.0022


def attack_mitm_arp(b: CaptureBuilder) -> None:
    """ARP cache poisoning of the gateway and the web server."""
    # Legitimate ARP first, so the capture contains the *correct* binding.
    b.set_label(MITM)
    t = 5.0
    for client in CLIENTS[:4]:
        arp_announce(b, GW_MAC, GATEWAY, host_mac(client), client, t, op=2)
        t += 0.2
    arp_announce(b, host_mac(WEB_SERVER), WEB_SERVER, GW_MAC, GATEWAY, t, op=2)
    arp_announce(b, GW_MAC, GATEWAY, host_mac(WEB_SERVER), WEB_SERVER, t + 0.2, op=2)

    # Attacker poisons every client: "the gateway is at my MAC".
    b.set_label(MITM)
    t = 15.0
    for _ in range(12):
        for client in CLIENTS:
            arp_announce(b, ATTACKER_MAC, GATEWAY, host_mac(client), client, t, op=2)
            t += 0.05

    # ...and poisons clients about the web server too.
    t = 40.0
    for _ in range(8):
        for client in CLIENTS:
            arp_announce(b, ATTACKER_MAC, WEB_SERVER, host_mac(client), client, t, op=2)
            t += 0.05

    # Victim traffic now flows via the attacker's MAC (man-in-the-middle).
    b.set_label(MITM)
    t = 60.0
    victim = CLIENTS[0]
    sport = _eph(b)
    seq_c = b.rng.randrange(1, 2 ** 31)
    b.emit(Ether(src=host_mac(victim), dst=ATTACKER_MAC)
           / IP(src=victim, dst=EXTERNAL_WEB)
           / TCP(sport=sport, dport=80, flags="S", seq=seq_c), t)
    b.emit(Ether(src=ATTACKER_MAC, dst=GW_MAC)
           / IP(src=victim, dst=EXTERNAL_WEB)
           / TCP(sport=sport, dport=80, flags="S", seq=seq_c), t + 0.002)
    b.emit(Ether(src=GW_MAC, dst=ATTACKER_MAC)
           / IP(src=EXTERNAL_WEB, dst=victim)
           / TCP(sport=80, dport=sport, flags="SA", seq=999, ack=seq_c + 1), t + 0.02)
    b.emit(Ether(src=ATTACKER_MAC, dst=host_mac(victim))
           / IP(src=EXTERNAL_WEB, dst=victim)
           / TCP(sport=80, dport=sport, flags="SA", seq=999, ack=seq_c + 1), t + 0.022)


# --------------------------------------------------------------------------
# Scenario assembly
# --------------------------------------------------------------------------
def build_scenario(name: str, seed: int = 7) -> Tuple[Path, Path]:
    b = CaptureBuilder(name, seed=seed)

    if name == "scenario_1_benign":
        generate_benign(b, 0.0, 150.0)

    elif name == "scenario_2_port_scan":
        generate_benign(b, 0.0, 150.0)
        attack_port_scan(b)

    elif name == "scenario_3_dos":
        generate_benign(b, 0.0, 110.0)
        attack_dos(b)

    elif name == "scenario_4_brute_force":
        generate_benign(b, 0.0, 120.0)
        attack_brute_force(b)

    elif name == "scenario_5_ambiguous":
        generate_benign(b, 0.0, 130.0)
        attack_ambiguous(b)

    elif name == "scenario_6_mitm_arp":
        generate_benign(b, 0.0, 100.0)
        attack_mitm_arp(b)

    else:
        raise SystemExit(f"Unknown scenario: {name}")

    return b.write(), b


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--only", action="append", choices=list(DEFAULT_SCENARIOS),
                        help="Generate just these scenarios (repeatable)")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)

    targets = args.only or list(DEFAULT_SCENARIOS)
    manifest = {}

    print(f"Generating {len(targets)} capture(s) into {PCAP_DIR}\n")
    for name in targets:
        (pcap_path, label_path), builder = build_scenario(name, seed=args.seed)
        label_counts: Dict[str, int] = {}
        for label in builder.labels.values():
            label_counts[label] = label_counts.get(label, 0) + 1

        size_kb = pcap_path.stat().st_size / 1024
        print(f"  {name:<26} {len(builder.packets):>6} packets  "
              f"{size_kb:>7.1f} KB  {len(builder.labels):>4} flows")
        for label, count in sorted(label_counts.items(), key=lambda kv: -kv[1]):
            print(f"      {label:<12} {count:>4} flows")

        manifest[name] = {
            "description": DEFAULT_SCENARIOS[name],
            "pcap": str(pcap_path),
            "labels": str(label_path),
            "packets": len(builder.packets),
            "flows": len(builder.labels),
            "label_counts": label_counts,
        }
        print()

    manifest_path = PCAP_DIR.parent / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"Manifest written to {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
