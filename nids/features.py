"""Packet parsing, bidirectional flow reconstruction and feature extraction.

Pipeline
--------
1. ``iter_packets`` streams a pcap file (never loads it all into RAM) and
   normalises each frame into a flat :class:`PacketRecord`.
2. ``build_flows`` folds packets into bidirectional 5-tuple flows, closing a
   flow after ``flow_idle_timeout`` seconds of silence.
3. ``flow_features`` derives per-flow statistics (duration, rates, packet-size
   distribution, flag ratios, inter-arrival times).
4. ``window_features`` derives *host behaviour* statistics over a sliding
   window: how many distinct hosts/ports a source touched, the entropy of its
   destination ports, fan-in at a victim, and so on. These are what separate a
   port scan from a busy-but-legitimate client.
5. ``extract_features`` glues the three stages together and returns a tidy
   DataFrame plus any layer-2 (ARP) events.

All thresholds are injected from :class:`nids.config.DetectionConfig`.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

# Registering these layers is not optional: ``PcapReader`` resolves the pcap
# link type through Scapy's layer registry, and without an explicit import of
# the L2/L3 layers every frame is decoded as ``Raw`` (silently yielding zero
# flows). Import them once, at module load.
from scapy.layers.inet import ICMP, IP, TCP, UDP  # noqa: F401
from scapy.layers.l2 import ARP, Ether  # noqa: F401

from .config import DetectionConfig
from .constants import (
    BENIGN,
    FLAG_NAMES,
    IPPROTO_TCP,
    IPPROTO_UDP,
    PORT_SSH,
    PROTO_NAMES,
    TCP_ACK,
    TCP_FIN,
    TCP_PSH,
    TCP_RST,
    TCP_SYN,
    TCP_URG,
)


# ==========================================================================
# 1. Packet level
# ==========================================================================
@dataclass
class PacketRecord:
    """A single normalised frame."""

    ts: float
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    proto: int = 0
    length: int = 0
    payload_len: int = 0
    flags: int = 0
    is_arp: bool = False
    arp_op: int = 0
    arp_src_ip: str = ""
    arp_dst_ip: str = ""
    arp_src_mac: str = ""

    @property
    def proto_name(self) -> str:
        if self.is_arp:
            return "ARP"
        return PROTO_NAMES.get(self.proto, f"IP/{self.proto}")


def parse_packet(pkt: Any) -> Optional[PacketRecord]:
    """Convert a Scapy packet into a :class:`PacketRecord` (or ``None``)."""
    try:
        ts = float(pkt.time)
    except Exception:  # pragma: no cover - malformed timestamps are rare
        return None

    # Layer 2: ARP is the only non-IP protocol we care about (MITM detection).
    try:
        from scapy.layers.l2 import ARP

        if pkt.haslayer(ARP):
            arp = pkt[ARP]
            return PacketRecord(
                ts=ts,
                length=len(pkt),
                is_arp=True,
                arp_op=int(arp.op),
                arp_src_ip=str(arp.psrc),
                arp_dst_ip=str(arp.pdst),
                arp_src_mac=str(arp.hwsrc).lower(),
            )
    except Exception:  # pragma: no cover
        pass

    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP

        if not pkt.haslayer(IP):
            return None

        ip = pkt[IP]
        rec = PacketRecord(
            ts=ts,
            src_ip=str(ip.src),
            dst_ip=str(ip.dst),
            proto=int(ip.proto),
            length=int(ip.len) if ip.len else len(pkt),
        )

        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            rec.src_port = int(tcp.sport)
            rec.dst_port = int(tcp.dport)
            rec.flags = int(tcp.flags)
            rec.payload_len = len(bytes(tcp.payload))
        elif pkt.haslayer(UDP):
            udp = pkt[UDP]
            rec.src_port = int(udp.sport)
            rec.dst_port = int(udp.dport)
            rec.payload_len = len(bytes(udp.payload))
        elif pkt.haslayer(ICMP):
            icmp = pkt[ICMP]
            rec.payload_len = len(bytes(icmp.payload))
        else:
            rec.payload_len = max(rec.length - 20, 0)

        return rec
    except Exception:  # pragma: no cover
        return None


def iter_packets(pcap_path: str | Path) -> Iterator[PacketRecord]:
    """Stream a pcap file. Uses ``PcapReader`` so memory stays flat."""
    from scapy.utils import PcapReader

    with PcapReader(str(pcap_path)) as reader:
        for pkt in reader:
            rec = parse_packet(pkt)
            if rec is not None:
                yield rec


# ==========================================================================
# 2. Flow level
# ==========================================================================
def canonical_key(proto: int, src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> str:
    """Direction-independent 5-tuple identifier.

    ``A -> B`` and ``B -> A`` collapse to the same key, which is what makes the
    flow bidirectional. ARP has no 5-tuple and is handled separately.
    """
    a = (src_ip, src_port)
    b = (dst_ip, dst_port)
    if a <= b:
        return f"{proto}|{a[0]}:{a[1]}|{b[0]}:{b[1]}"
    return f"{proto}|{b[0]}:{b[1]}|{a[0]}:{a[1]}"


@dataclass
class Flow:
    """A bidirectional conversation between two endpoints."""

    key: str
    proto: int
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    start_ts: float
    last_ts: float
    packets: List[Tuple[float, bool, int, int, int]] = field(default_factory=list)
    """(timestamp, is_forward, wire_length, payload_length, tcp_flags)"""

    @property
    def duration(self) -> float:
        return max(self.last_ts - self.start_ts, 0.0)

    @property
    def proto_name(self) -> str:
        return PROTO_NAMES.get(self.proto, f"IP/{self.proto}")

    def add(self, rec: PacketRecord) -> None:
        self.packets.append(
            (
                rec.ts,
                rec.src_ip == self.src_ip and rec.src_port == self.src_port,
                rec.length,
                rec.payload_len,
                rec.flags,
            )
        )
        self.last_ts = rec.ts


def build_flows(
    records: Iterable[PacketRecord],
    idle_timeout: float = 60.0,
) -> Tuple[List[Flow], List[PacketRecord]]:
    """Fold packets into flows, returning ``(flows, arp_records)``.

    A 5-tuple that goes quiet for longer than ``idle_timeout`` is closed and a
    fresh flow is opened for the next packet of that tuple, so a long-lived
    service that is periodically re-used does not become one giant flow.
    """
    open_flows: Dict[str, Flow] = {}
    closed: List[Flow] = []
    arp_records: List[PacketRecord] = []

    for rec in records:
        if rec.is_arp:
            arp_records.append(rec)
            continue

        key = canonical_key(rec.proto, rec.src_ip, rec.src_port, rec.dst_ip, rec.dst_port)
        flow = open_flows.get(key)

        if flow is not None and (rec.ts - flow.last_ts) > idle_timeout:
            closed.append(flow)
            flow = None

        if flow is None:
            flow = Flow(
                key=key,
                proto=rec.proto,
                src_ip=rec.src_ip,
                dst_ip=rec.dst_ip,
                src_port=rec.src_port,
                dst_port=rec.dst_port,
                start_ts=rec.ts,
                last_ts=rec.ts,
            )
            open_flows[key] = flow

        flow.add(rec)

    closed.extend(open_flows.values())
    closed.sort(key=lambda f: f.start_ts)
    return closed, arp_records


# ==========================================================================
# 3. Per-flow features
# ==========================================================================
FEATURE_COLUMNS: List[str] = [
    # volume / timing
    "duration",
    "fwd_packets",
    "bwd_packets",
    "total_packets",
    "fwd_bytes",
    "bwd_bytes",
    "total_bytes",
    "pkt_rate",
    "byte_rate",
    "payload_bytes",
    "payload_ratio",
    # packet size distribution
    "pkt_len_mean",
    "pkt_len_std",
    "pkt_len_min",
    "pkt_len_max",
    "fwd_pkt_len_mean",
    "bwd_pkt_len_mean",
    # inter-arrival times
    "iat_mean",
    "iat_std",
    "iat_max",
    "iat_min",
    # TCP flag behaviour
    "syn_cnt",
    "ack_cnt",
    "fin_cnt",
    "rst_cnt",
    "psh_cnt",
    "urg_cnt",
    "syn_ratio",
    "ack_ratio",
    "rst_ratio",
    "fin_ratio",
    "has_syn",
    "has_synack",
    "handshake_completed",
    "failed_handshake",
    "null_scan",
    "xmas_scan",
    # protocol / endpoint
    "proto_tcp",
    "proto_udp",
    "proto_icmp",
    "dst_port",
    "is_well_known_port",
    # host behaviour over the sliding window
    "src_flow_count_win",
    "src_unique_dst_hosts_win",
    "src_unique_dst_ports_win",
    "src_port_entropy_win",
    "src_pkt_count_win",
    "src_syn_pkts_win",
    "src_pps_peak",
    "src_syn_ratio_win",
    "src_failed_handshakes_win",
    "src_ssh_attempts_win",
    "dst_unique_src_hosts_win",
    "dst_pkt_count_win",
    "dst_pps_peak",
    "dst_syn_ratio_win",
]

META_COLUMNS: List[str] = [
    "flow_key",
    "scenario",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "proto",
    "proto_name",
    "start_ts",
    "end_ts",
    "window",
    "tcp_flags_summary",
]

WELL_KNOWN_PORTS = {
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 111, 123, 135, 137, 138, 139,
    143, 161, 162, 389, 443, 445, 465, 514, 587, 636, 993, 995, 1433, 1521,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
}


def _safe_div(num: float, den: float, default: float = 0.0) -> float:
    return float(num) / float(den) if den else default


def flow_features(flow: Flow) -> Dict[str, Any]:
    """Compute the per-flow half of the feature vector."""
    ts = np.array([p[0] for p in flow.packets], dtype=float)
    fwd_mask = np.array([p[1] for p in flow.packets], dtype=bool)
    lengths = np.array([p[2] for p in flow.packets], dtype=float)
    payloads = np.array([p[3] for p in flow.packets], dtype=float)
    flags = np.array([p[4] for p in flow.packets], dtype=int)

    total_packets = int(len(ts))
    duration = float(ts[-1] - ts[0]) if total_packets > 1 else 0.0
    dur_safe = max(duration, 1e-3)

    fwd_len = lengths[fwd_mask]
    bwd_len = lengths[~fwd_mask]

    if total_packets > 1:
        iat = np.diff(ts)
        iat_mean, iat_std = float(iat.mean()), float(iat.std())
        iat_max, iat_min = float(iat.max()), float(iat.min())
    else:
        iat_mean = iat_std = iat_max = iat_min = 0.0

    syn_cnt = int(np.sum(flags & TCP_SYN != 0))
    ack_cnt = int(np.sum(flags & TCP_ACK != 0))
    fin_cnt = int(np.sum(flags & TCP_FIN != 0))
    rst_cnt = int(np.sum(flags & TCP_RST != 0))
    psh_cnt = int(np.sum(flags & TCP_PSH != 0))
    urg_cnt = int(np.sum(flags & TCP_URG != 0))

    # A completed handshake needs SYN (initiator) -> SYN/ACK (responder) -> ACK.
    has_syn = bool(np.any((flags & TCP_SYN != 0) & fwd_mask))
    has_synack = bool(np.any((flags & TCP_SYN != 0) & (flags & TCP_ACK != 0) & ~fwd_mask))
    handshake_completed = has_syn and has_synack

    # Scanning with illegal flag combinations: a NULL scan sends no flags at
    # all, an XMAS scan sets FIN+PSH+URG together. Both are meaningless to a
    # conforming TCP stack, which is exactly why attackers use them.
    null_scan = int(np.any(flags == 0)) if flow.proto == IPPROTO_TCP else 0
    xmas_scan = int(np.any((flags & (TCP_FIN | TCP_PSH | TCP_URG))
                           == (TCP_FIN | TCP_PSH | TCP_URG)))

    total_bytes = float(lengths.sum())
    payload_bytes = float(payloads.sum())

    return {
        "duration": duration,
        "fwd_packets": int(fwd_mask.sum()),
        "bwd_packets": int((~fwd_mask).sum()),
        "total_packets": total_packets,
        "fwd_bytes": float(fwd_len.sum()),
        "bwd_bytes": float(bwd_len.sum()),
        "total_bytes": total_bytes,
        "pkt_rate": _safe_div(total_packets, dur_safe),
        "byte_rate": _safe_div(total_bytes, dur_safe),
        "payload_bytes": payload_bytes,
        "payload_ratio": _safe_div(payload_bytes, total_bytes),
        "pkt_len_mean": float(lengths.mean()),
        "pkt_len_std": float(lengths.std()),
        "pkt_len_min": float(lengths.min()),
        "pkt_len_max": float(lengths.max()),
        "fwd_pkt_len_mean": float(fwd_len.mean()) if fwd_len.size else 0.0,
        "bwd_pkt_len_mean": float(bwd_len.mean()) if bwd_len.size else 0.0,
        "iat_mean": iat_mean,
        "iat_std": iat_std,
        "iat_max": iat_max,
        "iat_min": iat_min,
        "syn_cnt": syn_cnt,
        "ack_cnt": ack_cnt,
        "fin_cnt": fin_cnt,
        "rst_cnt": rst_cnt,
        "psh_cnt": psh_cnt,
        "urg_cnt": urg_cnt,
        "syn_ratio": _safe_div(syn_cnt, total_packets),
        "ack_ratio": _safe_div(ack_cnt, total_packets),
        "rst_ratio": _safe_div(rst_cnt, total_packets),
        "fin_ratio": _safe_div(fin_cnt, total_packets),
        "has_syn": int(has_syn),
        "has_synack": int(has_synack),
        "handshake_completed": int(handshake_completed),
        "failed_handshake": int(has_syn and not handshake_completed),
        "null_scan": null_scan,
        "xmas_scan": xmas_scan,
        "proto_tcp": int(flow.proto == IPPROTO_TCP),
        "proto_udp": int(flow.proto == IPPROTO_UDP),
        "proto_icmp": int(flow.proto not in (IPPROTO_TCP, IPPROTO_UDP)),
        "dst_port": int(flow.dst_port),
        "is_well_known_port": int(flow.dst_port in WELL_KNOWN_PORTS),
    }


def _entropy(counter: Counter) -> float:
    total = sum(counter.values())
    if total <= 0:
        return 0.0
    ent = 0.0
    for count in counter.values():
        p = count / total
        ent -= p * math.log2(p)
    return ent


# ==========================================================================
# 4. Host behaviour over a sliding window
# ==========================================================================
_WINDOW_DEFAULTS = {
    "src_flow_count_win": 0,
    "src_unique_dst_hosts_win": 0,
    "src_unique_dst_ports_win": 0,
    "src_port_entropy_win": 0.0,
    "src_pkt_count_win": 0,
    "src_syn_pkts_win": 0,
    "src_pps_peak": 0.0,
    "src_syn_ratio_win": 0.0,
    "src_failed_handshakes_win": 0,
    "src_ssh_attempts_win": 0,
    "dst_unique_src_hosts_win": 0,
    "dst_pkt_count_win": 0,
    "dst_pps_peak": 0.0,
    "dst_syn_ratio_win": 0.0,
}


def window_features(rows: Sequence[Dict[str, Any]], window_seconds: float) -> List[Dict[str, Any]]:
    """Attach per-source and per-destination behaviour aggregates.

    ``rows`` must contain one dict per flow with the keys used below. Each flow
    is placed in ``window = int(start_ts // window_seconds)``. The source-side
    aggregates describe *fan-out* (scanning); the destination-side aggregates
    describe *fan-in* (distributed flooding).
    """
    src_groups: Dict[Tuple[str, int], List[Dict[str, Any]]] = defaultdict(list)
    dst_groups: Dict[Tuple[str, int], List[Dict[str, Any]]] = defaultdict(list)

    for row in rows:
        bucket = int(row["start_ts"] // window_seconds)
        row["window"] = bucket
        src_groups[(row["src_ip"], bucket)].append(row)
        dst_groups[(row["dst_ip"], bucket)].append(row)

    def _peak_per_second(group: List[Dict[str, Any]]) -> float:
        """Highest packet count seen in any single 1-second slice of the window.

        A window-average hides exactly the short bursts a flood detector needs
        to see, so rates are reported as peak-per-second instead.
        """
        per_second: Counter = Counter()
        for r in group:
            per_second[int(r["start_ts"])] += int(r["total_packets"])
        return float(max(per_second.values())) if per_second else 0.0

    out: List[Dict[str, Any]] = []

    for row in rows:
        bucket = row["window"]
        src_rows = src_groups[(row["src_ip"], bucket)]
        dst_rows = dst_groups[(row["dst_ip"], bucket)]

        port_counter = Counter(int(r["dst_port"]) for r in src_rows)
        src_pkts = sum(int(r["total_packets"]) for r in src_rows)
        src_syns = sum(int(r["syn_cnt"]) for r in src_rows)
        dst_pkts = sum(int(r["total_packets"]) for r in dst_rows)
        dst_syns = sum(int(r["syn_cnt"]) for r in dst_rows)

        merged = dict(row)
        merged.update(
            {
                "src_flow_count_win": len(src_rows),
                "src_unique_dst_hosts_win": len({r["dst_ip"] for r in src_rows}),
                "src_unique_dst_ports_win": len(port_counter),
                "src_port_entropy_win": _entropy(port_counter),
                "src_pkt_count_win": src_pkts,
                "src_syn_pkts_win": src_syns,
                "src_pps_peak": _peak_per_second(src_rows),
                "src_syn_ratio_win": _safe_div(src_syns, src_pkts),
                "src_failed_handshakes_win": sum(int(r["failed_handshake"]) for r in src_rows),
                "src_ssh_attempts_win": sum(
                    1 for r in src_rows if int(r["dst_port"]) in (PORT_SSH, 3389)
                ),
                "dst_unique_src_hosts_win": len({r["src_ip"] for r in dst_rows}),
                "dst_pkt_count_win": dst_pkts,
                "dst_pps_peak": _peak_per_second(dst_rows),
                "dst_syn_ratio_win": _safe_div(dst_syns, dst_pkts),
            }
        )
        out.append(merged)

    return out


# ==========================================================================
# 5. Layer-2 (ARP) analysis for MITM
# ==========================================================================
def analyse_arp(arp_records: Sequence[PacketRecord], config: DetectionConfig) -> List[Dict[str, Any]]:
    """Detect ARP cache poisoning from gratuitous / conflicting ARP traffic.

    Two independent signals are used:

    * **Conflict** - the same IP address is announced by more than one MAC
      inside the capture. On a healthy network an IP maps to exactly one MAC.
    * **Gratuitous storm** - an unsolicited ARP reply (``op == 2`` with
      ``psrc == pdst``) repeated many times, typical of ``arpspoof``/Ettercap.
    """
    if not arp_records:
        return []

    claims: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
    gratuitous: Counter = Counter()

    for rec in arp_records:
        if not rec.arp_src_ip or not rec.arp_src_mac:
            continue
        entry = claims[rec.arp_src_ip].setdefault(
            rec.arp_src_mac, {"count": 0, "first_ts": rec.ts, "last_ts": rec.ts}
        )
        entry["count"] += 1
        entry["last_ts"] = rec.ts
        if rec.arp_op == 2 and rec.arp_src_ip == rec.arp_dst_ip:
            gratuitous[(rec.arp_src_ip, rec.arp_src_mac)] += 1

    events: List[Dict[str, Any]] = []

    for ip, macs in claims.items():
        if len(macs) < config.arp_min_mac_changes:
            continue
        ordered = sorted(macs.items(), key=lambda kv: kv[1]["last_ts"])
        latest_mac, latest = ordered[-1]
        original_mac = ordered[0][0]
        events.append(
            {
                "rule_id": "R-007",
                "rule_name": "ARP_CACHE_POISONING",
                "category": "mitm",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "src_ip": ip,
                "dst_ip": ip,
                "src_port": 0,
                "dst_port": 0,
                "proto": "ARP",
                "timestamp": latest["first_ts"],
                "evidence": {
                    "ip": ip,
                    "mac_count": len(macs),
                    "macs": {m: v["count"] for m, v in macs.items()},
                    "original_mac": original_mac,
                    "suspect_mac": latest_mac,
                },
                "explanation": (
                    f"IP {ip} was announced by {len(macs)} different MAC addresses "
                    f"({', '.join(sorted(macs))}); the most recent claim came from "
                    f"{latest_mac} while it was previously bound to {original_mac}. "
                    "This is the signature of ARP cache poisoning used to position "
                    "an attacker for man-in-the-middle interception."
                ),
            }
        )

    for (ip, mac), count in gratuitous.items():
        if count < config.arp_gratuitous_threshold:
            continue
        if any(e["evidence"].get("suspect_mac") == mac for e in events):
            continue
        events.append(
            {
                "rule_id": "R-007b",
                "rule_name": "GRATUITOUS_ARP_FLOOD",
                "category": "mitm",
                "severity": "MEDIUM",
                "confidence": 0.70,
                "src_ip": ip,
                "dst_ip": ip,
                "src_port": 0,
                "dst_port": 0,
                "proto": "ARP",
                "timestamp": min(
                    r.ts for r in arp_records
                    if r.arp_src_ip == ip and r.arp_src_mac == mac
                ),
                "evidence": {"ip": ip, "mac": mac, "gratuitous_count": count},
                "explanation": (
                    f"{mac} sent {count} unsolicited (gratuitous) ARP replies for "
                    f"{ip}. Legitimate hosts only do this when their address changes; "
                    "a sustained burst is characteristic of ARP poisoning tooling."
                ),
            }
        )

    return events


# ==========================================================================
# 6. Public entry point
# ==========================================================================
def extract_features(
    pcap_path: str | Path,
    config: DetectionConfig | None = None,
    scenario: str | None = None,
) -> Tuple[pd.DataFrame, List[Dict[str, Any]]]:
    """Run the full feature-extraction pipeline on one capture.

    Returns ``(flows_dataframe, arp_events)``.
    """
    config = config or DetectionConfig()
    pcap_path = Path(pcap_path)

    flows, arp_records = build_flows(
        iter_packets(pcap_path), idle_timeout=config.flow_idle_timeout
    )

    rows: List[Dict[str, Any]] = []
    for flow in flows:
        row = flow_features(flow)
        row.update(
            {
                "flow_key": flow.key,
                "scenario": scenario or pcap_path.stem,
                "src_ip": flow.src_ip,
                "dst_ip": flow.dst_ip,
                "src_port": flow.src_port,
                "dst_port": flow.dst_port,
                "proto": flow.proto,
                "proto_name": flow.proto_name,
                "start_ts": flow.start_ts,
                "end_ts": flow.last_ts,
                "tcp_flags_summary": "".join(
                    sorted({_flag_letters(p[4]) for p in flow.packets if p[4]})
                ) or "-",
            }
        )
        rows.append(row)

    rows = window_features(rows, config.window_seconds)

    for row in rows:
        row.setdefault("window", 0)
        for key, default in _WINDOW_DEFAULTS.items():
            row.setdefault(key, default)

    df = pd.DataFrame(rows)
    if df.empty:
        df = pd.DataFrame(columns=META_COLUMNS + FEATURE_COLUMNS)

    arp_events = analyse_arp(arp_records, config)
    return df, arp_events


def _flag_letters(flags: int) -> str:
    letters = "".join(ch for bit, ch in FLAG_NAMES if flags & bit)
    return letters or "-"


# --------------------------------------------------------------------------
# Ground-truth labels
# --------------------------------------------------------------------------
def load_labels(label_path: str | Path) -> pd.DataFrame:
    """Read a label CSV produced by ``data/generate_dataset.py``."""
    path = Path(label_path)
    if not path.exists():
        return pd.DataFrame(columns=["flow_key", "label"])
    df = pd.read_csv(path)
    df["flow_key"] = df["flow_key"].astype(str)
    return df


def attach_labels(df: pd.DataFrame, label_path: str | Path) -> pd.DataFrame:
    """Left-join ground truth onto extracted flows (missing -> benign)."""
    labels = load_labels(label_path)
    if labels.empty:
        out = df.copy()
        out["label"] = BENIGN
        return out
    out = df.merge(labels[["flow_key", "label"]], on="flow_key", how="left")
    out["label"] = out["label"].fillna(BENIGN)
    return out


def pcap_summary(records: Sequence[PacketRecord]) -> Dict[str, Any]:
    """Cheap descriptive statistics used by the dashboard and the report."""
    if not records:
        return {"packets": 0, "duration": 0.0}

    ts = [r.ts for r in records]
    proto_counter = Counter(r.proto_name for r in records)
    talkers = Counter(r.src_ip for r in records if not r.is_arp)
    return {
        "packets": len(records),
        "duration": max(ts) - min(ts),
        "first_ts": min(ts),
        "last_ts": max(ts),
        "protocols": dict(proto_counter),
        "top_sources": dict(talkers.most_common(5)),
        "avg_pps": len(records) / max(max(ts) - min(ts), 1e-3),
    }
