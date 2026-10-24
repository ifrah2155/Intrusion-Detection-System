"""Deterministic signature / rule layer.

Each rule inspects one flow *plus* its host-behaviour window features and, if
the traffic matches, returns a :class:`RuleHit` explaining precisely which
observable crossed which threshold. Nothing is a black box: every hit carries
an ``evidence`` dictionary with the observed value, the configured threshold
and the margin, which is what the report renders to the analyst.

Rules are deliberately written as small, single-purpose predicates so that a
threshold can be argued about (and tuned) in isolation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Union

from .config import DetectionConfig
from .constants import (
    DOS,
    BRUTE_FORCE,
    MITM,
    PORT_SCAN,
)

RowLike = Union[Dict[str, Any], Any]  # pandas Series also works


@dataclass
class RuleHit:
    """A single rule firing against a single flow."""

    rule_id: str
    rule_name: str
    category: str
    severity: str
    confidence: float
    entity: str
    entity_kind: str
    explanation: str
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "entity": self.entity,
            "entity_kind": self.entity_kind,
            "explanation": self.explanation,
            "evidence": self.evidence,
        }


def _g(row: RowLike, key: str, default: Any = 0) -> Any:
    """Read a value from either a dict or a pandas Series."""
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        value = row[key]
    except Exception:
        return default
    if value is None:
        return default
    try:
        if value != value:  # NaN
            return default
    except Exception:
        pass
    return value


def _f(row: RowLike, key: str, default: float = 0.0) -> float:
    try:
        return float(_g(row, key, default))
    except (TypeError, ValueError):
        return default


def _is_probe(row: RowLike) -> bool:
    """True when this flow looks like an unanswered TCP probe."""
    return _f(row, "syn_cnt") > 0 and _f(row, "handshake_completed") == 0


def _bump(base: float, observed: float, threshold: float, cap: float = 0.99) -> float:
    """Confidence that grows with the margin over threshold, never above ``cap``."""
    if threshold <= 0:
        return base
    excess = (observed - threshold) / threshold
    return float(min(cap, base + max(0.0, excess) * 0.15))


# ==========================================================================
# Individual rules
# ==========================================================================
def rule_vertical_port_scan(row: RowLike, cfg: DetectionConfig) -> Optional[RuleHit]:
    """R-001 - one source touching many destination ports with unanswered SYNs."""
    if not _is_probe(row):
        return None

    ports = _f(row, "src_unique_dst_ports_win")
    syn_ratio = _f(row, "src_syn_ratio_win")
    failed = _f(row, "src_failed_handshakes_win")

    if ports < cfg.scan_unique_ports or syn_ratio < cfg.scan_syn_ratio or failed < 5:
        return None

    confidence = _bump(0.72, ports, cfg.scan_unique_ports)
    return RuleHit(
        rule_id="R-001",
        rule_name="VERTICAL_PORT_SCAN",
        category=PORT_SCAN,
        severity="HIGH",
        confidence=confidence,
        entity=str(_g(row, "src_ip", "")),
        entity_kind="source",
        explanation=(
            f"{_g(row, 'src_ip')} sent TCP SYN probes to {int(ports)} distinct "
            f"destination ports within a {cfg.window_seconds:.0f}s window "
            f"(threshold {cfg.scan_unique_ports}), of which {int(failed)} never "
            f"received a SYN/ACK. Sweeping this many ports without completing "
            "handshakes is the classic signature of a vertical port scan."
        ),
        evidence={
            "observed_unique_ports": int(ports),
            "threshold_unique_ports": cfg.scan_unique_ports,
            "observed_syn_ratio": round(syn_ratio, 3),
            "threshold_syn_ratio": cfg.scan_syn_ratio,
            "unanswered_probes": int(failed),
            "port_entropy": round(_f(row, "src_port_entropy_win"), 3),
        },
    )


def rule_horizontal_port_scan(row: RowLike, cfg: DetectionConfig) -> Optional[RuleHit]:
    """R-002 - one source probing the same port across many hosts."""
    if not _is_probe(row):
        return None

    hosts = _f(row, "src_unique_dst_hosts_win")
    ports = _f(row, "src_unique_dst_ports_win")
    syn_ratio = _f(row, "src_syn_ratio_win")

    if hosts < cfg.scan_horizontal_hosts or ports > 3 or syn_ratio < 0.5:
        return None

    confidence = _bump(0.66, hosts, cfg.scan_horizontal_hosts)
    return RuleHit(
        rule_id="R-002",
        rule_name="HORIZONTAL_PORT_SCAN",
        category=PORT_SCAN,
        severity="HIGH",
        confidence=confidence,
        entity=str(_g(row, "src_ip", "")),
        entity_kind="source",
        explanation=(
            f"{_g(row, 'src_ip')} contacted {int(hosts)} distinct hosts on only "
            f"{int(ports)} distinct port(s) (threshold {cfg.scan_horizontal_hosts} "
            "hosts). Reaching the same service across a whole subnet is a "
            "horizontal scan used to enumerate which hosts expose that service."
        ),
        evidence={
            "observed_unique_hosts": int(hosts),
            "threshold_unique_hosts": cfg.scan_horizontal_hosts,
            "observed_unique_ports": int(ports),
            "target_port": int(_f(row, "dst_port")),
        },
    )


def rule_syn_flood_fanin(row: RowLike, cfg: DetectionConfig) -> Optional[RuleHit]:
    """R-003 - distributed SYN flood: many sources converging on one victim."""
    # Only unanswered probes belong to a flood. A legitimate session that also
    # opens with a SYN (then completes its handshake) must not be swept into
    # the incident.
    if not _is_probe(row):
        return None

    sources = _f(row, "dst_unique_src_hosts_win")
    dst_syn_ratio = _f(row, "dst_syn_ratio_win")
    dst_pps = _f(row, "dst_pps_peak")

    if (
        sources < cfg.syn_flood_fanin_sources
        or dst_syn_ratio < 0.6
        or dst_pps < cfg.syn_flood_fanin_pps
    ):
        return None

    confidence = _bump(0.80, sources, cfg.syn_flood_fanin_sources, cap=0.99)
    return RuleHit(
        rule_id="R-003",
        rule_name="SYN_FLOOD_FANIN",
        category=DOS,
        severity="CRITICAL",
        confidence=confidence,
        entity=str(_g(row, "dst_ip", "")),
        entity_kind="destination",
        explanation=(
            f"{_g(row, 'dst_ip')} received {int(sources)} distinct source "
            f"connections in {cfg.window_seconds:.0f}s ({dst_pps:.0f} pkt/s), "
            f"{dst_syn_ratio * 100:.0f}% of which were SYN packets that never "
            "completed a handshake. A high fan-in of half-open connections "
            "exhausts the victim's backlog and is a distributed SYN flood."
        ),
        evidence={
            "observed_distinct_sources": int(sources),
            "threshold_distinct_sources": cfg.syn_flood_fanin_sources,
            "victim_pps": round(dst_pps, 1),
            "threshold_pps": cfg.syn_flood_fanin_pps,
            "victim_syn_ratio": round(dst_syn_ratio, 3),
            "target_port": int(_f(row, "dst_port")),
        },
    )


def rule_syn_flood_single(row: RowLike, cfg: DetectionConfig) -> Optional[RuleHit]:
    """R-003b - single-source SYN flood."""
    if not _is_probe(row):
        return None

    pps = _f(row, "src_pps_peak")
    syn_ratio = _f(row, "src_syn_ratio_win")

    if pps < cfg.syn_flood_pps or syn_ratio < 0.8:
        return None

    confidence = _bump(0.75, pps, cfg.syn_flood_pps)
    return RuleHit(
        rule_id="R-003b",
        rule_name="SYN_FLOOD_SINGLE_SOURCE",
        category=DOS,
        severity="HIGH",
        confidence=confidence,
        entity=str(_g(row, "src_ip", "")),
        entity_kind="source",
        explanation=(
            f"{_g(row, 'src_ip')} emitted {pps:.0f} packets/s "
            f"(threshold {cfg.syn_flood_pps:.0f}) with {syn_ratio * 100:.0f}% of "
            "them being bare SYN segments. Sustained SYN-only output at this rate "
            "cannot come from a normal TCP stack, which waits for each handshake."
        ),
        evidence={
            "observed_pps": round(pps, 1),
            "threshold_pps": cfg.syn_flood_pps,
            "observed_syn_ratio": round(syn_ratio, 3),
            "threshold_syn_ratio": 0.8,
        },
    )


def rule_udp_flood(row: RowLike, cfg: DetectionConfig) -> Optional[RuleHit]:
    """R-004 - UDP flood."""
    if _f(row, "proto_udp") != 1:
        return None

    pps = _f(row, "src_pps_peak")
    if pps < cfg.udp_flood_pps:
        return None

    confidence = _bump(0.74, pps, cfg.udp_flood_pps)
    return RuleHit(
        rule_id="R-004",
        rule_name="UDP_FLOOD",
        category=DOS,
        severity="HIGH",
        confidence=confidence,
        entity=str(_g(row, "src_ip", "")),
        entity_kind="source",
        explanation=(
            f"{_g(row, 'src_ip')} generated {pps:.0f} UDP packets/s "
            f"(threshold {cfg.udp_flood_pps:.0f}) towards "
            f"{_g(row, 'dst_ip')}:{int(_f(row, 'dst_port'))}. Connectionless "
            "flooding at this rate saturates the link and forces the victim to "
            "generate ICMP port-unreachable replies, amplifying the load."
        ),
        evidence={
            "observed_pps": round(pps, 1),
            "threshold_pps": cfg.udp_flood_pps,
            "target_port": int(_f(row, "dst_port")),
            "avg_payload_bytes": round(_f(row, "payload_bytes") / max(_f(row, "total_packets"), 1), 1),
        },
    )


def rule_icmp_flood(row: RowLike, cfg: DetectionConfig) -> Optional[RuleHit]:
    """R-005 - ICMP echo flood."""
    if _f(row, "proto_icmp") != 1:
        return None

    pps = _f(row, "src_pps_peak")
    if pps < cfg.icmp_flood_pps:
        return None

    confidence = _bump(0.72, pps, cfg.icmp_flood_pps)
    return RuleHit(
        rule_id="R-005",
        rule_name="ICMP_FLOOD",
        category=DOS,
        severity="HIGH",
        confidence=confidence,
        entity=str(_g(row, "src_ip", "")),
        entity_kind="source",
        explanation=(
            f"{_g(row, 'src_ip')} sent {pps:.0f} ICMP packets/s "
            f"(threshold {cfg.icmp_flood_pps:.0f}) to {_g(row, 'dst_ip')}. "
            "Normal diagnostics send a handful of echo requests; this rate "
            "indicates a ping flood."
        ),
        evidence={
            "observed_pps": round(pps, 1),
            "threshold_pps": cfg.icmp_flood_pps,
            "packets": int(_f(row, "total_packets")),
        },
    )


def rule_ssh_brute_force(row: RowLike, cfg: DetectionConfig) -> Optional[RuleHit]:
    """R-006 - many short-lived login attempts against SSH/RDP."""
    dst_port = int(_f(row, "dst_port"))
    if dst_port not in (22, 3389):
        return None

    attempts = _f(row, "src_ssh_attempts_win")
    if attempts < cfg.brute_force_attempts:
        return None

    # Failed logins are short: the server accepts the TCP connection, rejects
    # the credential and the client tears the session down almost immediately.
    short = _f(row, "duration") <= cfg.brute_force_max_duration or _f(row, "total_packets") <= 8
    if not short:
        return None

    confidence = _bump(0.70, attempts, cfg.brute_force_attempts)
    service = "SSH" if dst_port == 22 else "RDP"
    return RuleHit(
        rule_id="R-006",
        rule_name="CREDENTIAL_BRUTE_FORCE",
        category=BRUTE_FORCE,
        severity="HIGH",
        confidence=confidence,
        entity=str(_g(row, "src_ip", "")),
        entity_kind="source",
        explanation=(
            f"{_g(row, 'src_ip')} opened {int(attempts)} short-lived {service} "
            f"sessions to {_g(row, 'dst_ip')}:{dst_port} within "
            f"{cfg.window_seconds:.0f}s (threshold {cfg.brute_force_attempts}). "
            f"Each session lasted {_f(row, 'duration'):.2f}s. Repeated rapid "
            "connect/teardown cycles against an authentication service indicate "
            "an automated credential-guessing attack."
        ),
        evidence={
            "observed_attempts": int(attempts),
            "threshold_attempts": cfg.brute_force_attempts,
            "service_port": dst_port,
            "flow_duration": round(_f(row, "duration"), 3),
            "packets_per_attempt": int(_f(row, "total_packets")),
        },
    )


def rule_null_xmas_scan(row: RowLike, cfg: DetectionConfig) -> Optional[RuleHit]:
    """R-008 - TCP probes with no flags (NULL) or FIN+PSH+URG (XMAS)."""
    is_null = _f(row, "null_scan") == 1
    is_xmas = _f(row, "xmas_scan") == 1
    if not (is_null or is_xmas):
        return None

    kind = "NULL" if is_null else "XMAS"
    return RuleHit(
        rule_id="R-008",
        rule_name=f"{kind}_SCAN",
        category=PORT_SCAN,
        severity=cfg.null_xmas_severity,
        confidence=0.80,
        entity=str(_g(row, "src_ip", "")),
        entity_kind="source",
        explanation=(
            f"{_g(row, 'src_ip')} sent a TCP segment to {_g(row, 'dst_ip')}:"
            f"{int(_f(row, 'dst_port'))} with "
            + ("no flags set at all" if is_null else "the illegal FIN+PSH+URG flag combination")
            + f" ({kind} scan). No conforming TCP stack produces this; it is used "
            "to probe firewalls that filter SYN but not other flag patterns."
        ),
        evidence={
            "scan_type": kind,
            "flags": str(_g(row, "tcp_flags_summary", "-")),
            "target_port": int(_f(row, "dst_port")),
        },
    )


FLOW_RULES = (
    rule_vertical_port_scan,
    rule_horizontal_port_scan,
    rule_syn_flood_fanin,
    rule_syn_flood_single,
    rule_udp_flood,
    rule_icmp_flood,
    rule_ssh_brute_force,
    rule_null_xmas_scan,
)


def evaluate_flow(row: RowLike, config: DetectionConfig | None = None) -> List[RuleHit]:
    """Run every flow-level rule against one extracted flow."""
    config = config or DetectionConfig()
    hits: List[RuleHit] = []
    for rule in FLOW_RULES:
        hit = rule(row, config)
        if hit is not None:
            hits.append(hit)
    return hits


def evaluate_dataframe(df, config: DetectionConfig | None = None) -> List[RuleHit]:
    """Run every flow-level rule against every flow in a DataFrame."""
    config = config or DetectionConfig()
    hits: List[RuleHit] = []
    for _, row in df.iterrows():
        hits.extend(evaluate_flow(row, config))
    return hits


RULE_CATALOGUE = [
    {
        "id": "R-001",
        "name": "VERTICAL_PORT_SCAN",
        "category": PORT_SCAN,
        "logic": ">= scan_unique_ports distinct dst ports from one src in window, "
                 "SYN ratio >= scan_syn_ratio, >= 5 unanswered probes",
    },
    {
        "id": "R-002",
        "name": "HORIZONTAL_PORT_SCAN",
        "category": PORT_SCAN,
        "logic": ">= scan_horizontal_hosts distinct dst hosts, <= 3 distinct ports",
    },
    {
        "id": "R-003",
        "name": "SYN_FLOOD_FANIN",
        "category": DOS,
        "logic": ">= syn_flood_fanin_sources distinct sources at one victim, "
                 "victim pps >= syn_flood_fanin_pps, SYN ratio >= 0.6",
    },
    {
        "id": "R-003b",
        "name": "SYN_FLOOD_SINGLE_SOURCE",
        "category": DOS,
        "logic": "src pps >= syn_flood_pps and SYN ratio >= 0.8",
    },
    {
        "id": "R-004",
        "name": "UDP_FLOOD",
        "category": DOS,
        "logic": "UDP and src pps >= udp_flood_pps",
    },
    {
        "id": "R-005",
        "name": "ICMP_FLOOD",
        "category": DOS,
        "logic": "ICMP and src pps >= icmp_flood_pps",
    },
    {
        "id": "R-006",
        "name": "CREDENTIAL_BRUTE_FORCE",
        "category": BRUTE_FORCE,
        "logic": ">= brute_force_attempts sessions to :22/:3389 in window, "
                 "each <= brute_force_max_duration or <= 8 packets",
    },
    {
        "id": "R-007",
        "name": "ARP_CACHE_POISONING",
        "category": MITM,
        "logic": "one IP announced by >= arp_min_mac_changes distinct MACs",
    },
    {
        "id": "R-008",
        "name": "NULL_XMAS_SCAN",
        "category": PORT_SCAN,
        "logic": "TCP flags == 0 (NULL) or FIN+PSH+URG (XMAS)",
    },
]
