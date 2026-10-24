"""Unit tests for the signature rule layer."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nids.config import DetectionConfig
from nids.constants import BRUTE_FORCE, DOS, PORT_SCAN
from nids.rules import (
    evaluate_flow,
    rule_horizontal_port_scan,
    rule_null_xmas_scan,
    rule_ssh_brute_force,
    rule_syn_flood_fanin,
    rule_vertical_port_scan,
)

CFG = DetectionConfig()


def flow(**overrides) -> dict:
    """A benign-looking flow with overridable fields."""
    base = {
        "src_ip": "10.0.0.66", "dst_ip": "10.0.0.10",
        "src_port": 40000, "dst_port": 80, "proto": 6, "proto_name": "TCP",
        "total_packets": 10, "duration": 1.0,
        "syn_cnt": 1, "ack_cnt": 8, "handshake_completed": 1,
        "failed_handshake": 0, "has_syn": 1, "has_synack": 1,
        "null_scan": 0, "xmas_scan": 0,
        "proto_tcp": 1, "proto_udp": 0, "proto_icmp": 0,
        "src_flow_count_win": 1, "src_unique_dst_hosts_win": 1,
        "src_unique_dst_ports_win": 1, "src_port_entropy_win": 0.0,
        "src_pkt_count_win": 10, "src_syn_pkts_win": 1, "src_pps_peak": 10.0,
        "src_syn_ratio_win": 0.1, "src_failed_handshakes_win": 0,
        "src_ssh_attempts_win": 0,
        "dst_unique_src_hosts_win": 1, "dst_pkt_count_win": 10,
        "dst_pps_peak": 10.0, "dst_syn_ratio_win": 0.1,
        "payload_bytes": 500,
    }
    base.update(overrides)
    return base


def probe(**overrides) -> dict:
    """An unanswered SYN probe."""
    base = dict(syn_cnt=1, ack_cnt=0, handshake_completed=0, failed_handshake=1,
                has_synack=0, syn_ratio=1.0, src_syn_ratio_win=1.0)
    base.update(overrides)
    return flow(**base)


# --------------------------------------------------------------------------
def test_r001_fires_above_the_port_threshold():
    row = probe(src_unique_dst_ports_win=CFG.scan_unique_ports + 5,
                src_syn_ratio_win=0.95, src_failed_handshakes_win=20)
    hit = rule_vertical_port_scan(row, CFG)
    assert hit is not None
    assert hit.category == PORT_SCAN
    assert hit.evidence["observed_unique_ports"] == CFG.scan_unique_ports + 5


def test_r001_does_not_fire_below_the_port_threshold():
    row = probe(src_unique_dst_ports_win=CFG.scan_unique_ports - 1,
                src_syn_ratio_win=0.95, src_failed_handshakes_win=20)
    assert rule_vertical_port_scan(row, CFG) is None


def test_r001_ignores_completed_sessions():
    """A busy client opening many ports is not a scan if the handshakes finish."""
    row = flow(src_unique_dst_ports_win=40, src_syn_ratio_win=0.95,
               src_failed_handshakes_win=0)
    assert rule_vertical_port_scan(row, CFG) is None


def test_r002_horizontal_scan():
    row = probe(src_unique_dst_hosts_win=25, src_unique_dst_ports_win=1)
    hit = rule_horizontal_port_scan(row, CFG)
    assert hit is not None
    assert hit.rule_id == "R-002"


def test_r002_requires_a_narrow_port_set():
    row = probe(src_unique_dst_hosts_win=25, src_unique_dst_ports_win=9)
    assert rule_horizontal_port_scan(row, CFG) is None


def test_r003_syn_flood_fanin():
    row = probe(dst_unique_src_hosts_win=70, dst_syn_ratio_win=0.95,
                dst_pps_peak=400.0)
    hit = rule_syn_flood_fanin(row, CFG)
    assert hit is not None
    assert hit.severity == "CRITICAL"
    assert hit.entity_kind == "destination"


def test_r003_does_not_fire_for_completed_sessions():
    """Regression: benign sessions opening with a SYN must not join a flood."""
    row = flow(dst_unique_src_hosts_win=70, dst_syn_ratio_win=0.95,
               dst_pps_peak=400.0, handshake_completed=1)
    assert rule_syn_flood_fanin(row, CFG) is None


def test_r006_brute_force_needs_several_short_sessions():
    hit = rule_ssh_brute_force(
        flow(dst_port=22, src_ssh_attempts_win=12, duration=0.2, total_packets=6), CFG)
    assert hit is not None
    assert hit.category == BRUTE_FORCE


def test_r006_ignores_one_long_admin_session():
    row = flow(dst_port=22, src_ssh_attempts_win=12, duration=45.0, total_packets=400)
    assert rule_ssh_brute_force(row, CFG) is None


def test_r008_null_and_xmas():
    null_hit = rule_null_xmas_scan(flow(null_scan=1), CFG)
    xmas_hit = rule_null_xmas_scan(flow(xmas_scan=1), CFG)
    assert null_hit is not None and "NULL" in null_hit.rule_name
    assert xmas_hit is not None and "XMAS" in xmas_hit.rule_name


def test_evaluate_flow_returns_every_matching_rule():
    # A high-rate single-source SYN burst satisfies both R-001 and R-003b.
    row = probe(src_unique_dst_ports_win=30, src_unique_dst_hosts_win=1,
                src_syn_ratio_win=0.95, src_failed_handshakes_win=30,
                src_pps_peak=500.0)
    rule_ids = {hit.rule_id for hit in evaluate_flow(row, CFG)}
    assert {"R-001", "R-003b"}.issubset(rule_ids)


def test_vertical_and_horizontal_rules_are_mutually_exclusive():
    """R-002 requires a narrow port set, R-001 requires a wide one."""
    vertical = probe(src_unique_dst_ports_win=30, src_unique_dst_hosts_win=1,
                     src_failed_handshakes_win=30)
    assert rule_vertical_port_scan(vertical, CFG) is not None
    assert rule_horizontal_port_scan(vertical, CFG) is None

    horizontal = probe(src_unique_dst_ports_win=1, src_unique_dst_hosts_win=30,
                       src_failed_handshakes_win=30)
    assert rule_horizontal_port_scan(horizontal, CFG) is not None
    assert rule_vertical_port_scan(horizontal, CFG) is None


def test_benign_flow_triggers_nothing():
    assert evaluate_flow(flow(), CFG) == []


def test_every_hit_carries_an_explanation_and_evidence():
    row = probe(src_unique_dst_ports_win=30, src_syn_ratio_win=0.95,
                src_failed_handshakes_win=30)
    for hit in evaluate_flow(row, CFG):
        assert hit.explanation
        assert hit.evidence
        assert 0.0 <= hit.confidence <= 1.0
