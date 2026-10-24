"""Unit tests for packet/flow feature extraction."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nids.features import (
    PacketRecord,
    build_flows,
    canonical_key,
    flow_features,
    window_features,
)


def rec(ts, src, dst, sport, dport, proto=6, length=100, payload=0, flags=0):
    return PacketRecord(ts=ts, src_ip=src, dst_ip=dst, src_port=sport,
                        dst_port=dport, proto=proto, length=length,
                        payload_len=payload, flags=flags)


# --------------------------------------------------------------------------
def test_canonical_key_is_direction_independent():
    a = canonical_key(6, "10.0.0.1", 40000, "10.0.0.2", 80)
    b = canonical_key(6, "10.0.0.2", 80, "10.0.0.1", 40000)
    assert a == b


def test_canonical_key_distinguishes_protocols():
    assert canonical_key(6, "a", 1, "b", 2) != canonical_key(17, "a", 1, "b", 2)


# --------------------------------------------------------------------------
def test_build_flows_groups_both_directions_into_one_flow():
    packets = [
        rec(0.0, "10.0.0.1", "10.0.0.2", 40000, 80, flags=0x02),
        rec(0.1, "10.0.0.2", "10.0.0.1", 80, 40000, flags=0x12),
        rec(0.2, "10.0.0.1", "10.0.0.2", 40000, 80, flags=0x10),
    ]
    flows, arp = build_flows(packets)
    assert len(flows) == 1
    assert arp == []
    assert flow_features(flows[0])["total_packets"] == 3


def test_build_flows_splits_after_idle_timeout():
    packets = [
        rec(0.0, "10.0.0.1", "10.0.0.2", 40000, 80),
        rec(500.0, "10.0.0.1", "10.0.0.2", 40000, 80),
    ]
    flows, _ = build_flows(packets, idle_timeout=60.0)
    assert len(flows) == 2


def test_arp_packets_are_pulled_out_of_the_flow_table():
    packets = [rec(0.0, "10.0.0.1", "10.0.0.2", 0, 0, proto=0)]
    packets[0].is_arp = True
    packets[0].arp_op = 2
    packets[0].arp_src_ip = "10.0.0.1"
    packets[0].arp_src_mac = "aa:aa:aa:aa:aa:aa"

    flows, arp = build_flows(packets)
    assert flows == []
    assert len(arp) == 1


# --------------------------------------------------------------------------
def test_failed_handshake_is_detected_for_a_lone_syn():
    packets = [rec(0.0, "10.0.0.66", "10.0.0.10", 40000, 22, flags=0x02)]
    flows, _ = build_flows(packets)
    features = flow_features(flows[0])

    assert features["has_syn"] == 1
    assert features["has_synack"] == 0
    assert features["handshake_completed"] == 0
    assert features["failed_handshake"] == 1
    assert features["syn_ratio"] == 1.0


def test_completed_handshake_is_not_a_failed_handshake():
    packets = [
        rec(0.0, "10.0.0.1", "10.0.0.2", 40000, 80, flags=0x02),
        rec(0.01, "10.0.0.2", "10.0.0.1", 80, 40000, flags=0x12),
        rec(0.02, "10.0.0.1", "10.0.0.2", 40000, 80, flags=0x10),
    ]
    flows, _ = build_flows(packets)
    features = flow_features(flows[0])
    assert features["handshake_completed"] == 1
    assert features["failed_handshake"] == 0


def test_null_and_xmas_flags_are_flagged():
    null_flow, _ = build_flows([rec(0.0, "a", "b", 1000, 80, flags=0x00)])
    xmas_flow, _ = build_flows([rec(0.0, "a", "b", 1000, 80, flags=0x29)])  # FIN|PSH|URG

    assert flow_features(null_flow[0])["null_scan"] == 1
    assert flow_features(xmas_flow[0])["xmas_scan"] == 1


# --------------------------------------------------------------------------
def test_window_features_count_distinct_ports_per_source():
    rows = [
        {"src_ip": "10.0.0.66", "dst_ip": "10.0.0.10", "dst_port": 1000 + i,
         "start_ts": 12.0, "total_packets": 1, "syn_cnt": 1, "failed_handshake": 1}
        for i in range(20)
    ]
    out = window_features(rows, window_seconds=10.0)
    assert out[0]["src_unique_dst_ports_win"] == 20
    assert out[0]["src_failed_handshakes_win"] == 20
    assert out[0]["src_flow_count_win"] == 20


def test_window_features_are_scoped_to_the_time_bucket():
    early = {"src_ip": "10.0.0.66", "dst_ip": "10.0.0.10", "dst_port": 80,
             "start_ts": 5.0, "total_packets": 1, "syn_cnt": 1, "failed_handshake": 1}
    late = {"src_ip": "10.0.0.66", "dst_ip": "10.0.0.10", "dst_port": 443,
            "start_ts": 55.0, "total_packets": 1, "syn_cnt": 1, "failed_handshake": 1}

    out = window_features([early, late], window_seconds=10.0)
    assert out[0]["src_unique_dst_ports_win"] == 1
    assert out[1]["src_unique_dst_ports_win"] == 1


def test_peak_pps_uses_the_busiest_second_not_the_window_average():
    rows = [
        {"src_ip": "10.0.0.66", "dst_ip": "10.0.0.10", "dst_port": 80,
         "start_ts": 10.0 + i * 0.01, "total_packets": 10, "syn_cnt": 10,
         "failed_handshake": 1}
        for i in range(30)
    ]
    out = window_features(rows, window_seconds=10.0)
    # All 30 flows land inside one second => 300 packets in that second.
    assert out[0]["src_pps_peak"] == 300
