"""Tests for the hybrid fusion engine, ARP analysis and end-to-end behaviour."""

from __future__ import annotations

import sys
from pathlib import Path

import pandas as pd
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from nids.config import PCAP_DIR, DetectionConfig
from nids.constants import BENIGN, PORT_SCAN
from nids.engine import HybridEngine
from nids.features import PacketRecord, analyse_arp, FEATURE_COLUMNS
from nids.pipeline import analyse_pcap, load_model

CFG = DetectionConfig()
PKG_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
def make_flow(index: int = 0, **overrides) -> dict:
    row = {column: 0 for column in FEATURE_COLUMNS}
    row.update({
        "flow_key": f"6|10.0.0.66:{40000 + index}|10.0.0.10:1",
        "scenario": "unit",
        "src_ip": "10.0.0.66",
        "dst_ip": "10.0.0.10",
        "src_port": 40000 + index,
        "dst_port": 1,
        "proto": 6,
        "proto_name": "TCP",
        "start_ts": 20.0 + index * 0.01,
        "end_ts": 20.0 + index * 0.01,
        "window": 2,
        "tcp_flags_summary": "S",
        "label": PORT_SCAN,
        "total_packets": 1,
        "syn_cnt": 1,
        "failed_handshake": 1,
        "proto_tcp": 1,
        "src_unique_dst_ports_win": 40,
        "src_unique_dst_hosts_win": 1,
        "src_syn_ratio_win": 1.0,
        "src_failed_handshakes_win": 40,
        "src_flow_count_win": 40,
        "src_pps_peak": 40.0,
    })
    row.update(overrides)
    return row


def test_signature_incident_groups_many_flows_into_one_alert():
    flows = pd.DataFrame([make_flow(i) for i in range(40)])
    result = HybridEngine(CFG, model=None).analyse(flows)

    scan_alerts = [a for a in result.alerts if a.rule_id == "R-001"]
    assert len(scan_alerts) == 1
    assert scan_alerts[0].flow_count == 40
    assert scan_alerts[0].entity == "10.0.0.66"


def test_alert_explains_itself():
    flows = pd.DataFrame([make_flow(i) for i in range(40)])
    alert = HybridEngine(CFG, model=None).analyse(flows).alerts[0]

    assert alert.explanation
    assert "120" not in alert.explanation  # sanity: no placeholder leakage
    assert alert.evidence["observed_unique_ports"] == 40
    assert alert.iso_time


def test_severity_is_not_lowered_when_ml_disagrees():
    """A probabilistic model must never demote deterministic evidence."""
    flows = pd.DataFrame([make_flow(i) for i in range(40)])
    result = HybridEngine(CFG, model=None).analyse(flows)
    alert = result.alerts[0]

    assert alert.detection_layers == ["signature"]
    assert alert.ml_agrees is False
    assert "did not corroborate" in alert.ml_note
    # R-001 is HIGH; without ML support the severity stands, the confidence drops.
    assert alert.severity == "HIGH"
    assert alert.confidence < 0.9


def test_benign_flow_produces_no_alerts():
    flows = pd.DataFrame([make_flow(0, label=BENIGN, src_unique_dst_ports_win=1,
                                    src_syn_ratio_win=0.1, failed_handshake=0,
                                    syn_cnt=0, src_failed_handshakes_win=0,
                                    total_packets=10)])
    assert HybridEngine(CFG, model=None).analyse(flows).alerts == []


# --------------------------------------------------------------------------
def _arp(mac: str, ip: str, ts: float, op: int = 2, dst_ip: str | None = None) -> PacketRecord:
    return PacketRecord(ts=ts, is_arp=True, arp_op=op, arp_src_ip=ip,
                        arp_src_mac=mac, arp_dst_ip=dst_ip if dst_ip is not None else ip)


def test_arp_conflict_is_detected():
    records = [
        _arp("00:11:22:33:44:01", "10.0.0.1", 10.0),
        _arp("aa:bb:cc:dd:ee:ff", "10.0.0.1", 15.0),
        _arp("aa:bb:cc:dd:ee:ff", "10.0.0.1", 16.0),
    ]
    events = analyse_arp(records, CFG)

    assert len(events) == 1
    assert events[0]["category"] == "mitm"
    assert events[0]["evidence"]["suspect_mac"] == "aa:bb:cc:dd:ee:ff"
    assert events[0]["evidence"]["original_mac"] == "00:11:22:33:44:01"


def test_single_mac_binding_is_not_an_anomaly():
    # Normal ARP replies (psrc != pdst), one stable MAC per IP.
    records = [_arp("00:11:22:33:44:01", "10.0.0.1", 10.0 + i, dst_ip="10.0.0.21")
               for i in range(5)]
    assert analyse_arp(records, CFG) == []


# --------------------------------------------------------------------------
@pytest.mark.skipif(not (PCAP_DIR / "scenario_1_benign.pcap").exists(),
                    reason="dataset not generated")
def test_benign_capture_raises_no_alerts_end_to_end():
    """The headline promise: a clean baseline produces zero alerts."""
    result = analyse_pcap(PCAP_DIR / "scenario_1_benign.pcap", config=CFG,
                          model=load_model())
    assert result.alerts == []


@pytest.mark.skipif(not (PCAP_DIR / "scenario_2_port_scan.pcap").exists(),
                    reason="dataset not generated")
def test_port_scan_capture_is_detected_end_to_end():
    result = analyse_pcap(PCAP_DIR / "scenario_2_port_scan.pcap", config=CFG,
                          model=load_model())
    rule_ids = {a.rule_id for a in result.alerts}
    assert "R-001" in rule_ids
    assert "R-002" in rule_ids
    assert "R-008" in rule_ids


@pytest.mark.skipif(not (PCAP_DIR / "scenario_6_mitm_arp.pcap").exists(),
                    reason="dataset not generated")
def test_arp_spoofing_capture_is_detected_end_to_end():
    result = analyse_pcap(PCAP_DIR / "scenario_6_mitm_arp.pcap", config=CFG,
                          model=load_model())
    mitm = [a for a in result.alerts if a.category == "mitm"]
    assert mitm, "ARP poisoning was not detected"
    assert mitm[0].rule_id == "R-007"
