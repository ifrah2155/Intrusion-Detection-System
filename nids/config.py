"""Tunable configuration.

Every threshold used by the detection engine lives here so that a reviewer can
see, in one place, exactly what the system considers suspicious. The CLI can
override any of them, which is what makes the "ambiguous case" discussion in
the report reproducible.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any, Dict


@dataclass
class DetectionConfig:
    """Thresholds for the signature layer and the hybrid fusion stage."""

    # ---- Flow reconstruction -------------------------------------------
    flow_idle_timeout: float = 60.0
    """Seconds of silence after which a 5-tuple is closed and a new flow begins."""

    # ---- Aggregation window --------------------------------------------
    window_seconds: float = 10.0
    """Sliding bucket size for host-behaviour features (scan/flood evidence)."""

    # ---- R-001 vertical port scan ---------------------------------------
    scan_unique_ports: int = 15
    scan_syn_ratio: float = 0.60

    # ---- R-002 horizontal port scan --------------------------------------
    scan_horizontal_hosts: int = 10

    # ---- R-003 SYN flood -------------------------------------------------
    syn_flood_pps: float = 100.0          # single source
    syn_flood_fanin_sources: int = 40     # distinct sources hitting one victim
    syn_flood_fanin_pps: float = 150.0    # aggregate pps at the victim

    # ---- R-004 / R-005 UDP + ICMP flood ---------------------------------
    udp_flood_pps: float = 200.0
    icmp_flood_pps: float = 100.0

    # ---- R-006 SSH brute force ------------------------------------------
    brute_force_attempts: int = 8         # connection attempts to :22 per window
    brute_force_max_duration: float = 1.5 # seconds; failed logins are short-lived

    # ---- R-007 ARP cache poisoning --------------------------------------
    arp_min_mac_changes: int = 2
    arp_gratuitous_threshold: int = 5

    # ---- R-008 NULL / XMAS scan ------------------------------------------
    null_xmas_severity: str = "MEDIUM"

    # ---- ML --------------------------------------------------------------
    if_contamination: float = 0.03
    if_n_estimators: int = 300
    rf_n_estimators: int = 400
    rf_max_depth: int | None = None

    ml_anomaly_threshold: float = 0.90
    """Normalised Isolation Forest score at which a flow counts as a *novel*
    anomaly on its own. Calibrated on benign traffic: nothing legitimate in the
    baseline reaches 0.90, so this leg does not fire on normal traffic."""
    ml_only_min_flows: int = 2
    """An ML-only alert must cover at least this many flows (anti-noise)."""
    ml_only_medium_score: float = 0.85
    """Combined ML score above which a rule-less detection is raised to MEDIUM."""

    # ---- Hybrid fusion ---------------------------------------------------
    ml_anomaly_weight: float = 0.45
    signature_weight: float = 0.55
    rf_positive_probability: float = 0.50
    """Supervised probability above which a flow counts as an ML detection."""
    report_min_severity: str = "LOW"
    """Alerts below this severity are recorded but not surfaced to the analyst."""

    # ---- Feature engineering --------------------------------------------
    max_features_for_ml: int = 48
    top_contributors: int = 5
    """How many features to list in a per-alert explanation."""

    extras: Dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")

    @classmethod
    def load(cls, path: str | Path) -> "DetectionConfig":
        payload = json.loads(Path(path).read_text(encoding="utf-8"))
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in payload.items() if k in known})

    def with_overrides(self, **overrides: Any) -> "DetectionConfig":
        """Return a copy with selected fields replaced (ignores ``None``)."""
        clean = {k: v for k, v in overrides.items() if v is not None and k in self.to_dict()}
        return DetectionConfig(**{**self.to_dict(), **clean})


# --------------------------------------------------------------------------
# Filesystem layout
# --------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
PCAP_DIR = DATA_DIR / "pcaps"
LABEL_DIR = DATA_DIR / "labels"
MODEL_DIR = PROJECT_ROOT / "models"
RESULTS_DIR = PROJECT_ROOT / "results"

for _d in (DATA_DIR, PCAP_DIR, LABEL_DIR, MODEL_DIR, RESULTS_DIR):
    _d.mkdir(parents=True, exist_ok=True)


DEFAULT_SCENARIOS = {
    "scenario_1_benign": "Normal traffic baseline (no attacks)",
    "scenario_2_port_scan": "Reconnaissance: vertical + horizontal + NULL scans",
    "scenario_3_dos": "Denial of service: SYN / UDP / ICMP floods",
    "scenario_4_brute_force": "SSH / RDP credential brute force",
    "scenario_5_ambiguous": "Authorised scan, slow scan and bulk backup (hard cases)",
    "scenario_6_mitm_arp": "ARP cache poisoning / man-in-the-middle",
}
