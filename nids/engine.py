"""Hybrid detection engine: fuses the signature layer with the ML layer.

Design goals
------------
* **One alert per incident, not per packet.** A 120-port scan produces 120 flow
  hits; the analyst gets *one* alert that says "172.16.0.66 touched 120 ports
  in 10 s", with the contributing flows attached.
* **Every alert explains itself.** Each alert carries the rule(s) that fired,
  the observed-vs-threshold values, the ML scores, the top contributing
  features and a plain-English narrative.
* **Disagreement is surfaced, not hidden.** When the rule layer fires but the
  ML layer does not (or vice versa) the alert says so and the confidence drops,
  which is precisely the signal an analyst needs to triage.
"""

from __future__ import annotations

import datetime as _dt
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

import numpy as np
import pandas as pd

from .config import DetectionConfig
from .constants import BENIGN, SEVERITY_ORDER, Severity
from .ml import HybridMLModel
from .rules import RuleHit, evaluate_flow

# Rules whose evidence is attributed to the *victim* rather than the source.
DESTINATION_RULES = {"R-003"}

# Rules that are inherently "host behaviour" and therefore aggregated into a
# single incident instead of one alert per flow.
INCIDENT_RULES = {"R-001", "R-002", "R-003", "R-003b", "R-004", "R-005", "R-006"}


@dataclass
class Alert:
    """A single analyst-facing detection."""

    alert_id: str
    timestamp: float
    category: str
    severity: str
    confidence: float
    rule_id: str
    rule_name: str
    entity: str
    entity_kind: str
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    proto: str = ""
    flow_count: int = 1
    flow_keys: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    explanation: str = ""
    detection_layers: List[str] = field(default_factory=list)
    ml_if_score: float = 0.0
    ml_rf_prob: float = 0.0
    ml_agrees: bool = False
    ml_note: str = ""
    top_features: List[Dict[str, Any]] = field(default_factory=list)
    ground_truth: Optional[str] = None
    scenario: str = ""
    window: int = 0

    # ------------------------------------------------------------------
    @property
    def iso_time(self) -> str:
        return _dt.datetime.fromtimestamp(self.timestamp, tz=_dt.timezone.utc).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    @property
    def is_true_positive(self) -> Optional[bool]:
        if self.ground_truth is None:
            return None
        return self.ground_truth != BENIGN

    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "time_utc": self.iso_time,
            "scenario": self.scenario,
            "category": self.category,
            "severity": self.severity,
            "confidence": round(self.confidence, 3),
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "entity": self.entity,
            "entity_kind": self.entity_kind,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "proto": self.proto,
            "flow_count": self.flow_count,
            "flow_keys": self.flow_keys,
            "detection_layers": self.detection_layers,
            "ml": {
                "if_score": round(self.ml_if_score, 3),
                "rf_attack_prob": round(self.ml_rf_prob, 3),
                "agrees": self.ml_agrees,
                "note": self.ml_note,
                "top_features": self.top_features,
            },
            "evidence": self.evidence,
            "explanation": self.explanation,
            "ground_truth": self.ground_truth,
            "is_true_positive": self.is_true_positive,
        }


# --------------------------------------------------------------------------
@dataclass
class AnalysisResult:
    alerts: List[Alert]
    flows: pd.DataFrame
    arp_events: List[Dict[str, Any]]
    scenario: str = ""
    pcap: str = ""

    def alerts_frame(self) -> pd.DataFrame:
        if not self.alerts:
            return pd.DataFrame(columns=["alert_id", "time_utc", "category", "severity",
                                         "confidence", "src_ip", "dst_ip", "rule_name",
                                         "flow_count", "detection_layers", "ground_truth"])
        rows = []
        for a in self.alerts:
            rows.append({
                "alert_id": a.alert_id,
                "time_utc": a.iso_time,
                "category": a.category,
                "severity": a.severity,
                "confidence": round(a.confidence, 3),
                "rule_id": a.rule_id,
                "rule_name": a.rule_name,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "dst_port": a.dst_port,
                "proto": a.proto,
                "flow_count": a.flow_count,
                "layers": "+".join(a.detection_layers),
                "ml_if": round(a.ml_if_score, 3),
                "ml_rf": round(a.ml_rf_prob, 3),
                "ground_truth": a.ground_truth,
            })
        return pd.DataFrame(rows)


# --------------------------------------------------------------------------
class HybridEngine:
    """Runs both detection layers and fuses the result."""

    def __init__(self, config: DetectionConfig | None = None,
                 model: Optional[HybridMLModel] = None):
        self.config = config or DetectionConfig()
        self.model = model

    # ------------------------------------------------------------------
    def analyse(self, flows: pd.DataFrame, arp_events: Sequence[Dict[str, Any]] | None = None,
                scenario: str = "", pcap: str = "") -> AnalysisResult:
        arp_events = list(arp_events or [])

        scored = self._score_flows(flows)
        alerts: List[Alert] = []

        # 1. Signature layer -> group per (rule, entity, window)
        groups: Dict[Tuple[str, str, int], List[Tuple[int, RuleHit]]] = defaultdict(list)
        per_flow_hit: Dict[int, List[RuleHit]] = defaultdict(list)

        for idx, row in scored.iterrows():
            for hit in evaluate_flow(row, self.config):
                window = int(row.get("window", 0))
                groups[(hit.rule_id, hit.entity, window)].append((idx, hit))
                per_flow_hit[idx].append(hit)

        for (rule_id, entity, window), members in groups.items():
            alerts.append(self._build_signature_alert(rule_id, entity, window, members, scored))

        # 2. ML-only detections for flows no rule covered
        ml_only = [
            idx for idx, row in scored.iterrows()
            if row.get("ml_verdict", 0) == 1 and idx not in per_flow_hit
        ]
        if ml_only:
            alerts.extend(self._build_ml_alerts(scored.loc[ml_only]))

        # 3. Layer-2 ARP / MITM events
        for event in arp_events:
            alerts.append(self._alert_from_arp(event, scenario))

        # 4. Ordering + filtering
        alerts.sort(key=lambda a: (-SEVERITY_ORDER.get(a.severity, 0), a.timestamp))
        min_rank = SEVERITY_ORDER.get(self.config.report_min_severity.upper(), 0)
        alerts = [a for a in alerts if SEVERITY_ORDER.get(a.severity, 0) >= min_rank]
        for i, alert in enumerate(alerts, start=1):
            alert.alert_id = f"A-{i:04d}"
            alert.scenario = alert.scenario or scenario

        scored = self._mark_covered(scored, alerts)

        # Per-flow record of whether the *signature* layer covered this flow.
        # Needed to score each layer independently in the evaluation.
        scored["signature_hit"] = [1 if idx in per_flow_hit else 0 for idx in scored.index]

        return AnalysisResult(alerts=alerts, flows=scored, arp_events=arp_events,
                              scenario=scenario, pcap=pcap)

    # ------------------------------------------------------------------
    def _score_flows(self, flows: pd.DataFrame) -> pd.DataFrame:
        if flows.empty:
            return flows

        if self.model is not None:
            scored = self.model.predict(flows)
        else:
            scored = flows.assign(
                if_score=0.0, if_anomaly=0, rf_attack_prob=0.0,
                rf_label=BENIGN, ml_score=0.0, ml_verdict=0,
            )

        if "label" not in scored.columns:
            scored["label"] = BENIGN
        return scored

    # ------------------------------------------------------------------
    def _representative(self, group: pd.DataFrame, entity_kind: str) -> pd.Series:
        """Pick the flow that best exhibits the behaviour (most packets)."""
        if group.empty:
            return pd.Series(dtype=object)
        order = group.sort_values("total_packets", ascending=False)
        return order.iloc[0]

    def _build_signature_alert(self, rule_id: str, entity: str, window: int,
                               members: List[Tuple[int, RuleHit]],
                               scored: pd.DataFrame) -> Alert:
        idxs = [i for i, _ in members]
        hits = [h for _, h in members]
        group = scored.loc[idxs]
        lead = hits[0]
        rep = self._representative(group, lead.entity_kind)

        mean_if = float(group["if_score"].mean())
        mean_rf = float(group["rf_attack_prob"].mean())
        ml_score = float(group["ml_score"].mean()) if "ml_score" in group else 0.0
        any_ml_flag = bool((group.get("ml_verdict", pd.Series([0] * len(group))) == 1).any())

        ml_agrees = (
            any_ml_flag
            or mean_if >= self.config.ml_anomaly_threshold
            or mean_rf >= self.config.rf_positive_probability
        )

        rule_conf = float(np.mean([h.confidence for h in hits]))
        if ml_agrees:
            confidence = min(0.99, 0.6 * rule_conf + 0.4 * max(mean_if, mean_rf, ml_score))
        else:
            confidence = min(0.95, 0.85 * rule_conf)

        severity = self._fuse_severity(lead.severity, ml_agrees)

        # Aggregate evidence across the incident, keeping the first hit's
        # thresholds (they are identical for a given rule).
        evidence = dict(lead.evidence)
        evidence["flows_in_incident"] = int(len(group))
        evidence["packets_in_incident"] = int(group["total_packets"].sum())

        layers = ["signature"] + (["ml"] if ml_agrees else [])
        if ml_agrees:
            ml_note = (
                f"ML corroborates: Isolation Forest score {mean_if:.2f}, Random Forest "
                f"attack probability {mean_rf:.2f}."
            )
        else:
            ml_note = (
                f"ML did not corroborate (Isolation Forest {mean_if:.2f}, Random Forest "
                f"{mean_rf:.2f}); alert rests on the deterministic rule alone."
            )

        explanation = lead.explanation
        if ml_agrees:
            explanation += (
                f" The ML layer independently flagged these flows "
                f"(anomaly score {mean_if:.2f}, attack probability {mean_rf:.2f}), "
                "which raises confidence."
            )

        top_features = self._explain(rep)

        return Alert(
            alert_id="",
            timestamp=float(group["start_ts"].min()),
            category=lead.category,
            severity=severity,
            confidence=confidence,
            rule_id=rule_id,
            rule_name=lead.rule_name,
            entity=entity,
            entity_kind=lead.entity_kind,
            src_ip=str(rep.get("src_ip", "")),
            dst_ip=str(rep.get("dst_ip", "")),
            src_port=int(rep.get("src_port", 0)),
            dst_port=int(rep.get("dst_port", 0)),
            proto=str(rep.get("proto_name", "")),
            flow_count=int(len(group)),
            flow_keys=[str(k) for k in group["flow_key"].tolist()],
            evidence=evidence,
            explanation=explanation,
            detection_layers=layers,
            ml_if_score=mean_if,
            ml_rf_prob=mean_rf,
            ml_agrees=ml_agrees,
            ml_note=ml_note,
            top_features=top_features,
            ground_truth=self._majority_label(group),
            window=window,
        )

    # ------------------------------------------------------------------
    def _build_ml_alerts(self, subset: pd.DataFrame) -> List[Alert]:
        """Group ML detections that no rule covered.

        Grouping is by source across the whole capture, not per 10 s window and
        not per guessed class: a deliberately slow attack that emits a handful
        of probes per window is still one incident, and one alert is far more
        useful to an analyst than thirty fragments. The category is the
        majority class prediction, because the classifier's *class* guess is
        less stable than its attack probability.
        """
        alerts: List[Alert] = []

        subset = subset.copy()
        subset["ml_category"] = [
            (str(row.get("rf_label", "anomaly"))
             if float(row.get("rf_attack_prob", 0.0)) >= self.config.rf_positive_probability
             else "anomaly")
            for _, row in subset.iterrows()
        ]

        for src_ip, group in subset.groupby("src_ip", sort=True):
            if len(group) < self.config.ml_only_min_flows:
                continue

            category = str(group["ml_category"].value_counts().index[0])

            rep = self._representative(group, "source")
            mean_if = float(group["if_score"].mean())
            mean_rf = float(group["rf_attack_prob"].mean())
            best_score = float(max(mean_if, mean_rf))
            confidence = float(min(0.90, 0.5 * best_score + 0.25))

            top_features = self._explain(rep)

            explanation = (
                f"No signature matched, but the ML layer scored this traffic as "
                f"'{category}' (Random Forest attack probability {mean_rf:.2f}, "
                f"Isolation Forest anomaly score {mean_if:.2f}) across "
                f"{len(group)} flows. The strongest deviations from the benign "
                f"baseline are: "
                + "; ".join(
                    f"{f['label']} = {f['value']} (z={f['z_score']:+.1f})"
                    for f in top_features[:3]
                )
                + ". This is an ML-only detection: treat it as a lead to "
                "investigate rather than a confirmed intrusion."
            )

            alerts.append(
                Alert(
                    alert_id="",
                    timestamp=float(group["start_ts"].min()),
                    category=str(category),
                    severity="MEDIUM" if best_score >= self.config.ml_only_medium_score else "LOW",
                    confidence=confidence,
                    rule_id="ML-001",
                    rule_name="ML_DETECTION",
                    entity=str(src_ip),
                    entity_kind="source",
                    src_ip=str(rep.get("src_ip", "")),
                    dst_ip=str(rep.get("dst_ip", "")),
                    src_port=int(rep.get("src_port", 0)),
                    dst_port=int(rep.get("dst_port", 0)),
                    proto=str(rep.get("proto_name", "")),
                    flow_count=int(len(group)),
                    flow_keys=[str(k) for k in group["flow_key"].tolist()],
                    evidence={
                        "if_score": round(mean_if, 3),
                        "rf_attack_prob": round(mean_rf, 3),
                        "flows_in_group": int(len(group)),
                        "note": "Supervised/unsupervised ML detection without rule support",
                    },
                    explanation=explanation,
                    detection_layers=["ml"],
                    ml_if_score=mean_if,
                    ml_rf_prob=mean_rf,
                    ml_agrees=True,
                    ml_note="This alert originates from the ML layer.",
                    top_features=top_features,
                    ground_truth=self._majority_label(group),
                    window=int(group["window"].min()) if "window" in group else 0,
                )
            )
        return alerts

    # ------------------------------------------------------------------
    def _alert_from_arp(self, event: Dict[str, Any], scenario: str) -> Alert:
        return Alert(
            alert_id="",
            timestamp=float(event.get("timestamp", 0.0)),
            category=event.get("category", "mitm"),
            severity=event.get("severity", "HIGH"),
            confidence=float(event.get("confidence", 0.8)),
            rule_id=event.get("rule_id", "R-007"),
            rule_name=event.get("rule_name", "ARP_CACHE_POISONING"),
            entity=event.get("src_ip", ""),
            entity_kind="layer2",
            src_ip=event.get("src_ip", ""),
            dst_ip=event.get("dst_ip", ""),
            proto=event.get("proto", "ARP"),
            flow_count=1,
            flow_keys=[],
            evidence=event.get("evidence", {}),
            explanation=event.get("explanation", ""),
            detection_layers=["signature"],
            ground_truth="mitm",
            scenario=scenario,
        )

    # ------------------------------------------------------------------
    @staticmethod
    def _fuse_severity(rule_severity: str, ml_agrees: bool) -> str:
        """ML agreement can raise severity; disagreement must never lower it.

        A rule is deterministic evidence - 120 unanswered SYNs really did
        happen. Letting a probabilistic model demote that would be a safety
        regression, so disagreement is expressed through *confidence* instead.
        """
        rank = SEVERITY_ORDER.get(rule_severity, 2)
        if ml_agrees and rank < SEVERITY_ORDER["CRITICAL"]:
            rank += 1
        name = [k for k, v in SEVERITY_ORDER.items() if v == rank]
        return name[0] if name else rule_severity

    def _explain(self, row: pd.Series) -> List[Dict[str, Any]]:
        if self.model is None:
            return []
        try:
            return self.model.explain(row, top_k=self.config.top_contributors)
        except Exception:
            return []

    @staticmethod
    def _majority_label(group: pd.DataFrame) -> Optional[str]:
        if "label" not in group.columns or group.empty:
            return None
        counts = group["label"].astype(str).value_counts()
        return str(counts.index[0]) if len(counts) else None

    # ------------------------------------------------------------------
    def _mark_covered(self, scored: pd.DataFrame, alerts: Sequence[Alert]) -> pd.DataFrame:
        """Attach the alert that covers each flow (used by the evaluator)."""
        out = scored.copy()
        out["alert_id"] = ""
        out["flow_verdict"] = 0
        out["flow_severity"] = ""

        if out.empty:
            return out

        index_by_key = {key: idx for idx, key in out["flow_key"].items()}
        for alert in alerts:
            for key in alert.flow_keys:
                idx = index_by_key.get(key)
                if idx is None:
                    continue
                if out.at[idx, "flow_verdict"] == 1:
                    continue
                out.at[idx, "alert_id"] = alert.alert_id
                out.at[idx, "flow_verdict"] = 1
                out.at[idx, "flow_severity"] = alert.severity
        return out


# --------------------------------------------------------------------------
def analyse_dataframe(flows: pd.DataFrame,
                      arp_events: Sequence[Dict[str, Any]] | None = None,
                      config: DetectionConfig | None = None,
                      model: Optional[HybridMLModel] = None,
                      scenario: str = "") -> AnalysisResult:
    """Convenience wrapper used by the CLI, dashboard and tests."""
    engine = HybridEngine(config=config, model=model)
    return engine.analyse(flows, arp_events=arp_events, scenario=scenario)
