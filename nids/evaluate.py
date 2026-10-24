"""Detection-performance evaluation.

Three configurations are scored on exactly the same flows so the comparison is
fair:

``signature``  the deterministic rule layer alone
``ml``         the machine-learning layer alone
``hybrid``     the fused engine actually shipped to the analyst

All headline metrics are computed at **flow level** (does the system flag this
conversation?), which is the granularity at which labels exist. Alert-level
precision is reported separately because that is what determines analyst
workload.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import numpy as np
import pandas as pd

from .config import RESULTS_DIR, DetectionConfig
from .constants import ATTACK_LABELS, BENIGN, LABEL_DESCRIPTIONS
from .engine import Alert, AnalysisResult
from .pipeline import analyse_pcap, available_pcaps
from .ml import HybridMLModel

LAYERS = ("signature", "ml", "hybrid")

PREDICTOR_COLUMNS = {
    "signature": "signature_hit",
    "ml": "ml_verdict",
    "hybrid": "flow_verdict",
}


# --------------------------------------------------------------------------
# Confusion matrix and derived metrics
# --------------------------------------------------------------------------
@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.tn + self.fn

    def as_dict(self) -> Dict[str, int]:
        return {"tp": self.tp, "fp": self.fp, "tn": self.tn, "fn": self.fn}

    def metrics(self) -> Dict[str, float]:
        precision = self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0
        recall = self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0
        f1 = 2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
        accuracy = (self.tp + self.tn) / self.total if self.total else 0.0
        fpr = self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0
        fnr = self.fn / (self.fn + self.tp) if (self.fn + self.tp) else 0.0
        specificity = self.tn / (self.tn + self.fp) if (self.tn + self.fp) else 0.0
        return {
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "accuracy": round(accuracy, 4),
            "false_positive_rate": round(fpr, 4),
            "false_negative_rate": round(fnr, 4),
            "specificity": round(specificity, 4),
        }


def confusion(y_true: Sequence[int], y_pred: Sequence[int]) -> Confusion:
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            tp += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 0 and p == 0:
            tn += 1
        else:
            fn += 1
    return Confusion(tp, fp, tn, fn)


# --------------------------------------------------------------------------
@dataclass
class ScenarioScore:
    scenario: str
    flows: int
    benign_flows: int
    attack_flows: int
    layers: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    alerts: int = 0
    alert_precision: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario,
            "flows": self.flows,
            "benign_flows": self.benign_flows,
            "attack_flows": self.attack_flows,
            "alerts": self.alerts,
            "alert_precision": round(self.alert_precision, 4),
            "layers": self.layers,
        }


# --------------------------------------------------------------------------
class Evaluator:
    """Scores one or more :class:`AnalysisResult` objects."""

    def __init__(self):
        self.scenarios: List[ScenarioScore] = []
        self.all_flows: List[pd.DataFrame] = []
        self.alerts: List[Alert] = []

    # ------------------------------------------------------------------
    def add(self, result: AnalysisResult) -> None:
        flows = result.flows.copy()
        if flows.empty:
            return

        flows["scenario"] = result.scenario or flows.get("scenario", "")
        self.all_flows.append(flows)
        self.alerts.extend(result.alerts)

        y_true = (flows["label"] != BENIGN).astype(int).to_numpy()
        layers: Dict[str, Dict[str, Any]] = {}

        for layer, column in PREDICTOR_COLUMNS.items():
            if column not in flows:
                continue
            y_pred = flows[column].fillna(0).astype(int).to_numpy()
            cm = confusion(y_true, y_pred)
            layers[layer] = {**cm.as_dict(), **cm.metrics()}

        tp_alerts = sum(1 for a in result.alerts if a.is_true_positive)
        self.scenarios.append(
            ScenarioScore(
                scenario=result.scenario,
                flows=len(flows),
                benign_flows=int((flows["label"] == BENIGN).sum()),
                attack_flows=int((flows["label"] != BENIGN).sum()),
                layers=layers,
                alerts=len(result.alerts),
                alert_precision=(tp_alerts / len(result.alerts)) if result.alerts else 0.0,
            )
        )

    # ------------------------------------------------------------------
    @property
    def flows(self) -> pd.DataFrame:
        if not self.all_flows:
            return pd.DataFrame()
        return pd.concat(self.all_flows, ignore_index=True)

    def overall(self, subset: Optional[pd.DataFrame] = None) -> Dict[str, Any]:
        flows = subset if subset is not None else self.flows
        if flows is None or flows.empty:
            return {}

        y_true = (flows["label"] != BENIGN).astype(int).to_numpy()
        out: Dict[str, Any] = {}
        for layer, column in PREDICTOR_COLUMNS.items():
            if column not in flows:
                continue
            y_pred = flows[column].fillna(0).astype(int).to_numpy()
            cm = confusion(y_true, y_pred)
            out[layer] = {**cm.as_dict(), **cm.metrics()}
        return out

    def per_attack_class(self) -> Dict[str, Any]:
        flows = self.flows
        out: Dict[str, Any] = {}
        for label in ATTACK_LABELS:
            subset = flows[flows["label"] == label]
            if subset.empty:
                continue
            entry: Dict[str, Any] = {"flows": int(len(subset))}
            for layer, column in PREDICTOR_COLUMNS.items():
                if column in subset:
                    detected = int(subset[column].fillna(0).astype(int).sum())
                    entry[layer] = {
                        "detected": detected,
                        "recall": round(detected / len(subset), 4),
                    }
            out[label] = entry
        return out

    def alert_summary(self) -> Dict[str, Any]:
        if not self.alerts:
            return {"total": 0, "true_positive": 0, "false_positive": 0,
                    "alert_precision": 0.0, "by_severity": {}, "by_category": {}}

        tp = sum(1 for a in self.alerts if a.is_true_positive)
        fp = sum(1 for a in self.alerts if a.is_true_positive is False)
        return {
            "total": len(self.alerts),
            "true_positive": tp,
            "false_positive": fp,
            "alert_precision": round(tp / len(self.alerts), 4) if self.alerts else 0.0,
            "by_severity": dict(Counter(a.severity for a in self.alerts)),
            "by_category": dict(Counter(a.category for a in self.alerts)),
        }

    # ------------------------------------------------------------------
    def examples(self, limit: int = 5) -> Dict[str, List[Dict[str, Any]]]:
        """Concrete false positives and false negatives for the report."""
        flows = self.flows
        if flows.empty:
            return {"false_positives": [], "false_negatives": []}

        def row_to_dict(row: pd.Series, note: str) -> Dict[str, Any]:
            return {
                "scenario": str(row.get("scenario", "")),
                "src_ip": str(row.get("src_ip", "")),
                "dst_ip": str(row.get("dst_ip", "")),
                "dst_port": int(row.get("dst_port", 0)),
                "proto": str(row.get("proto_name", "")),
                "total_packets": int(row.get("total_packets", 0)),
                "duration": round(float(row.get("duration", 0.0)), 3),
                "ground_truth": str(row.get("label", "")),
                "alert_id": str(row.get("alert_id", "")),
                "severity": str(row.get("flow_severity", "")),
                "if_score": round(float(row.get("if_score", 0.0)), 3),
                "rf_attack_prob": round(float(row.get("rf_attack_prob", 0.0)), 3),
                "note": note,
            }

        fps = flows[(flows["label"] == BENIGN) & (flows["flow_verdict"] == 1)]
        fns = flows[(flows["label"] != BENIGN) & (flows["flow_verdict"] == 0)]

        return {
            "false_positives": [row_to_dict(r, "benign flow flagged") for _, r in fps.head(limit).iterrows()],
            "false_negatives": [row_to_dict(r, "attack flow missed") for _, r in fns.head(limit).iterrows()],
            "false_positive_flows": int(len(fps)),
            "false_negative_flows": int(len(fns)),
        }

    # ------------------------------------------------------------------
    def summary(self) -> Dict[str, Any]:
        flows = self.flows
        holdout = flows[flows["scenario"].isin(["scenario_5_ambiguous", "scenario_6_mitm_arp"])] \
            if not flows.empty else flows
        ip_only = flows[flows["label"] != "mitm"] if not flows.empty else flows

        mitm_alerts = [a for a in self.alerts if a.category == "mitm"]

        return {
            "generated_at": pd.Timestamp.utcnow().isoformat(timespec="seconds"),
            "totals": {
                "flows": int(len(flows)),
                "benign_flows": int((flows["label"] == BENIGN).sum()) if not flows.empty else 0,
                "attack_flows": int((flows["label"] != BENIGN).sum()) if not flows.empty else 0,
                "pcaps": len(self.scenarios),
                "alerts": len(self.alerts),
            },
            "overall": self.overall(),
            "overall_excluding_layer2": self.overall(ip_only),
            "holdout_only": self.overall(holdout),
            "per_scenario": [s.to_dict() for s in self.scenarios],
            "per_attack_class": self.per_attack_class(),
            "alert_summary": self.alert_summary(),
            "mitm_event_level": {
                "alerts": len(mitm_alerts),
                "detected": len(mitm_alerts) > 0,
                "rule_ids": sorted({a.rule_id for a in mitm_alerts}),
                "true_positives": sum(1 for a in mitm_alerts if a.is_true_positive),
                "note": (
                    "ARP cache poisoning is a layer-2 control-plane attack: it "
                    "produces no TCP/IP flow of its own, so it is scored at the "
                    "event level rather than through the flow-level confusion "
                    "matrix. The one 'mitm' flow label is the victim's redirected "
                    "HTTP conversation, which is indistinguishable from ordinary "
                    "traffic once ARP has been poisoned."
                ),
            },
            "examples": self.examples(),
            "label_definitions": LABEL_DESCRIPTIONS,
        }


# --------------------------------------------------------------------------
# Running a full evaluation
# --------------------------------------------------------------------------
def evaluate_directory(
    pcap_dir: Optional[Path] = None,
    config: Optional[DetectionConfig] = None,
    model: Optional[HybridMLModel] = None,
    only: Optional[Iterable[str]] = None,
    out_dir: Path = RESULTS_DIR,
    write: bool = True,
) -> Dict[str, Any]:
    """Analyse every capture and score the result."""
    config = config or DetectionConfig()
    evaluator = Evaluator()

    paths = available_pcaps(pcap_dir) if pcap_dir else available_pcaps()
    if only:
        wanted = set(only)
        paths = [p for p in paths if p.stem in wanted]

    if not paths:
        raise FileNotFoundError("No pcaps found. Run: python data/generate_dataset.py")

    for path in paths:
        print(f"  analysing {path.stem} ...", end=" ", flush=True)
        result = analyse_pcap(path, config=config, model=model)
        evaluator.add(result)
        print(f"{len(result.alerts)} alerts")

    summary = evaluator.summary()
    summary["per_scenario"] = summary["per_scenario"]
    summary["confusion_matrices"] = {
        s.scenario: {layer: {k: s.layers[layer][k] for k in ("tp", "fp", "tn", "fn")}
                     for layer in s.layers}
        for s in evaluator.scenarios
    }

    if write:
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "evaluation.json").write_text(
            json.dumps(summary, indent=2, default=str), encoding="utf-8"
        )
        pd.DataFrame(summary["per_scenario"]).to_json(
            out_dir / "per_scenario.json", orient="records", indent=2
        )
        evaluator.flows.to_csv(out_dir / "flows.csv", index=False)

    summary["_evaluator"] = evaluator
    return summary


def render_markdown(summary: Dict[str, Any]) -> str:
    """Human-readable tables, copied verbatim into the technical report."""
    lines: List[str] = []
    lines.append("| Layer | TP | FP | TN | FN | Precision | Recall | F1 | Accuracy | FPR |")
    lines.append("|---|---|---|---|---|---|---|---|---|---|")

    for layer in LAYERS:
        m = summary["overall"].get(layer)
        if not m:
            continue
        lines.append(
            f"| {layer} | {m['tp']} | {m['fp']} | {m['tn']} | {m['fn']} | "
            f"{m['precision']:.3f} | {m['recall']:.3f} | {m['f1']:.3f} | "
            f"{m['accuracy']:.3f} | {m['false_positive_rate']:.3f} |"
        )

    lines.append("")
    lines.append("| Attack class | Flows | Signature recall | ML recall | Hybrid recall |")
    lines.append("|---|---|---|---|---|")
    for label, entry in summary["per_attack_class"].items():
        note = " (layer-2, see event-level results)" if label == "mitm" else ""
        lines.append(
            f"| {label}{note} | {entry['flows']} | "
            f"{entry.get('signature', {}).get('recall', 0):.3f} | "
            f"{entry.get('ml', {}).get('recall', 0):.3f} | "
            f"{entry.get('hybrid', {}).get('recall', 0):.3f} |"
        )
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    from .pipeline import ensure_model

    config = DetectionConfig()
    model = ensure_model(config)
    summary = evaluate_directory(config=config, model=model)

    print()
    print(render_markdown(summary))
    print()
    print(json.dumps(summary["alert_summary"], indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
