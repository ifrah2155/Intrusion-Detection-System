"""Output rendering: JSON/CSV export, console tables and evaluation charts.

Charts are written with the non-interactive ``Agg`` backend so the module works
identically in a terminal, in CI and inside Streamlit.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402

from .config import RESULTS_DIR
from .constants import SEVERITY_ORDER
from .engine import Alert, AnalysisResult

SEVERITY_COLOURS = {
    "CRITICAL": "#b3001b",
    "HIGH": "#e06000",
    "MEDIUM": "#d4a017",
    "LOW": "#3d7ea6",
    "INFO": "#7f8c8d",
}


# --------------------------------------------------------------------------
# Exports
# --------------------------------------------------------------------------
def export_result(result: AnalysisResult, out_dir: str | Path = RESULTS_DIR,
                  stem: Optional[str] = None) -> Dict[str, Path]:
    """Write ``<stem>.alerts.json`` and ``<stem>.alerts.csv``."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    stem = stem or (result.scenario or "analysis")

    json_path = out_dir / f"{stem}.alerts.json"
    csv_path = out_dir / f"{stem}.alerts.csv"
    flows_path = out_dir / f"{stem}.flows.csv"

    payload = {
        "scenario": result.scenario,
        "pcap": result.pcap,
        "generated_at": pd.Timestamp.utcnow().isoformat(timespec="seconds"),
        "summary": {
            "alerts": len(result.alerts),
            "flows": int(len(result.flows)),
            "by_severity": _count_by(result.alerts, "severity"),
            "by_category": _count_by(result.alerts, "category"),
        },
        "alerts": [a.to_dict() for a in result.alerts],
    }
    json_path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")

    result.alerts_frame().to_csv(csv_path, index=False)
    result.flows.to_csv(flows_path, index=False)

    return {"json": json_path, "csv": csv_path, "flows": flows_path}


def _count_by(alerts: Sequence[Alert], attribute: str) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for alert in alerts:
        key = str(getattr(alert, attribute, "unknown"))
        counts[key] = counts.get(key, 0) + 1
    return dict(sorted(counts.items(), key=lambda kv: -kv[1]))


# --------------------------------------------------------------------------
# Console rendering
# --------------------------------------------------------------------------
def format_alerts_table(alerts: Sequence[Alert], max_rows: int = 25) -> str:
    """A fixed-width table that survives any terminal."""
    if not alerts:
        return "  No alerts raised."

    header = (
        f"{'ID':<7} {'TIME(UTC)':<10} {'SEVERITY':<9} {'RULE':<8} {'CATEGORY':<12} "
        f"{'SOURCE':<16} {'TARGET':<22} {'FLOWS':>5} {'CONF':>5}"
    )
    lines = [header, "-" * len(header)]

    for alert in alerts[:max_rows]:
        target = f"{alert.dst_ip}:{alert.dst_port}" if alert.dst_port else alert.dst_ip
        lines.append(
            f"{alert.alert_id:<7} {alert.iso_time[11:19]:<10} {alert.severity:<9} "
            f"{alert.rule_id:<8} {alert.category:<12} {alert.src_ip:<16} "
            f"{target:<22} {alert.flow_count:>5} {alert.confidence:>5.2f}"
        )

    if len(alerts) > max_rows:
        lines.append(f"... {len(alerts) - max_rows} more alerts (see the JSON/CSV export)")
    return "\n".join(lines)


def format_alert_detail(alert: Alert) -> str:
    """The 'why was this flagged' panel - the core of the explainability story."""
    bar = "=" * 78
    lines = [
        bar,
        f"  {alert.alert_id}  |  {alert.severity}  |  {alert.rule_name} ({alert.rule_id})",
        bar,
        f"  Time        : {alert.iso_time} UTC",
        f"  Category    : {alert.category}",
        f"  Source      : {alert.src_ip}:{alert.src_port}",
        f"  Destination : {alert.dst_ip}:{alert.dst_port} ({alert.proto})",
        f"  Flows       : {alert.flow_count}",
        f"  Confidence  : {alert.confidence:.2f}",
        f"  Layers      : {', '.join(alert.detection_layers)}",
        f"  Ground truth: {alert.ground_truth}",
        "",
        "  WHY IT FIRED",
        "  " + "-" * 74,
    ]

    for line in _wrap(alert.explanation, 72):
        lines.append(f"  {line}")

    if alert.evidence:
        lines.append("")
        lines.append("  EVIDENCE")
        lines.append("  " + "-" * 74)
        for key, value in alert.evidence.items():
            if isinstance(value, dict):
                value = ", ".join(f"{k}={v}" for k, v in value.items())
            lines.append(f"    {key:<32} {value}")

    if alert.top_features:
        lines.append("")
        lines.append("  ML FEATURE ATTRIBUTION (deviation from benign baseline)")
        lines.append("  " + "-" * 74)
        lines.append(f"    {'feature':<32} {'value':>10} {'benign':>10} {'z':>7}")
        for feature in alert.top_features:
            lines.append(
                f"    {feature['label'][:32]:<32} {feature['value']:>10} "
                f"{feature['benign_mean']:>10} {feature['z_score']:>+7.1f}"
            )

    lines.append("")
    lines.append(f"  ML: {alert.ml_note}")
    lines.append(bar)
    return "\n".join(lines)


def _wrap(text: str, width: int) -> List[str]:
    words = text.split()
    lines: List[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines


# --------------------------------------------------------------------------
# Charts
# --------------------------------------------------------------------------
def plot_confusion_matrices(summary: Dict[str, Any],
                            out_path: Optional[Path] = None) -> Path:
    out_path = out_path or RESULTS_DIR / "confusion_matrices.png"
    layers = ["signature", "ml", "hybrid"]
    labels = ["benign", "attack"]

    fig, axes = plt.subplots(1, 3, figsize=(13, 4.2))
    for ax, layer in zip(axes, layers):
        m = summary["overall"].get(layer)
        matrix = np.array([[m["tn"], m["fp"]], [m["fn"], m["tp"]]]) if m else np.zeros((2, 2))

        ax.imshow(matrix, cmap="Blues")
        ax.set_xticks([0, 1], labels)
        ax.set_yticks([0, 1], labels)
        ax.set_xlabel("Predicted")
        ax.set_ylabel("Actual")
        ax.set_title(f"{layer}\nrecall={m['recall']:.3f}  precision={m['precision']:.3f}" if m else layer)

        for i in range(2):
            for j in range(2):
                value = int(matrix[i, j])
                colour = "white" if value > matrix.max() / 2 else "black"
                ax.text(j, i, f"{value}", ha="center", va="center", color=colour, fontsize=13)

    fig.suptitle("Flow-level confusion matrices", fontsize=13)
    fig.tight_layout()
    fig.savefig(out_path, dpi=140, bbox_inches="tight")
    plt.close(fig)
    return out_path


def plot_scenario_alerts(summary: Dict[str, Any],
                         out_path: Optional[Path] = None) -> Path:
    out_path = out_path or RESULTS_DIR / "alerts_by_scenario.png"
    scenarios = [s["scenario"] for s in summary["per_scenario"]]
    alerts = [s["alerts"] for s in summary["per_scenario"]]
    flows = [s["attack_flows"] for s in summary["per_scenario"]]

    x = np.arange(len(scenarios))
    fig, ax = plt.subplots(figsize=(10, 4.4))
    ax.bar(x - 0.2, flows, width=0.4, label="attack flows (ground truth)", color="#c9d6df")
    ax.bar(x + 0.2, alerts, width=0.4, label="alerts raised", color="#2e86ab")
    ax.set_xticks(x, [s.replace("scenario_", "S") for s in scenarios], rotation=20, ha="right")
    ax.set_ylabel("count")
    ax.set_title("Ground-truth attack flows vs. alerts raised, per scenario")
    ax.legend()
    fig.tight_layout()
    fig.savefig(out_path, dpi=140, bbox_inches="tight")
    plt.close(fig)
    return out_path


def plot_score_distribution(flows: pd.DataFrame,
                            out_path: Optional[Path] = None) -> Path:
    """How separable are the classes in the ML score space?"""
    out_path = out_path or RESULTS_DIR / "ml_score_distribution.png"
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.2))

    for ax, column, title in (
        (axes[0], "if_score", "Isolation Forest anomaly score"),
        (axes[1], "rf_attack_prob", "Random Forest attack probability"),
    ):
        if column not in flows:
            continue
        benign = flows.loc[flows["label"] == "benign", column].to_numpy()
        attack = flows.loc[flows["label"] != "benign", column].to_numpy()
        bins = np.linspace(0, 1, 30)
        ax.hist(benign, bins=bins, alpha=0.65, label="benign", color="#2e86ab")
        ax.hist(attack, bins=bins, alpha=0.65, label="attack", color="#b3001b")
        ax.set_title(title)
        ax.set_xlabel("score")
        ax.set_ylabel("flows")
        ax.legend()

    fig.tight_layout()
    fig.savefig(out_path, dpi=140, bbox_inches="tight")
    plt.close(fig)
    return out_path


def plot_alert_timeline(result: AnalysisResult,
                        out_path: Optional[Path] = None) -> Optional[Path]:
    """Alert timestamps coloured by severity - the analyst's first view."""
    if not result.alerts:
        return None

    out_path = out_path or RESULTS_DIR / f"timeline_{result.scenario or 'analysis'}.png"
    t0 = min(a.timestamp for a in result.alerts)

    fig, ax = plt.subplots(figsize=(11, 3.4))
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        subset = [a for a in result.alerts if a.severity == severity]
        if not subset:
            continue
        xs = [a.timestamp - t0 for a in subset]
        ys = [SEVERITY_ORDER.get(a.severity, 0) for a in subset]
        ax.scatter(xs, ys, s=[40 + 6 * min(a.flow_count, 40) for a in subset],
                   label=f"{severity} ({len(subset)})",
                   color=SEVERITY_COLOURS.get(severity, "grey"), alpha=0.8, edgecolors="white")

    ax.set_yticks([0, 1, 2, 3, 4], ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
    ax.set_xlabel("seconds since first alert")
    ax.set_title(f"Alert timeline - {result.scenario}")
    ax.grid(alpha=0.25, axis="x")
    ax.legend(loc="upper left", fontsize=8)
    fig.tight_layout()
    fig.savefig(out_path, dpi=140, bbox_inches="tight")
    plt.close(fig)
    return out_path


def render_evaluation_charts(summary: Dict[str, Any], flows: pd.DataFrame,
                             out_dir: Path = RESULTS_DIR) -> Dict[str, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    return {
        "confusion": plot_confusion_matrices(summary, out_dir / "confusion_matrices.png"),
        "per_scenario": plot_scenario_alerts(summary, out_dir / "alerts_by_scenario.png"),
        "scores": plot_score_distribution(flows, out_dir / "ml_score_distribution.png"),
    }
