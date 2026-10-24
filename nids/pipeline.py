"""End-to-end pipeline: pcap file in, :class:`AnalysisResult` out.

The CLI and the Streamlit dashboard both call :func:`analyse_pcap`, so there is
exactly one code path between "raw capture" and "alert list".
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

from .config import LABEL_DIR, MODEL_DIR, PCAP_DIR, DetectionConfig
from .engine import AnalysisResult, HybridEngine
from .features import attach_labels, extract_features, pcap_summary, iter_packets
from .ml import HybridMLModel


def load_model(model_path: Optional[str | Path] = None,
               required: bool = False) -> Optional[HybridMLModel]:
    """Load the persisted model, training one first if it is missing."""
    path = Path(model_path) if model_path else MODEL_DIR / "hybrid_model.joblib"

    if not path.exists():
        if required:
            raise FileNotFoundError(
                f"No trained model at {path}. Run: python -m nids.train"
            )
        return None

    return HybridMLModel.load(path)


def ensure_model(config: Optional[DetectionConfig] = None,
                 model_path: Optional[str | Path] = None) -> HybridMLModel:
    """Return a trained model, training one on the spot if necessary."""
    model = load_model(model_path)
    if model is not None:
        return model

    print("No trained model found - training one now (this takes a few seconds)...")
    from .train import train_model

    model, _, _ = train_model(config=config)
    return model


def analyse_pcap(
    pcap_path: str | Path,
    config: Optional[DetectionConfig] = None,
    model: Optional[HybridMLModel] = None,
    attach_ground_truth: bool = True,
    scenario: Optional[str] = None,
) -> AnalysisResult:
    """Run detection on a single capture."""
    config = config or DetectionConfig()
    pcap_path = Path(pcap_path)
    scenario = scenario or pcap_path.stem

    flows, arp_events = extract_features(pcap_path, config=config, scenario=scenario)

    if attach_ground_truth:
        label_path = LABEL_DIR / f"{scenario}.csv"
        if label_path.exists():
            flows = attach_labels(flows, label_path)

    engine = HybridEngine(config=config, model=model)
    return engine.analyse(flows, arp_events=arp_events, scenario=scenario,
                          pcap=str(pcap_path))


def pcap_overview(pcap_path: str | Path) -> Dict:
    """Cheap capture statistics for the dashboard header."""
    return pcap_summary(list(iter_packets(pcap_path)))


def available_pcaps(pcap_dir: Path = PCAP_DIR) -> List[Path]:
    return sorted(pcap_dir.glob("*.pcap"))
