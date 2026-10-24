"""Feature extraction cache + model training.

The evaluation protocol matters as much as the model, so it is enforced here:

* Scenarios 1-4 are the *development* set. Flows are split into train/test with
  ``GroupShuffleSplit`` keyed on ``(scenario, time window)``, so an entire
  incident (and its benign background in the same 10 s bucket) lands on one
  side of the split. A random per-flow split would put near-duplicate scan
  probes in both sets and inflate every metric.
* Scenario 5 (ambiguous) and scenario 6 (ARP/MITM) are never used for training.
  They are pure hold-out data.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd
from sklearn.model_selection import GroupShuffleSplit

from .config import DATA_DIR, LABEL_DIR, MODEL_DIR, PCAP_DIR, DetectionConfig
from .constants import ATTACK_LABELS, BENIGN
from .features import attach_labels, extract_features
from .ml import HybridMLModel

CACHE_PATH = DATA_DIR / "features_cache.pkl"

DEV_SCENARIOS = [
    "scenario_1_benign",
    "scenario_2_port_scan",
    "scenario_3_dos",
    "scenario_4_brute_force",
]
HOLDOUT_SCENARIOS = ["scenario_5_ambiguous", "scenario_6_mitm_arp"]


# --------------------------------------------------------------------------
def discover_pcaps(pcap_dir: Path = PCAP_DIR) -> List[Path]:
    return sorted(p for p in pcap_dir.glob("*.pcap"))


def load_all_features(
    config: Optional[DetectionConfig] = None,
    use_cache: bool = True,
    pcap_dir: Path = PCAP_DIR,
) -> Tuple[pd.DataFrame, Dict[str, List[Dict]]]:
    """Extract (or load from cache) features for every capture on disk."""
    config = config or DetectionConfig()
    pcaps = discover_pcaps(pcap_dir)
    if not pcaps:
        raise FileNotFoundError(
            f"No captures in {pcap_dir}. Run: python data/generate_dataset.py"
        )

    if use_cache and CACHE_PATH.exists():
        cached = pd.read_pickle(CACHE_PATH)
        newest = max(p.stat().st_mtime for p in pcaps)
        if cached.attrs.get("built_at", 0) >= newest and cached.attrs.get("n_pcaps") == len(pcaps):
            arp = cached.attrs.get("arp_events", {})
            return cached, arp

    frames = []
    arp_index: Dict[str, List[Dict]] = {}

    for pcap in pcaps:
        scenario = pcap.stem
        started = time.perf_counter()
        df, arp_events = extract_features(pcap, config=config, scenario=scenario)
        label_path = LABEL_DIR / f"{scenario}.csv"
        df = attach_labels(df, label_path)
        frames.append(df)
        arp_index[scenario] = arp_events
        print(f"  {scenario:<26} {len(df):>5} flows, {len(arp_events):>2} L2 events "
              f"({time.perf_counter() - started:.1f}s)")

    combined = pd.concat(frames, ignore_index=True)
    combined.attrs["built_at"] = max(p.stat().st_mtime for p in pcaps)
    combined.attrs["n_pcaps"] = len(pcaps)
    combined.attrs["arp_events"] = arp_index

    try:
        combined.to_pickle(CACHE_PATH)
    except Exception as exc:  # pragma: no cover
        print(f"  (cache not written: {exc})")

    return combined, arp_index


# --------------------------------------------------------------------------
def split_dev_set(df: pd.DataFrame, test_size: float = 0.35, seed: int = 42,
                  n_candidates: int = 40) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """Group-aware train/test split of the development scenarios.

    Splitting by group (scenario + window) is non-negotiable: a random per-flow
    split would place near-duplicate probes from one scan on both sides and
    inflate every metric. But group sizes here are wildly unequal - the SYN
    flood contributes ~1800 flows in three windows - so a single arbitrary
    draw can land 80% of the data in the test set.

    We therefore evaluate several candidate group splits and keep the one whose
    flow-level test fraction is closest to ``test_size``, subject to every
    attack class being present in both halves.
    """
    dev = df[df["scenario"].isin(DEV_SCENARIOS)].copy()
    dev["group"] = dev["scenario"].astype(str) + "_" + dev["window"].astype(str)

    required = set(dev["label"]) - {BENIGN}
    splitter = GroupShuffleSplit(n_splits=n_candidates, test_size=test_size, random_state=seed)

    best: Optional[Tuple[float, np.ndarray, np.ndarray]] = None
    for train_idx, test_idx in splitter.split(dev, groups=dev["group"]):
        train_labels = set(dev.iloc[train_idx]["label"])
        test_labels = set(dev.iloc[test_idx]["label"])
        if not required.issubset(train_labels) or not required.issubset(test_labels):
            continue
        if (dev.iloc[train_idx]["label"] == BENIGN).sum() < 30:
            continue
        score = abs(len(test_idx) / len(dev) - test_size)
        if best is None or score < best[0]:
            best = (score, train_idx, test_idx)

    if best is None:  # fall back to a single draw
        train_idx, test_idx = next(splitter.split(dev, groups=dev["group"]))
        return dev.iloc[train_idx].copy(), dev.iloc[test_idx].copy()

    _, train_idx, test_idx = best
    return dev.iloc[train_idx].copy(), dev.iloc[test_idx].copy()


def train_model(
    df: Optional[pd.DataFrame] = None,
    config: Optional[DetectionConfig] = None,
    save: bool = True,
) -> Tuple[HybridMLModel, pd.DataFrame, pd.DataFrame]:
    """Train on the development split; return ``(model, train, test)``."""
    config = config or DetectionConfig()

    if df is None:
        df, _ = load_all_features(config=config)

    train_df, test_df = split_dev_set(df)
    benign_train = train_df[train_df["label"] == BENIGN]

    print(f"\n  training flows : {len(train_df)} "
          f"({len(benign_train)} benign, {len(train_df) - len(benign_train)} attack)")
    print(f"  held-out flows : {len(test_df)}")
    print(f"  attack classes : {sorted(set(train_df['label']) - {BENIGN})}")

    model = HybridMLModel(config)
    model.fit(benign_df=benign_train, labelled_df=train_df)
    model.metadata["trained_at"] = time.strftime("%Y-%m-%dT%H:%M:%S")
    model.metadata["train_flows"] = int(len(train_df))
    model.metadata["test_flows"] = int(len(test_df))
    model.metadata["dev_scenarios"] = DEV_SCENARIOS
    model.metadata["holdout_scenarios"] = HOLDOUT_SCENARIOS

    if save:
        path = model.save(MODEL_DIR)
        print(f"  model saved    : {path}")

    return model, train_df, test_df


def model_info(path: Optional[Path] = None) -> Dict:
    path = path or MODEL_DIR / "hybrid_model.joblib"
    if not path.exists():
        return {"exists": False, "path": str(path)}
    model = HybridMLModel.load(path)
    return {"exists": True, "path": str(path), **model.metadata}


def main() -> int:
    config = DetectionConfig()
    df, _ = load_all_features(config=config, use_cache=False)
    train_model(df, config)
    print(json.dumps(model_info(), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
