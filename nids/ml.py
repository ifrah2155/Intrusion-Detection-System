"""Machine-learning layer: unsupervised anomaly detection + supervised classifier.

Two complementary models are trained:

``AnomalyModel`` (Isolation Forest)
    Trained on **benign traffic only**. It learns what normal looks like and
    scores how far a flow sits from that envelope. Because it never sees an
    attack during training it can, in principle, flag traffic types that were
    not present in the labelled data - this is the layer that addresses
    "novel threats" in the brief.

``SupervisedModel`` (Random Forest)
    Trained on labelled flows (benign + the four attack families). It provides
    a calibrated attack probability and, crucially, a feature-importance vector
    that makes the ML decision explainable.

Everything is persisted with joblib so the dashboard and CLI can load a trained
model without refitting.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier

from .config import DetectionConfig
from .constants import BENIGN
from .features import FEATURE_COLUMNS

# --------------------------------------------------------------------------
# Feature selection for the ML models
# --------------------------------------------------------------------------
# ``dst_port`` is intentionally excluded: as a raw integer the model would
# treat port 3389 as "bigger" than port 22, and would memorise "port 22 means
# brute force" rather than learning behaviour. Port semantics are already
# carried by ``is_well_known_port`` and are handled precisely by the rules.
EXCLUDED_FEATURES = {"dst_port"}

# Heavy-tailed counters are log-compressed before scaling. Without this a
# single 100 MB transfer dominates every distance metric.
LOG_FEATURES = {
    "duration",
    "fwd_bytes",
    "bwd_bytes",
    "total_bytes",
    "pkt_rate",
    "byte_rate",
    "payload_bytes",
    "pkt_len_max",
    "iat_max",
    "src_pkt_count_win",
    "src_syn_pkts_win",
    "src_pps_peak",
    "dst_pkt_count_win",
    "dst_pps_peak",
    "fwd_packets",
    "bwd_packets",
    "total_packets",
}

ML_FEATURES: List[str] = [c for c in FEATURE_COLUMNS if c not in EXCLUDED_FEATURES]

FEATURE_LABELS: Dict[str, str] = {
    "duration": "flow duration (s)",
    "fwd_packets": "packets sent by initiator",
    "bwd_packets": "packets sent by responder",
    "total_packets": "total packets in flow",
    "fwd_bytes": "bytes sent by initiator",
    "bwd_bytes": "bytes sent by responder",
    "total_bytes": "total bytes in flow",
    "pkt_rate": "packets per second",
    "byte_rate": "bytes per second",
    "payload_bytes": "payload bytes",
    "payload_ratio": "payload / total bytes",
    "pkt_len_mean": "mean packet size",
    "pkt_len_std": "packet size std-dev",
    "pkt_len_min": "minimum packet size",
    "pkt_len_max": "maximum packet size",
    "fwd_pkt_len_mean": "mean forward packet size",
    "bwd_pkt_len_mean": "mean reverse packet size",
    "iat_mean": "mean inter-arrival time",
    "iat_std": "inter-arrival time std-dev",
    "iat_max": "maximum inter-arrival time",
    "iat_min": "minimum inter-arrival time",
    "syn_cnt": "SYN count",
    "ack_cnt": "ACK count",
    "fin_cnt": "FIN count",
    "rst_cnt": "RST count",
    "psh_cnt": "PSH count",
    "urg_cnt": "URG count",
    "syn_ratio": "SYN / total packets",
    "ack_ratio": "ACK / total packets",
    "rst_ratio": "RST / total packets",
    "fin_ratio": "FIN / total packets",
    "has_syn": "flow started with SYN",
    "has_synack": "responder sent SYN/ACK",
    "handshake_completed": "TCP handshake completed",
    "failed_handshake": "SYN never answered",
    "null_scan": "NULL-flag probe",
    "xmas_scan": "XMAS-flag probe",
    "proto_tcp": "protocol is TCP",
    "proto_udp": "protocol is UDP",
    "proto_icmp": "protocol is ICMP",
    "is_well_known_port": "destination is a well-known port",
    "src_flow_count_win": "flows from source in window",
    "src_unique_dst_hosts_win": "distinct hosts contacted by source",
    "src_unique_dst_ports_win": "distinct ports touched by source",
    "src_port_entropy_win": "entropy of destination ports",
    "src_pkt_count_win": "source packets in window",
    "src_syn_pkts_win": "source SYNs in window",
    "src_pps_peak": "source packets per second",
    "src_syn_ratio_win": "source SYN ratio in window",
    "src_failed_handshakes_win": "unanswered probes by source",
    "src_ssh_attempts_win": "login-service attempts by source",
    "dst_unique_src_hosts_win": "distinct sources at destination",
    "dst_pkt_count_win": "destination packets in window",
    "dst_pps_peak": "destination packets per second",
    "dst_syn_ratio_win": "destination SYN ratio in window",
}


# --------------------------------------------------------------------------
# Matrix preparation
# --------------------------------------------------------------------------
def _to_matrix(df: pd.DataFrame, features: Sequence[str]) -> Tuple[np.ndarray, pd.DataFrame]:
    """Return ``(model_matrix, display_frame)``.

    ``model_matrix`` has log-compressed heavy tails and no NaNs/infinities;
    ``display_frame`` keeps the original, human-readable values.
    """
    display = df.reindex(columns=list(features)).astype(float)
    display = display.replace([np.inf, -np.inf], np.nan).fillna(0.0)

    matrix = display.copy()
    for col in features:
        if col in LOG_FEATURES:
            matrix[col] = np.log1p(np.clip(matrix[col].to_numpy(), 0.0, None))
    return matrix.to_numpy(dtype=float), display


@dataclass
class _Baseline:
    mean: np.ndarray
    std: np.ndarray


# --------------------------------------------------------------------------
# Unsupervised layer
# --------------------------------------------------------------------------
class AnomalyModel:
    """Isolation Forest trained on benign traffic only."""

    def __init__(self, config: DetectionConfig | None = None):
        self.config = config or DetectionConfig()
        self.features: List[str] = list(ML_FEATURES)
        self.model: Optional[IsolationForest] = None
        self.baseline: Optional[_Baseline] = None
        self.raw_mean_: Optional[np.ndarray] = None
        self.mu_: float = 0.0
        self.sigma_: float = 1.0

    def fit(self, benign_df: pd.DataFrame) -> "AnomalyModel":
        X, display = _to_matrix(benign_df, self.features)
        self.model = IsolationForest(
            n_estimators=self.config.if_n_estimators,
            contamination=self.config.if_contamination,
            random_state=42,
            n_jobs=-1,
        ).fit(X)

        raw = -self.model.score_samples(X)
        self.mu_ = float(raw.mean())
        self.sigma_ = float(raw.std()) or 1.0
        self.baseline = _Baseline(mean=X.mean(axis=0), std=X.std(axis=0) + 1e-9)
        # Means of the *untransformed* values, so explanations can quote a
        # human-readable "benign average" next to the observed value.
        self.raw_mean_ = display.mean(axis=0).to_numpy(dtype=float)
        return self

    def score(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """Return ``(normalised_score_0_1, is_anomaly)``."""
        if self.model is None:
            raise RuntimeError("AnomalyModel is not fitted")
        X, _ = _to_matrix(df, self.features)
        raw = -self.model.score_samples(X)
        z = (raw - self.mu_) / (self.sigma_ * 2.0)
        normalised = 1.0 / (1.0 + np.exp(-z))
        flags = (self.model.predict(X) == -1).astype(int)
        return normalised, flags

    def ablation_contributions(self, row: pd.Series, top_k: int = 5) -> List[Dict[str, Any]]:
        """Per-feature attribution by replacing one feature at a time.

        For every feature we swap the flow's value for the benign mean and
        measure how much the anomaly score drops. The drop is the feature's
        contribution to *this* flow being considered anomalous.
        """
        if self.model is None or self.baseline is None:
            return []

        X, _ = _to_matrix(pd.DataFrame([row]), self.features)
        base = float((-self.model.score_samples(X))[0])

        contributions = []
        for i, feature in enumerate(self.features):
            probe = X.copy()
            probe[0, i] = self.baseline.mean[i]
            delta = base - float((-self.model.score_samples(probe))[0])
            contributions.append((feature, delta))

        contributions.sort(key=lambda kv: abs(kv[1]), reverse=True)
        return [
            {"feature": f, "ablation_delta": round(float(d), 4)}
            for f, d in contributions[:top_k]
        ]


# --------------------------------------------------------------------------
# Supervised layer
# --------------------------------------------------------------------------
class SupervisedModel:
    """Random Forest classifier over labelled flows."""

    def __init__(self, config: DetectionConfig | None = None):
        self.config = config or DetectionConfig()
        self.features: List[str] = list(ML_FEATURES)
        self.model: Optional[RandomForestClassifier] = None
        self.classes_: List[str] = []

    def fit(self, labelled_df: pd.DataFrame, label_col: str = "label") -> "SupervisedModel":
        df = labelled_df.dropna(subset=[label_col])
        y_text = df[label_col].astype(str).to_numpy()
        self.classes_ = sorted(set(y_text))
        if len(self.classes_) < 2:
            self.model = None
            return self

        X, _ = _to_matrix(df, self.features)
        self.model = RandomForestClassifier(
            n_estimators=self.config.rf_n_estimators,
            max_depth=self.config.rf_max_depth,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        ).fit(X, y_text)
        return self

    @property
    def is_fitted(self) -> bool:
        return self.model is not None

    def attack_probability(self, df: pd.DataFrame) -> np.ndarray:
        """Probability that a flow is *any* attack class."""
        if self.model is None:
            return np.zeros(len(df))
        X, _ = _to_matrix(df, self.features)
        proba = self.model.predict_proba(X)
        benign_idx = list(self.model.classes_).index(BENIGN) if BENIGN in self.model.classes_ else None
        if benign_idx is None:
            return proba.max(axis=1)
        return 1.0 - proba[:, benign_idx]

    def predict_label(self, df: pd.DataFrame) -> List[str]:
        if self.model is None:
            return [BENIGN] * len(df)
        X, _ = _to_matrix(df, self.features)
        return [str(v) for v in self.model.predict(X)]

    @property
    def importances(self) -> np.ndarray:
        if self.model is None:
            return np.zeros(len(self.features))
        return np.asarray(self.model.feature_importances_, dtype=float)


# --------------------------------------------------------------------------
# Combined model
# --------------------------------------------------------------------------
class HybridMLModel:
    """Container that owns both models plus everything needed for explanation."""

    def __init__(self, config: DetectionConfig | None = None):
        self.config = config or DetectionConfig()
        self.features: List[str] = list(ML_FEATURES)
        self.anomaly = AnomalyModel(self.config)
        self.supervised = SupervisedModel(self.config)
        self.metadata: Dict[str, Any] = {}
        self._importance_norm: np.ndarray = np.zeros(len(self.features))

    # ---- training ----------------------------------------------------
    def fit(self, benign_df: pd.DataFrame, labelled_df: Optional[pd.DataFrame] = None) -> "HybridMLModel":
        if benign_df.empty:
            raise ValueError("Cannot train on an empty benign dataset")

        self.anomaly.fit(benign_df)

        if labelled_df is not None and not labelled_df.empty:
            self.supervised.fit(labelled_df)
            if self.supervised.is_fitted:
                self.metadata["supervised_available"] = True
                self.metadata["classes"] = list(self.supervised.classes_)
            else:
                self.metadata["supervised_available"] = False
        else:
            self.metadata["supervised_available"] = False

        self.metadata["benign_flows"] = int(len(benign_df))
        self.metadata["features"] = len(self.features)
        self._derive_importance()
        return self

    def _derive_importance(self) -> None:
        """Global feature importance used to weight per-flow attributions."""
        if self.supervised.is_fitted:
            imp = self.supervised.importances
        else:
            # Fall back to mean |ablation| over a slice of the benign baseline.
            imp = np.zeros(len(self.features))
            if self.anomaly.baseline is not None:
                dummy = pd.DataFrame(
                    np.tile(self.anomaly.baseline.mean, (1, 1)), columns=self.features
                )
                for i, feature in enumerate(self.features):
                    probe = dummy.copy()
                    probe.iloc[0, i] = self.anomaly.baseline.mean[i] + self.anomaly.baseline.std[i] * 2
                    X, _ = _to_matrix(probe, self.features)
                    imp[i] = abs(float((-self.anomaly.model.score_samples(X))[0]))
        total = imp.sum()
        self._importance_norm = imp / total if total > 0 else np.zeros_like(imp)

    # ---- inference ---------------------------------------------------
    def predict(self, df: pd.DataFrame) -> pd.DataFrame:
        """Attach ML scores to a flow DataFrame."""
        if df.empty:
            return df.assign(
                if_score=[], if_anomaly=[], rf_attack_prob=[], rf_label=[], ml_score=[], ml_verdict=[]
            )

        if_score, if_flag = self.anomaly.score(df)

        if self.supervised.is_fitted:
            rf_prob = self.supervised.attack_probability(df)
            rf_label = self.supervised.predict_label(df)
        else:
            rf_prob = np.zeros(len(df))
            rf_label = [BENIGN] * len(df)

        if self.supervised.is_fitted:
            ml_score = 0.5 * if_score + 0.5 * rf_prob
        else:
            ml_score = if_score

        # Decision logic. The supervised classifier is the primary ML signal;
        # the Isolation Forest only stands alone when it is *strongly*
        # anomalous (>= ml_anomaly_threshold), which is what keeps benign
        # traffic out of the alert stream while still surfacing genuinely
        # novel behaviour the classifier has never seen.
        supervised_positive = rf_prob >= self.config.rf_positive_probability
        novelty_positive = if_score >= self.config.ml_anomaly_threshold
        verdict = (supervised_positive | novelty_positive).astype(int)

        return df.assign(
            if_score=np.round(if_score, 4),
            if_anomaly=if_flag,
            if_candidate=novelty_positive.astype(int),
            rf_attack_prob=np.round(rf_prob, 4),
            rf_label=rf_label,
            ml_score=np.round(ml_score, 4),
            ml_verdict=verdict,
        )

    # ---- explanation --------------------------------------------------
    def explain(self, row: pd.Series, top_k: int | None = None) -> List[Dict[str, Any]]:
        """Return the features that pushed this flow away from the baseline.

        Contribution = |z-score against the benign baseline| x global model
        importance. Both quantities are inspectable, so an analyst can verify
        the ranking by hand.
        """
        if self.anomaly.baseline is None:
            return []

        top_k = top_k or self.config.top_contributors
        _, display = _to_matrix(pd.DataFrame([row]), self.features)
        X, _ = _to_matrix(pd.DataFrame([row]), self.features)
        x = X[0]
        raw = display.iloc[0]

        z = (x - self.anomaly.baseline.mean) / self.anomaly.baseline.std
        # Clamp: when a feature never varies in benign traffic its std is ~0
        # and the raw z-score becomes meaningless (1e12). Reporting a bounded
        # score keeps the table readable without hiding the deviation.
        z = np.clip(z, -50.0, 50.0)
        contribution = np.abs(z) * self._importance_norm * 100.0

        order = np.argsort(contribution)[::-1][:top_k]
        out: List[Dict[str, Any]] = []
        for idx in order:
            feature = self.features[idx]
            value = float(raw[feature])
            benign_mean = (
                float(self.anomaly.raw_mean_[idx])
                if self.anomaly.raw_mean_ is not None
                else 0.0
            )
            out.append(
                {
                    "feature": feature,
                    "label": FEATURE_LABELS.get(feature, feature),
                    "value": round(value, 3),
                    "benign_mean": round(benign_mean, 3),
                    "z_score": round(float(z[idx]), 2),
                    "direction": "elevated" if z[idx] > 0 else "reduced",
                    "importance": round(float(self._importance_norm[idx]), 4),
                    "contribution": round(float(contribution[idx]), 2),
                }
            )
        return out

    def summary_text(self, row: pd.Series, top_k: int = 3) -> str:
        """One-sentence, human-readable ML justification."""
        feats = self.explain(row, top_k=top_k)
        if not feats:
            return "No ML explanation available."
        parts = [
            f"{f['label']} = {f['value']} vs benign mean {f['benign_mean']} (z={f['z_score']:+.1f})"
            for f in feats
        ]
        return "Unusual features: " + "; ".join(parts)

    # ---- persistence ---------------------------------------------------
    def save(self, directory: str | Path) -> Path:
        directory = Path(directory)
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "hybrid_model.joblib"
        joblib.dump(self, path)
        return path

    @staticmethod
    def load(path: str | Path) -> "HybridMLModel":
        obj = joblib.load(str(path))
        if not isinstance(obj, HybridMLModel):
            raise TypeError(f"{path} does not contain a HybridMLModel")
        return obj
