"""AI-Driven Network Traffic Analysis and Intrusion Detection System.

A hybrid (signature + machine-learning) network intrusion detection system that
ingests packet captures, extracts bidirectional flow and host-behaviour
features, and produces analyst-grade, explainable alerts.

Package layout
--------------
``features``  packet parsing, flow reconstruction, feature extraction
``rules``     deterministic signature/rule layer
``ml``        statistical / machine-learning layer (Isolation Forest + Random Forest)
``engine``    hybrid fusion, severity scoring and explanation generation
``evaluate``  ground-truth scoring (precision / recall / F1 / confusion matrix)
``report``    console, JSON, CSV and chart rendering
``cli``       command line interface
"""

__version__ = "1.0.0"

from .constants import (  # noqa: F401
    BENIGN,
    BRUTE_FORCE,
    DOS,
    MITM,
    PORT_SCAN,
    SEVERITY_ORDER,
    AttackLabel,
)

__all__ = [
    "__version__",
    "BENIGN",
    "PORT_SCAN",
    "DOS",
    "BRUTE_FORCE",
    "MITM",
    "SEVERITY_ORDER",
    "AttackLabel",
]
