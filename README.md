# AI-Driven Network Traffic Analysis & Intrusion Detection System

A hybrid network intrusion detection system that ingests packet captures,
reconstructs bidirectional flows, extracts behavioural features, and detects
port scanning, denial-of-service, credential brute-force and ARP-poisoning
attacks — **with a written justification for every alert it raises**.

Every detection is explainable: which rule fired, which observed value crossed
which threshold, how far the flow deviates from the benign baseline, and whether
the two detection layers agree.

```
Signature layer (9 rules)  ─┐
                            ├─→  Fusion & severity  ─→  Explainable incident
ML layer (IF + RF)         ─┘        scoring              + evidence + attribution
```

---

## Results at a glance

Evaluated on 2,844 labelled flows across six captures:

| Layer | Precision | Recall | F1 | Accuracy |
|---|---|---|---|---|
| Signature only | 0.984 | 0.989 | 0.987 | 0.977 |
| ML only | 0.983 | 0.993 | 0.988 | 0.979 |
| **Hybrid (shipped)** | **0.984** | **1.000** | **0.992** | **0.986** |

* **12 alerts** across all six captures — 11 true positives, 1 false positive
  (an *authorised* vulnerability scan), giving alert-level precision **0.917**.
* **Zero alerts** on the benign baseline capture (`scenario_1_benign`).
* On the five non-ambiguous scenarios the hybrid produces **0 false-positive
  flows**; every false positive in the table above (40 flows) comes from the
  deliberately ambiguous scenario.
* The hybrid recovers a **slow scan that the rule layer misses entirely**, which
  is the concrete reason for combining the two approaches.

Full numbers, confusion matrices and failure analysis: [`results/evaluation.json`](results/evaluation.json)
and [`docs/REPORT.md`](docs/REPORT.md).

---

## Quickstart

```bash
# 1. install
pip install -r requirements.txt

# 2. generate the labelled dataset (deterministic, seeded)
python -m nids generate

# 3. train the ML models
python -m nids train

# 4. analyse a capture
python -m nids analyze -p data/pcaps/scenario_2_port_scan.pcap --explain A-0001

# 5. score the whole system against ground truth
python -m nids evaluate --charts

# 6. optional: analyst dashboard
streamlit run dashboard/app.py
```

Tested on Windows 11 with Python 3.12; no platform-specific code.

### The five mandated scenarios

```bash
python -m nids demo --pause          # walks all six captures with narration
```

| Scenario | Capture | What it demonstrates |
|---|---|---|
| 1 — Benign baseline | `scenario_1_benign.pcap` | 71 flows, **0 alerts** |
| 2 — Reconnaissance | `scenario_2_port_scan.pcap` | vertical (120 ports), horizontal (40 hosts), NULL & XMAS scans |
| 3 — Denial of service | `scenario_3_dos.pcap` | distributed SYN flood (60 sources), UDP flood, ICMP flood |
| 4 — Additional attack | `scenario_4_brute_force.pcap` | SSH + RDP credential brute force |
| 5 — Ambiguous / missed | `scenario_5_ambiguous.pcap` | authorised scanner (FP), slow scan (rule miss → ML catch), bulk backup |
| Bonus — MITM | `scenario_6_mitm_arp.pcap` | ARP cache poisoning of the gateway and server |

---

## How it works

### 1 · Traffic data

Captures are **synthesised with Scapy** (`data/generate_dataset.py`) rather than
recorded live. This was a deliberate trade-off:

* **Ground truth is exact.** Every flow carries a label because the generator
  knows which packets it crafted as an attack. No manual labelling, no
  ambiguity about where an attack starts and stops.
* **Fully reproducible.** One seed produces byte-identical traffic on any
  machine, so the evaluator can re-run everything.
* **No privileged access needed.** Live capture requires Npcap/admin rights and
  is impossible to reproduce in CI; public datasets (CICIDS2017, NSL-KDD) are
  static and cannot demonstrate a *runnable* pipeline end to end.

The trade-off is realism: the traffic is structurally valid (correct TCP
handshakes, sequence numbers, flag semantics, realistic payload sizes) but it
is not a real network. Limitations are discussed honestly in the report.

The network models a small enterprise: gateway `10.0.0.1`, web server
`10.0.0.10`, database `10.0.0.11`, seven client hosts, an audit station
`10.0.0.200`, and external destinations.

### 2 · Feature extraction — 55 features

`nids/features.py` streams the pcap (never loading it whole), folds packets into
**bidirectional 5-tuple flows** with a 60 s idle timeout, then derives:

| Group | Examples | Why |
|---|---|---|
| Volume & timing | duration, packet/byte rate, payload ratio | separates floods from normal sessions |
| Packet-size distribution | mean/std/min/max per direction | floods use uniformly small packets |
| Inter-arrival times | mean, std, max, min | automated traffic is metronomic |
| TCP flag behaviour | SYN/ACK/RST ratios, `handshake_completed`, `failed_handshake`, `null_scan`, `xmas_scan` | half-open connections are the core scan/flood signal |
| Host behaviour (10 s window) | distinct destination hosts/ports, **Shannon entropy of destination ports**, fan-in at a victim, peak packets-per-second | distinguishes a scan from a busy client |
| Protocol / endpoint | TCP/UDP/ICMP one-hots, well-known-port flag | cheap context |

Two design decisions worth calling out:

* **Peak pps, not window-average pps.** A 300-packet burst inside one second of
  a 10-second window averages to 30 pps and would slip past every flood
  threshold. Rates are therefore the maximum of the per-second sub-buckets.
* **Port entropy.** A client touching 20 ports of one service has low entropy;
  a scanner sweeping 120 ports has entropy ≈ log₂(120) ≈ 6.9. This single
  feature separates the two cases far more cleanly than a raw port count.

### 3 · Detection

**Layer 1 — deterministic rules** (`nids/rules.py`). Nine single-purpose
predicates, each with explicit, configurable thresholds:

| ID | Rule | Core logic |
|---|---|---|
| R-001 | Vertical port scan | ≥15 distinct ports in 10 s, SYN ratio ≥0.40, ≥5 unanswered probes |
| R-002 | Horizontal port scan | ≥10 distinct hosts, ≤3 distinct ports |
| R-003 | SYN flood (fan-in) | ≥40 distinct sources at one victim, victim ≥150 pps, SYN ratio ≥0.6 |
| R-003b | SYN flood (single source) | ≥100 pps from one source, SYN ratio ≥0.8 |
| R-004 | UDP flood | UDP and ≥200 pps |
| R-005 | ICMP flood | ICMP and ≥100 pps |
| R-006 | Credential brute force | ≥8 sessions to :22/:3389 in 10 s, each ≤1.5 s or ≤8 packets |
| R-007 | ARP cache poisoning | one IP announced by ≥2 distinct MACs |
| R-008 | NULL / XMAS scan | TCP flags `0x00` or FIN+PSH+URG |

**Layer 2 — machine learning** (`nids/ml.py`).

* *Isolation Forest* trained on **benign flows only**. It never sees an attack,
  so it can in principle flag behaviour no rule and no classifier was taught.
* *Random Forest* on labelled flows, `class_weight="balanced"` to counter the
  severe attack/benign imbalance.
* Heavy-tailed counters are `log1p`-compressed so a 100 MB transfer cannot
  dominate every distance metric. The raw `dst_port` integer is deliberately
  excluded — otherwise the model learns "port 3389 is a big number" instead of
  learning behaviour.

**Fusion** (`nids/engine.py`).

* Flow hits are collapsed into **one incident per (rule, entity, time window)**.
  A 120-port scan is one alert with 120 attached flows, not 120 alerts.
* Agreement between layers **raises** severity; **disagreement never lowers it** —
  a probabilistic model must not override deterministic evidence. Disagreement
  is instead surfaced in plain text and reflected in a lower confidence score.
* ML-only detections are emitted as `LOW`/`MEDIUM` leads, require at least two
  flows, and are grouped per source so a slow multi-window attack stays one alert.

### 4 · Explainability

Every alert carries, in JSON, CSV, console and dashboard:

```
A-0001  |  CRITICAL  |  VERTICAL_PORT_SCAN (R-001)
  WHY IT FIRED
  10.0.0.66 sent TCP SYN probes to 120 distinct destination ports within a 10s
  window (threshold 15), of which 120 never received a SYN/ACK. ...
  The ML layer independently flagged these flows (anomaly score 0.79, attack
  probability 1.00), which raises confidence.

  EVIDENCE
    observed_unique_ports        120
    threshold_unique_ports       15
    unanswered_probes            120
    port_entropy                 6.907

  ML FEATURE ATTRIBUTION (deviation from benign baseline)
    distinct ports touched by source     120.0   benign 1.561   z=+50.0
    entropy of destination ports           6.9   benign 0.535   z=+11.4
```

Feature attribution is `|z-score vs the benign baseline| × global model
importance` — two quantities a reviewer can verify by hand, rather than an
opaque SHAP value.

---

## Repository layout

```
megaminds-ids/
├── nids/                     # the library
│   ├── features.py           # parsing, flow reconstruction, 55 features, ARP analysis
│   ├── rules.py              # 9 signature rules
│   ├── ml.py                 # Isolation Forest + Random Forest + attribution
│   ├── engine.py             # fusion, severity, incident grouping, explanations
│   ├── evaluate.py           # precision / recall / F1 / confusion matrices
│   ├── report.py             # JSON/CSV export, console tables, charts
│   ├── train.py              # leakage-safe group split + training
│   └── cli.py                # command line interface
├── dashboard/app.py          # Streamlit analyst console
├── data/
│   ├── generate_dataset.py   # Scapy traffic generator
│   ├── pcaps/                # 6 labelled captures
│   ├── labels/               # flow_key -> label ground truth
│   └── manifest.json
├── models/hybrid_model.joblib
├── results/                  # evaluation.json + charts + per-scenario exports
├── tests/                    # 34 unit + integration tests
└── docs/
    ├── REPORT.md             # technical report
    └── VIDEO_DEMO_GUIDE.md   # shot-by-shot recording script
```

---

## Reproducing the numbers

```bash
python -m nids generate --seed 7     # deterministic
python -m nids train                 # group-split, no leakage
python -m nids evaluate --charts     # writes results/evaluation.json
python -m pytest tests -q            # 34 tests
```

**Evaluation protocol.** Scenarios 1–4 form the development set and are split
by `(scenario, time window)` with `GroupShuffleSplit`, so an entire incident
lands on one side of the split. A per-flow random split would put near-duplicate
scan probes in both train and test and inflate every metric. Scenarios 5 and 6
are never used for training.

---

## Known limitations

* **Synthetic traffic.** The captures are structurally valid but not a real
  network; absolute precision/recall will not transfer unchanged to production.
* **The authorised-scan false positive is a genuine limitation, not a bug.**
  R-001 cannot distinguish an audit from an intrusion without an allow-list.
* **The Isolation Forest contributes little here.** Attack flows score ≈0.74 on
  average versus ≈0.52 for benign — too close to carry decisions alone, which is
  why the classifier is the primary ML signal and IF is a second opinion.
* **No TLS inspection**, so encrypted brute force or exfiltration is invisible
  at this layer.
* **Layer-2 detection is capture-local**: one vantage point sees only the ARP
  traffic on its own segment.
* **Inline throughput** was not measured; the design is offline/batch and would
  need a ring buffer and sampling strategy to run inline.

## Ethical and legal note

All captures in `data/pcaps/` were generated locally from a Python script.
No live network was scanned, no third-party system was touched, and no
credentials were used. Only run this tool against networks you own or are
explicitly authorised to test.
