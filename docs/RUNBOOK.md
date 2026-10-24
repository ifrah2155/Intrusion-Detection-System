# Runbook — exact steps

Every command below is copy-pasteable into **PowerShell** on Windows, from the
project root. Expected output is quoted so you can tell whether each step
actually worked before moving on.

Project root:

```
C:\Users\mehwaz\OneDrive\Documents\Default Project\megaminds-ids
```

---

## Step 0 — What you need

| Requirement | Check | Expected |
|---|---|---|
| Python 3.10+ | `python --version` | `Python 3.12.x` |
| pip | `python -m pip --version` | any recent version |
| Disk space | — | ~60 MB (deps + model + captures) |
| Time | — | ~3 min first run, ~40 s after |

No administrator rights, no Npcap, no live network access. Everything runs
offline against generated captures.

---

## Step 1 — Open a terminal in the project root

```powershell
cd "C:\Users\mehwaz\OneDrive\Documents\Default Project\megaminds-ids"
```

Confirm you are in the right place:

```powershell
Get-ChildItem -Name
```

You should see: `README.md  requirements.txt  nids  data  dashboard  docs  models  results  tests`

---

## Step 2 — Install dependencies

```powershell
python -m pip install -r requirements.txt
```

Takes 1–3 minutes the first time. If you see warnings about scripts not being
on `PATH` (`scapy.exe`, `streamlit.exe`), ignore them — every command in this
runbook uses `python -m`, which does not need `PATH`.

Verify the important ones:

```powershell
python -c "import scapy, sklearn, streamlit, pandas, matplotlib; print('deps ok')"
```

Expected: `deps ok`

> **Optional but recommended:** isolate the install.
> ```powershell
> python -m venv .venv
> Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
> .\.venv\Scripts\Activate.ps1
> python -m pip install -r requirements.txt
> ```
> Your prompt will show `(.venv)` when it is active. Every later command is unchanged.

---

## Step 3 — Generate the labelled dataset

```powershell
python -m nids generate
```

Expected output:

```
Generating 6 capture(s) into ...\data\pcaps

  scenario_1_benign             940 packets    240.2 KB    71 flows
      benign         71 flows

  scenario_2_port_scan         1132 packets    253.3 KB   243 flows
      port_scan     172 flows
      benign         71 flows

  scenario_3_dos               3228 packets    569.7 KB  2257 flows
      dos          2201 flows
      benign         56 flows

  scenario_4_brute_force        928 packets    213.6 KB    90 flows
      benign         60 flows
      brute_force    30 flows

  scenario_5_ambiguous         2706 packets   1625.0 KB   130 flows
      benign        105 flows
      port_scan      25 flows

  scenario_6_mitm_arp           842 packets    188.4 KB    53 flows
      benign         52 flows
      mitm            1 flows

Manifest written to ...\data\manifest.json
```

**Checkpoint:** 6 captures, **9,776 packets, 2,844 flows** in total. If you see
`0 flows`, the pcap was written without Scapy's layers registered — that bug is
already fixed, so seeing it means you are running an old copy.

---

## Step 4 — Train the models

```powershell
python -m nids train
```

Expected (the numbers that matter):

```
  training flows : 1982 (157 benign, 1825 attack)
  held-out flows : 679
  attack classes : ['brute_force', 'dos', 'port_scan']
  model saved    : ...\models\hybrid_model.joblib
```

Takes 10–25 seconds. Two things to notice:

* **1,982 train / 679 test** — roughly the 65/35 target. If you see something
  like 583/2078, the group-split candidate search did not run.
* **Scenarios 5 and 6 are absent from `attack classes`** — they are never
  trained on. That is deliberate.

Output ends with a JSON metadata block showing `"features": 55`.

---

## Step 5 — Analyse one capture

```powershell
python -m nids analyze -p data/pcaps/scenario_2_port_scan.pcap
```

Expected:

```
  flows analysed : 243
  packets        : 1132
  duration       : 150.0 s
  ground truth   : {'port_scan': 172, 'benign': 71}
  alerts         : 3
  by severity    : {'CRITICAL': 2, 'HIGH': 1}

ID      TIME(UTC)  SEVERITY  RULE     CATEGORY     SOURCE           TARGET                 FLOWS  CONF
------------------------------------------------------------------------------------------------------
A-0001  00:00:20   CRITICAL  R-001    port_scan    10.0.0.66        10.0.0.10:1              120  0.99
A-0002  00:00:45   CRITICAL  R-002    port_scan    10.0.0.66        10.0.0.100:80             40  0.98
A-0003  00:01:10   HIGH      R-008    port_scan    10.0.0.66        10.0.0.10:21              12  0.88
```

**172 attack flows, 3 alerts.** That gap is the incident grouping — 120 probes
become one alert carrying 120 flows, not 120 alerts.

---

## Step 6 — Read the explanation (the important command)

```powershell
python -m nids analyze -p data/pcaps/scenario_2_port_scan.pcap --explain A-0001
```

Expected, in three blocks:

```
  WHY IT FIRED
  10.0.0.66 sent TCP SYN probes to 120 distinct destination ports within a 10s
  window (threshold 15), of which 120 never received a SYN/ACK. ...

  EVIDENCE
    observed_unique_ports                120
    threshold_unique_ports               15
    unanswered_probes                    120
    port_entropy                         6.907

  ML FEATURE ATTRIBUTION (deviation from benign baseline)
    distinct ports touched by source     120.0   benign 1.561   z=+50.0
    ...
  ML: ML corroborates: Isolation Forest score 0.79, Random Forest attack probability 1.00.
```

Read it top to bottom: **what fired → observed vs threshold → which features
deviated → did the other layer agree.** That is the whole explainability story
in one screen.

To explain every alert in a capture, swap `--explain A-0001` for `--detailed`.

---

## Step 7 — Score the whole system

```powershell
python -m nids evaluate --charts
```

Expected:

```
| Layer     | TP   | FP | TN  | FN | Precision | Recall | F1    | Accuracy | FPR   |
| signature | 2403 | 40 | 375 | 26 | 0.984     | 0.989  | 0.987 | 0.977    | 0.096 |
| ml        | 2411 | 41 | 374 | 18 | 0.983     | 0.993  | 0.988 | 0.979    | 0.099 |
| hybrid    | 2428 | 40 | 375 | 1  | 0.984     | 1.000  | 0.992 | 0.986    | 0.096 |
```

Then alert-level precision `0.9167` (12 alerts: 11 TP, 1 FP), and a Layer-2
block reporting 2 ARP events detected.

Writes to `results/`:

| File | Contents |
|---|---|
| `evaluation.json` | every number, per scenario, per class, plus FP/FN examples |
| `confusion_matrices.png` | three panels side by side |
| `alerts_by_scenario.png` | attack flows vs alerts raised |
| `ml_score_distribution.png` | benign vs attack score overlap |
| `flows.csv` | all 2,844 scored flows |
| `<scenario>.alerts.json` | full explainable alert payloads |

---

## Step 8 — Run all six scenarios in sequence

```powershell
python -m nids demo --pause
```

Press **Enter** between scenarios. Expected alert counts:

| Scenario | Alerts |
|---|---|
| 1 benign | **0** |
| 2 port scan | 3 |
| 3 DoS | 3 |
| 4 brute force | 2 |
| 5 ambiguous | 2 |
| 6 ARP/MITM | 2 |

Without `--pause` it runs straight through (~15 s). Add `--explain-first` to
print the full explanation of the first alert in each scenario.

To run one scenario only:

```powershell
python -m nids demo --scenario scenario_5_ambiguous
```

---

## Step 9 — Open the dashboard

In a **second** terminal (leave it running):

```powershell
cd "C:\Users\mehwaz\OneDrive\Documents\Default Project\megaminds-ids"
streamlit run dashboard/app.py
```

It opens `http://localhost:8501` automatically. Takes ~5 s.

In the browser:

1. Sidebar → **Bundled capture** → `scenario_2_port_scan`
2. Press **▶ Analyse traffic**
3. Four metric tiles appear: Flows 243 · Alerts 3 · Critical 2 · High 1
4. Under **🚨 Alerts**, pick `A-0001` in the *Inspect an alert* box
5. Walk the four tabs: **Evidence**, **ML attribution**, **Affected flows**, **Raw alert**
6. Drag **Port-scan threshold** from 15 to 40 → press Analyse again → the
   vertical scan disappears. Drag back to 15 → it returns.

Stop it with `Ctrl+C` in that terminal.

---

## Step 10 — Run the tests

```powershell
python -m pytest tests -q
```

Expected:

```
..................................                                       [100%]
34 passed in 5.79s
```

If you are recording, run this **before** you hit record, not during.

---

## Step 11 — Rebuild the PDF

```powershell
python tools/build_report_pdf.py
```

Expected:

```
  pandoc  : ...\pandoc.exe
  xelatex : ...\xelatex.EXE
  markdown -> latex ... ok
  xelatex : pass 1/3 ... ok
  xelatex : pass 2/3 ... ok
  xelatex : pass 3/3 ... ok
  glyphs  : all characters rendered
  pages   : 7

  written : ...\docs\REPORT.pdf  (113 KB)
```

Needs pandoc and MiKTeX. Both are installed here; on a clean machine:

```powershell
python -m pip install pypandoc-binary
winget install MiKTeX.MiKTeX
```

Check the report is still inside the word limit:

```powershell
python tools/wordcount.py
```

Expected: `prose words : 1898` and `in range : yes (target 1500-2000)`.

---

## Step 12 — Publish to GitHub

```powershell
git status --short
git log --oneline
```

Both should be quiet: no uncommitted files, one commit.

With the GitHub CLI:

```powershell
gh repo create megaminds-ids --public --source . --push
```

Without it, create an empty repo on github.com first, then:

```powershell
git remote add origin https://github.com/<your-username>/megaminds-ids.git
git branch -M main
git push -u origin main
```

Then check the repo renders: open it on github.com, confirm the README shows
the results table and that `docs/REPORT.pdf` is downloadable.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `No captures in ...\data\pcaps` | dataset not generated | `python -m nids generate` |
| `No trained model at ...` | model missing | `python -m nids train` |
| `0 flows` extracted | Scapy layers not registered | you are on an old copy — `git pull` |
| Alerts differ from this document | model or thresholds changed | `python -m nids generate --seed 7` then `python -m nids train` |
| `streamlit: command not found` | Scripts dir not on `PATH` | use `python -m streamlit run dashboard/app.py` |
| Streamlit port busy | old server still alive | add `--server.port 8502` |
| Table wraps badly in the terminal | window too narrow | widen to ~110 columns |
| `pdflatex`/`xelatex` missing | MiKTeX not installed | `winget install MiKTeX.MiKTeX`, then rebuild |
| PowerShell kills a long command | `Select-Object -First N` closes the pipe | never pipe a command you need to finish |
| Charts take 8 s on first run | matplotlib font cache | run `--charts` once before recording |

---

## Timing expectations

| Action | Cold | Warm |
|---|---|---|
| `generate` | ~12 s | ~12 s |
| `train` | ~25 s | ~20 s |
| `analyze` (one capture) | ~4 s | ~2 s |
| `evaluate --charts` | ~25 s | ~18 s |
| `demo` (all six) | ~18 s | ~14 s |
| `pytest` | ~7 s | ~6 s |
| `build_report_pdf.py` | ~25 s | ~12 s |

"Cold" includes the one-off cost of loading scikit-learn and building
matplotlib's font cache. Do one warm-up run before recording so nothing stalls
on camera.
