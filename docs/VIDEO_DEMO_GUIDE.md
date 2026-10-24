# Video Demonstration Guide

**Target length: 9–10 minutes.** The brief requires 8–10 minutes and explicitly
says a source-code-only walkthrough is *not* sufficient, so this script is
built around **running the system and interpreting its output**, not reading
code.

---

## Before you hit record

### 1. Reset to a known-good state

Open PowerShell in the project root and run:

```powershell
python -m nids generate --seed 7
python -m nids train
python -m nids evaluate --charts
python -m pytest tests -q
```

You should see `34 passed`. If anything fails, fix it **before** recording.

### 2. Pre-warm everything

Run once so nothing is slow or downloads on camera:

```powershell
python -m nids demo
```

First-run cost (loading the model, matplotlib font cache) is now paid.

### 3. Screen setup

| Setting | Value |
|---|---|
| Terminal font size | 16–18 pt (readable after compression) |
| Terminal width | ~110 columns (the alert table is wide) |
| Window | Maximise; hide the taskbar |
| Shell | PowerShell or Windows Terminal |
| Resolution | 1920×1080, recorded at 30 fps |

Do **not** use a dark terminal with low contrast — tables with `CRITICAL` rows
become unreadable after video compression.

### 4. Keep these three windows ready

1. **Terminal** — project root
2. **Browser tab** — `http://localhost:8501` (Streamlit)
3. **File explorer** — `results/` folder (for the charts)

Start Streamlit in a second terminal *before* recording:

```powershell
streamlit run dashboard/app.py
```

Leave it running. It takes ~5 s to boot; don't waste video time on it.

### 5. Have this open in a note for your own reference

- 9,776 packets · 2,844 flows · 55 features · 9 rules
- Hybrid: precision 0.984 · recall 1.000 · F1 0.992
- 12 alerts → 11 true positives, 1 false positive
- Scenario 1: zero alerts

---

## Shot list

### Scene 1 — Problem statement (0:00 – 0:45)

**Show:** a plain text slide or the README title block.
**Do not** show code yet.

**Say (roughly):**

> "Signature-based IDS are precise but blind to anything not already in their
> rule set — a new scanner variant, a slower flood rate, or a scan spread over
> minutes will walk straight through. Machine learning generalises, but it
> hands the analyst a number with no explanation, and an unexplained score of
> 0.87 is not actionable.
>
> So the problem I set out to solve is not just *detect attacks*. It's detect
> them while keeping every decision justifiable to a human. My answer is a
> hybrid: deterministic rules for precision and accountability, machine
> learning for generalisation — and a fusion layer that makes them argue with
> each other in public."

**Why this works:** it states the trade-off, the design decision and the
result in 40 seconds, which is what evaluators are listening for.

---

### Scene 2 — Architecture (0:45 – 1:35)

**Show:** the ASCII diagram in `README.md`, scrolled to the "How it works"
section. Then `python -m nids rules` to flash the rule catalogue.

**Say:**

> "The pipeline is linear and every stage is a pure function.
>
> A pcap is streamed — never loaded whole — and folded into bidirectional
> five-tuple flows. Flows become a 55-feature matrix. Two independent detectors
> consume that matrix: nine deterministic rules, and an Isolation Forest plus a
> Random Forest. Their outputs are fused into *incidents* — one alert per
> attacker behaviour, not per packet — and every incident is rendered with its
> evidence.
>
> The important design choice is at the fusion step: when the layers agree,
> severity goes up. When they disagree, severity **never** goes down — because
> a probabilistic model must not be allowed to overrule deterministic
> evidence. Disagreement shows up as lower confidence and an explicit sentence
> in the alert."

---

### Scene 3 — Traffic data (1:35 – 2:25)

**Show:** `data/manifest.json` (or run `python -m nids generate` and let it
print the table).

**Say:**

> "I generated the traffic with Scapy instead of recording it live, and I want
> to be upfront about why, because it's a real trade-off.
>
> The gain is exact ground truth — the generator knows which packet it crafted
> as an attack, so every flow has a label by construction. It's also
> reproducible from one seed, and it runs without Npcap or admin rights.
>
> The cost is realism: the traffic is structurally valid — real handshakes,
> real sequence numbers, legal flag semantics — but it is not a real network.
> So my absolute numbers measure methodology and internal consistency, not
> production performance. I say that in the report too.
>
> Six captures, 9,776 packets, 2,844 flows: a benign baseline, a port scan, a
> denial of service, a brute force, an ARP-based man-in-the-middle, and one
> capture built specifically to be difficult."

---

### Scene 4 — Feature extraction (2:25 – 3:20)

**Show:** the feature table in the README, **then** this command:

```powershell
python -c "import pandas as pd; pd.set_option('display.width',220); pd.set_option('display.max_columns',None); f=pd.read_csv('results/flows.csv'); print(f[['src_ip','dst_port','total_packets','duration','syn_ratio','src_unique_dst_ports_win','src_port_entropy_win','failed_handshake']].head(8))"
```

**Say:**

> "Three groups of features.
>
> Per-flow volume and timing: rates, packet-size distributions, inter-arrival
> times. Automated traffic is metronomic; user traffic is bursty.
>
> TCP flag behaviour — and the single most discriminative feature in the whole
> system is `failed_handshake`: a SYN that never got a SYN/ACK. A scan is, by
> definition, a stream of connections that never complete.
>
> And host behaviour over a 10-second window: how many distinct hosts and ports
> a source touched, how many sources converged on one victim, and the **entropy
> of the destination-port distribution**. Entropy is the key one. A client
> touching twenty ports of one service has low entropy; a scanner sweeping 120
> ports has entropy of about 6.9. That separates them far better than a raw
> port count.
>
> One subtlety worth flagging: I report **peak packets-per-second**, not window
> averages. A 300-packet burst inside one second of a ten-second window
> averages to 30 pps and would slip under every flood threshold."

---

### Scene 5 — Scenario 1: benign baseline (3:20 – 4:00)

**Command:**

```powershell
python -m nids demo --scenario scenario_1_benign
```

**Show:** the `alerts : 0` line. Point at it.

**Say:**

> "Scenario one is the baseline: web, DNS, admin SSH, ICMP, NTP, database
> traffic. No attacks.
>
> Seventy-one flows, and **zero alerts**. That matters more than it sounds —
> the machine learning layer was trained on benign traffic, so a model that
> over-fits would light up here. It doesn't."

---

### Scene 6 — Scenario 2: port scan + explanation deep-dive (4:00 – 5:00)

**Command:**

```powershell
python -m nids demo --scenario scenario_2_port_scan
```

Three alerts: vertical scan (120 ports), horizontal scan (40 hosts), NULL/XMAS.

Then:

```powershell
python -m nids analyze -p data/pcaps/scenario_2_port_scan.pcap --explain A-0001
```

**This is the most important 60 seconds of the video — slow down here.**

**Say, walking down the output:**

> "Three alerts, not 172. That's the incident grouping: 120 probes become one
> alert carrying 120 flows.
>
> Now the part the brief cares about most — *why*.
>
> The rule fired because this source touched 120 distinct ports inside ten
> seconds, against a threshold of 15, and all 120 never received a SYN/ACK.
>
> Below that, the evidence block gives the observed value and the threshold
> side by side, so an analyst can check my arithmetic. Port entropy is 6.9,
> which is log₂ of 120 — consistent with a uniform sweep.
>
> And the feature attribution ranks what pushed this away from the benign
> baseline. 'Unanswered probes' is 120 against a benign average of zero. That
> is not a black box — both ingredients, the z-score and the model importance,
> are inspectable.
>
> Confidence is 0.99 because both layers agree: the Random Forest put the
> attack probability at 1.00."

---

### Scene 7 — Scenario 3: denial of service (5:00 – 5:45)

**Command:**

```powershell
python -m nids demo --scenario scenario_3_dos
```

**Say:**

> "Three floods, three alerts.
>
> The interesting one is the SYN flood: 60 spoofed sources, 1,800 attacking
> flows, collapsed into a single CRITICAL alert. Per-source rules would see
> nothing here — each spoofed address sends only 30 packets. It's caught by the
> *fan-in* feature: 60 distinct sources converging on one victim at over 150
> packets per second, 100% SYN, none completing a handshake.
>
> That's the difference between counting packets and understanding behaviour.
>
> Then the UDP flood at 400 packets per second and the ICMP flood, both
> single-source, both caught by rate."

---

### Scene 8 — Scenario 4: brute force (5:45 – 6:20)

**Command:**

```powershell
python -m nids demo --scenario scenario_4_brute_force
```

**Say:**

> "My chosen additional attack: credential brute force. Eighteen failed SSH
> logins and twelve failed RDP logins.
>
> The rule isn't 'many packets' — it's *many short sessions*. Each attempt lives
> 0.14 seconds and six packets: connect, banner, credential, reset. Eight or
> more of those in ten seconds against an authentication port is automated
> guessing. A single legitimate admin session, however long, does not trigger
> it — I have a unit test for exactly that."

---

### Scene 9 — Scenario 5: the ambiguous case (6:20 – 7:10)

**Command:**

```powershell
python -m nids demo --scenario scenario_5_ambiguous
```

**Say — this scene earns marks for honesty, don't rush it:**

> "This capture exists to show where the system is wrong.
>
> Alert one is a CRITICAL port scan from 10.0.0.200 — and it's a **false
> positive**. That host is an authorised audit station running a vulnerability
> scan. At the packet level it is indistinguishable from reconnaissance, and no
> threshold can tell them apart without an allow-list. I deliberately labelled
> it *benign* in the ground truth so the false positive shows up in my metrics
> instead of being hidden.
>
> Alert two is the opposite failure — and it's the strongest argument for the
> hybrid. Ten-point-77 is running a scan at one probe every three seconds. No
> ten-second window ever reaches 15 ports, so the rule layer misses it
> **completely**. The Random Forest catches all 25 probes at a mean attack
> probability of 0.94. That's a detection the signature layer structurally
> cannot make.
>
> There's a third case worth mentioning: the bulk backup. It scored 0.52 —
> just above the classifier's threshold — but it was *not* promoted to an alert,
> because ML-only detections require at least two flows. That anti-noise gate
> is why a legitimate backup doesn't become a false alarm."

---

### Scene 10 — Scenario 6: ARP / MITM (7:10 – 7:40)

**Command:**

```powershell
python -m nids demo --scenario scenario_6_mitm_arp
```

**Say:**

> "A bonus attack: ARP cache poisoning. ARP has no IP five-tuple, so it runs on
> a separate layer-2 path — same detector, different evidence.
>
> The gateway's IP is announced by two different MAC addresses: the real router,
> then the attacker's. Same for the web server. Both CRITICAL.
>
> I'm explicit in the report that this is scored at event level, not through the
> flow confusion matrix — because the attack lives in the control plane and the
> victim's redirected traffic looks completely ordinary."

---

### Scene 11 — Evaluation (7:40 – 8:40)

**Show:** `results/confusion_matrices.png`, then
`results/ml_score_distribution.png`, then the metrics table.

**Say:**

> "Three configurations, scored on identical flows.
>
> Signature alone: recall 0.989, precision 0.984. It misses 26 flows — the
> slow scan.
>
> ML alone: recall 0.993, but it misses 18 brute-force flows where it had few
> training exemplars.
>
> Hybrid: recall 1.000, precision 0.984, F1 0.992. Each layer covers the other's
> blind spot.
>
> Twelve alerts total: eleven true positives, one false positive, so
> alert-level precision is 0.917. And every one of those 40 false-positive
> flows comes from the deliberately ambiguous scenario — on the other five
> captures, the false-positive rate is zero.
>
> One methodological point I want to make, because it's easy to cheat here. I
> split train and test by *time window*, not by flow. A random per-flow split
> would put near-duplicate probes from the same scan on both sides and inflate
> every number. Scenarios 5 and 6 were never trained on at all."

---

### Scene 12 — Limitations (8:40 – 9:25)

**Say — do not skip this; it's a scored criterion:**

> "Where this falls short.
>
> One: synthetic traffic. The topology and protocol behaviour are valid, but
> there's no real jitter, no retransmissions, no unrelated background noise.
> Absolute numbers won't transfer to production unchanged.
>
> Two: the Isolation Forest under-performs here. Attack flows average 0.74
> against 0.52 for benign — too close to carry a decision alone. I kept it as a
> second opinion rather than pretending it's the primary detector.
>
> Three: no TLS inspection, so encrypted brute force or exfiltration is
> invisible at this layer.
>
> Four: no inline throughput measurement. This is a batch pipeline; running it
> inline would need a ring buffer and sampling, and p99 latency would rise.
>
> And the authorised-scan false positive is a genuine limitation, not a bug to
> be waved away."

---

### Scene 13 — Conclusion (9:25 – 9:50)

**Say:**

> "What I built is a hybrid detector where every alert can be defended: which
> rule, which observed value, which threshold, how far from the benign
> baseline, and whether the two layers agree.
>
> Recall 1.000, precision 0.984, zero false positives on every non-ambiguous
> capture — and an honest account of the one case it gets wrong.
>
> The code, dataset, tests, evaluation and this report are all in the
> repository. Thank you."

---

## Dashboard segment (optional, +45 s)

If you have time, insert this after Scene 10. It shows the analyst-facing view
and is worth points for "working prototype".

**Show:** browser at `localhost:8501`.

1. Sidebar → capture `scenario_2_port_scan`
2. Press **▶ Analyse traffic**
3. Point at the four metric tiles (flows, alerts, critical, high)
4. In **🚨 Alerts**, click `A-0001` → walk the four tabs:
   - **Evidence** — the threshold table
   - **ML attribution** — the horizontal bar chart ("why is this anomalous")
   - **Affected flows** — the 120 contributing flows
5. Drag the **Port-scan threshold** slider from 15 down to 40 → re-run → the
   vertical scan disappears. This demonstrates the threshold is live, not
   hard-coded.

**Say:** *"This is the same engine, same code path — the dashboard is only a
presentation layer. Notice I can move the threshold and watch the detection
change: that's what makes the sensitivity analysis in the report reproducible."*

---

## Recording checklist

- [ ] First 10 seconds state the problem, not the tech stack
- [ ] Every scenario is **run**, not described
- [ ] At least one alert is explained field by field (Scene 6)
- [ ] Scenario 5 is presented as a genuine failure, without excuses
- [ ] Evaluation slide shows all three layers side by side
- [ ] Limitations get ~45 uninterrupted seconds
- [ ] No dead air; no terminal typos left in
- [ ] Audio is clear (record a separate voice track if the room is noisy)
- [ ] Final length between 8:00 and 10:00

---

## Troubleshooting during recording

| Symptom | Fix |
|---|---|
| `FileNotFoundError: No captures` | `python -m nids generate` |
| `No trained model at …` | `python -m nids train` |
| Streamlit port busy | `streamlit run dashboard/app.py --server.port 8502` |
| Table wraps and looks messy | Widen the terminal to ~110 columns |
| Font cache rebuild on first chart | Already warmed by the pre-flight run |
| Model looks stale after code edits | `python -m nids train` |
