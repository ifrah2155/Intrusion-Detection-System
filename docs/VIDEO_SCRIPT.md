# Video script — the actual words

A spoken script, not a shot list. Roughly **1,300 words**, which is about
9 minutes at a normal talking pace plus the time the commands take to run.
The shot-by-shot technical version is in `VIDEO_DEMO_GUIDE.md`; this file is
what you say out loud.

**Read it once, then put it down and talk.** It is written the way people speak
— contractions, short sentences, the occasional admission. If you read it
word-for-word in a flat voice it will sound like a script, which is worse than
saying it slightly differently from memory.

---

## How to deliver it

| Do | Don't |
|---|---|
| Pause after a number you want remembered | Rush to fill silence |
| Point at the screen when you say "here" | Read the terminal aloud |
| Say "I" and "I built" | Say "the system utilises" |
| Admit the false positive plainly | Apologise for it or explain it away |
| Keep one hand off the keyboard while talking | Type while narrating |

Speak at about **140 words per minute**. If you find yourself at 170, you are
going too fast and the numbers will not land.

Two passages are marked `[CUT IF RUNNING LONG]`. Drop them and you lose 35
seconds without losing an argument.

---

## Scene 1 · The problem — 0:00

*Screen: nothing. Or the README title. Do not show code yet.*

> Let me start with the problem, because it decides everything else.
>
> Signature-based detection is precise. It's fast, it's easy to explain, and
> when it fires you know exactly why. But it only knows what somebody already
> wrote a rule for. A new scanner variant, a flood turned down to just under
> your threshold, a scan spread over ten minutes — all of that walks straight
> past it.
>
> Machine learning has the opposite problem. It generalises. It catches things
> nobody wrote a rule for. But then it hands you a number, and "this flow
> scored 0.87" is not something an analyst can act on. You can't defend that
> in a report.
>
> So the problem I set out to solve wasn't "detect attacks". It was: detect
> attacks, and still be able to justify every single alert to a human. That's
> why I built a hybrid — rules for precision and accountability, machine
> learning for generalisation, and a fusion layer that makes them check each
> other.

---

## Scene 2 · Architecture — 0:45

*Screen: the pipeline diagram in the report, section 4.*

> Here's the shape of it.
>
> A pcap goes in. It's streamed, not loaded whole, and folded into
> bidirectional flows — one conversation per five-tuple. Those flows become a
> fifty-five feature table. Two detectors read that table independently: nine
> deterministic rules, and a pair of models, an Isolation Forest and a Random
> Forest. Their output is fused into incidents, and every incident is rendered
> with the evidence behind it.
>
> The decision I care most about is at the fusion step. When the two layers
> agree, severity goes up. When they disagree, severity does **not** go down.
> A rule firing means a hundred and twenty unanswered SYNs actually happened —
> that's deterministic. I'm not letting a probabilistic model overrule it.
> Disagreement shows up as lower confidence, and as a sentence in the alert
> saying the ML layer didn't corroborate this.

---

## Scene 3 · Where the traffic comes from — 1:35

*Screen: `data/manifest.json`, or the output of `python -m nids generate`.*

> Now, where the traffic comes from, because this is a trade-off and I'd
> rather be straight about it.
>
> I generated the captures with Scapy instead of recording them. The reason is
> ground truth. Because the generator crafts each packet, I know exactly which
> flow is an attack and which is background. No manual labelling, no arguing
> about where an attack starts.
>
> It's also reproducible — one seed gives identical traffic on any machine —
> and it needs no Npcap, no admin rights, no live network.
>
> The cost is realism, and it's a real cost. The traffic is structurally valid:
> real handshakes, real sequence numbers, legal flag combinations. But it is
> not a real network. No jitter, no retransmissions, no unrelated noise. So my
> numbers measure methodology and internal consistency, not production
> performance. I say that in the report too.
>
> Six captures. Nine thousand seven hundred packets. Two thousand eight
> hundred flows.

---

## Scene 4 · Features — 2:25

*Screen: the feature table in the README, then the flows DataFrame.*

> Features come in three groups.
>
> Per-flow volume and timing — rates, packet sizes, gaps between packets.
> Automated traffic is metronomic. People are bursty.
>
> TCP flag behaviour. And the single most useful feature in the whole system
> is `failed_handshake`: a SYN that never got a SYN/ACK back. A port scan is,
> by definition, a pile of connections that never complete. That one feature
> does a lot of work.
>
> Then host behaviour over a ten-second window. How many hosts and ports a
> source touched, how many sources hit one victim, and the entropy of the
> destination ports.
>
> Entropy is the one I'd point at. A client hitting twenty ports of one service
> has low entropy. A scanner sweeping a hundred and twenty ports has entropy
> around six point nine — that's log base two of a hundred and twenty. It
> measures how spread out the sweep is, not just how big.
>
> One thing I got wrong at first: I was reporting packets per second averaged
> over the window. A three-hundred-packet burst inside one second of a
> ten-second window averages to thirty, and thirty slides under every flood
> threshold. So rates are peak-per-second now.

---

## Scene 5 · Scenario 1, the baseline — 3:20

```powershell
python -m nids demo --scenario scenario_1_benign
```

> Scenario one is just a normal day. Web, DNS, admin SSH, ping, NTP, database
> queries.
>
> Seventy-one flows. Zero alerts.
>
> That's the number I care about most, actually. The models were trained on
> benign traffic, and a model that's overfit will light up on clean data. This
> one doesn't. If I'd got alerts here, everything after it would be noise.

---

## Scene 6 · Scenario 2, and the explanation — 4:00

*This is the most important scene. Slow down.*

```powershell
python -m nids demo --scenario scenario_2_port_scan
```

> Scenario two is reconnaissance: a hundred-and-twenty-port vertical scan, a
> horizontal sweep across forty hosts, and then some NULL and XMAS probes.
>
> Three alerts. Not a hundred and seventy-two. The hundred and twenty probes
> became one alert that carries all hundred and twenty flows. That's incident
> grouping — an analyst wants one thing to look at, not a wall of them.

```powershell
python -m nids analyze -p data/pcaps/scenario_2_port_scan.pcap --explain A-0001
```

> Now the part that matters most — why did this fire?
>
> Because that source touched a hundred and twenty distinct ports inside ten
> seconds, against a threshold of fifteen. And all hundred and twenty of them
> never got a SYN/ACK back.
>
> Underneath that, the evidence block gives you the observed value next to the
> threshold, so you can check my arithmetic yourself. Port entropy is six point
> nine, which is log base two of a hundred and twenty — consistent with a
> uniform sweep.
>
> Then the feature attribution, which ranks what pushed this flow away from the
> benign baseline. Unanswered probes: a hundred and twenty, against a benign
> average of zero. And that isn't a black box — it's the z-score multiplied by
> the model's feature importance. Both of those you can inspect.
>
> Confidence is 0.99 because both layers agree. The Random Forest put attack
> probability at 1.00, independently.

---

## Scene 7 · Scenario 3, denial of service — 5:00

```powershell
python -m nids demo --scenario scenario_3_dos
```

> Scenario three: three different floods, three alerts.
>
> The one worth looking at is the SYN flood. Sixty spoofed source addresses,
> eighteen hundred attacking flows, and it collapses into one critical alert.
>
> And here's why that's hard. Per-source rules see nothing. Each spoofed
> address only sends about thirty packets — that's not suspicious at all. It's
> caught by fan-in: sixty distinct sources converging on one victim at over a
> hundred and fifty packets a second, all SYN, none of them completing a
> handshake.
>
> That's the difference between counting packets and looking at behaviour.

---

## Scene 8 · Scenario 4, brute force — 5:45

```powershell
python -m nids demo --scenario scenario_4_brute_force
```

> Scenario four is my extra attack: credential brute force. Eighteen failed SSH
> logins, twelve failed RDP.
>
> Notice the rule isn't "lots of packets". It's lots of *short* sessions. Each
> attempt lives about a tenth of a second and six packets — connect, banner,
> credential, reset. Eight or more of those in ten seconds against an
> authentication port is a script guessing passwords.
>
> A single admin session, however long it runs, doesn't trigger it. There's a
> unit test for exactly that, because a rule that fires on legitimate SSH would
> be useless.

---

## Scene 9 · Scenario 5, the ambiguous case — 6:20

*Do not rush this one. It is where the marks are.*

```powershell
python -m nids demo --scenario scenario_5_ambiguous
```

> Scenario five exists to show you where this breaks.
>
> First alert: critical port scan from ten-dot-zero-dot-zero-dot-two-hundred.
> That's a false positive. That host is an authorised audit station running a
> vulnerability scan. At packet level it is genuinely identical to
> reconnaissance, and no threshold can tell them apart without an allow-list.
> I labelled it benign in the ground truth on purpose, so the mistake shows up
> in my metrics instead of disappearing.
>
> The second alert is the opposite failure, and it's the best argument I have
> for a hybrid. Ten-dot-zero-dot-zero-dot-seventy-seven is scanning at one
> probe every three seconds. No ten-second window ever reaches fifteen ports,
> so the rules miss it completely — zero detections. The Random Forest catches
> all twenty-five flows, mean probability 0.94. That's a detection the rule
> layer structurally cannot make.
>
> There's a third case: the bulk backup. It scored 0.52 — just over the
> classifier's threshold — and it did *not* become an alert, because ML-only
> alerts need at least two flows. That gate is why a legitimate backup doesn't
> turn into a false alarm.

---

## Scene 10 · Scenario 6, ARP poisoning — 7:10

`[CUT IF RUNNING LONG — saves 35s]`

```powershell
python -m nids demo --scenario scenario_6_mitm_arp
```

> Last one, a bonus: ARP cache poisoning.
>
> ARP has no IP five-tuple, so it runs down a separate layer-2 path. Same
> detector, different evidence.
>
> The gateway's IP gets announced by two different MAC addresses — first the
> real router, then the attacker's. Same for the web server. Both come out
> critical.
>
> I'm explicit in the report that this is scored at event level, not through
> the flow matrix, because the attack lives in the control plane. The victim's
> traffic afterwards looks completely ordinary.

---

## Scene 11 · Evaluation — 7:40

*Screen: `results/confusion_matrices.png`, then the metrics table.*

> Evaluation. Three configurations, scored on the same flows.
>
> Signature alone: recall 0.989, precision 0.984. It misses twenty-six flows —
> the slow scan.
>
> ML alone: recall 0.993, but it misses eighteen brute-force flows, because
> after the group split it had very few examples to learn from.
>
> Hybrid: recall 1.000, precision 0.984, F1 0.992. Each layer covers the
> other's blind spot.
>
> Twelve alerts in total. Eleven true positives, one false positive, so
> alert-level precision is 0.917. And all forty false-positive flows come from
> that deliberately ambiguous capture — on the other five, the false-positive
> rate is zero.
>
> One methodological thing, because it's easy to cheat here. I split train and
> test by time window, not by flow. Split randomly and near-identical probes
> from the same scan land on both sides, and every number goes up. Scenarios
> five and six were never trained on at all.

---

## Scene 12 · Limitations — 8:40

> Where this falls short.
>
> The traffic is synthetic. Valid structure, but no real jitter, no
> retransmissions, no unrelated noise. Absolute numbers won't transfer to
> production as they are.
>
> The Isolation Forest underperforms here — attack flows average 0.74, benign
> 0.52, too close together to carry a decision alone. I kept it as a second
> opinion rather than pretending it's the primary detector.
>
> No TLS inspection, so encrypted brute force or exfiltration is invisible at
> this layer.
>
> And no inline throughput measurement. This is a batch pipeline. Running it
> inline needs a ring buffer and sampling, and p99 latency would rise.

`[CUT IF RUNNING LONG — saves 20s]`

> The authorised-scan false positive is a real limitation, not something I can
> tune away. Fixing it needs an allow-list, which is a policy decision, not a
> threshold.

---

## Scene 13 · Close — 9:25

> So: a hybrid detector where every alert can be defended. Which rule, which
> observed value, which threshold, how far from normal, and whether the other
> layer agreed.
>
> Recall 1.000, precision 0.984, zero false positives on every non-ambiguous
> capture, and an honest account of the one case it gets wrong.
>
> The code, the dataset, the tests, the evaluation and the report are all in
> the repository. Thanks for watching.

---

## If you are running over

Cut in this order:

1. Scene 10 (ARP bonus) — 35 s
2. The last paragraph of Scene 12 — 20 s
3. The entropy explanation in Scene 4 — 25 s
4. Scene 8's unit-test sentence — 12 s

That is 92 seconds of slack. **Never** cut Scene 6 or Scene 9 — those are the
two scenes that demonstrate the required capabilities.

## Numbers to have straight

| Thing | Value |
|---|---|
| Packets / flows | 9,776 / 2,844 |
| Features / rules | 55 / 9 |
| Hybrid precision / recall / F1 | 0.984 / 1.000 / 0.992 |
| Alerts | 12 total — 11 TP, 1 FP |
| Alert precision | 0.917 |
| Benign baseline | 71 flows, 0 alerts |
| Slow scan | 25 flows missed by rules, caught by ML at 0.94 |
| Authorised scan | 40 flows, false positive, deliberate |

If you blank on a number, say "about" and move on. A pause costs more than a
rounded figure.
