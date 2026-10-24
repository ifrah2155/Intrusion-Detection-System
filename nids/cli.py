"""Command-line interface.

    python -m nids generate                 # build the labelled dataset
    python -m nids train                    # fit the ML models
    python -m nids analyze -p data/pcaps/scenario_2_port_scan.pcap
    python -m nids analyze -p <pcap> --explain A-0001
    python -m nids evaluate --charts
    python -m nids demo                     # all five mandated scenarios
    python -m nids rules                    # print the rule catalogue
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from .config import DATA_DIR, PROJECT_ROOT, RESULTS_DIR, DetectionConfig
from .constants import SEVERITY_ORDER
from .evaluate import evaluate_directory, render_markdown
from .pipeline import analyse_pcap, available_pcaps, ensure_model, load_model
from .report import (
    export_result,
    format_alert_detail,
    format_alerts_table,
    render_evaluation_charts,
)


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def _config_from_args(args: argparse.Namespace) -> DetectionConfig:
    config = DetectionConfig()
    overrides = {}
    if getattr(args, "min_severity", None):
        overrides["report_min_severity"] = args.min_severity.upper()
    if getattr(args, "window", None):
        overrides["window_seconds"] = float(args.window)
    if getattr(args, "scan_ports", None):
        overrides["scan_unique_ports"] = int(args.scan_ports)
    return config.with_overrides(**overrides)


def _print_overview(result, config: DetectionConfig) -> None:
    flows = result.flows
    print()
    print("=" * 78)
    print(f"  CAPTURE : {Path(result.pcap).name if result.pcap else '(dataframe)'}")
    print(f"  SCENARIO: {result.scenario}")
    print("=" * 78)
    print(f"  flows analysed : {len(flows)}")
    if not flows.empty:
        print(f"  packets        : {int(flows['total_packets'].sum())}")
        print(f"  duration       : {flows['end_ts'].max() - flows['start_ts'].min():.1f} s")
        if "label" in flows:
            counts = flows["label"].value_counts().to_dict()
            print(f"  ground truth   : {counts}")
    print(f"  alerts         : {len(result.alerts)}")
    if result.alerts:
        by_sev: dict = {}
        for alert in result.alerts:
            by_sev[alert.severity] = by_sev.get(alert.severity, 0) + 1
        ordered = sorted(by_sev.items(), key=lambda kv: -SEVERITY_ORDER.get(kv[0], 0))
        print(f"  by severity    : {dict(ordered)}")
    print()


# --------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------
def cmd_generate(args: argparse.Namespace) -> int:
    script = PROJECT_ROOT / "data" / "generate_dataset.py"
    cmd = [sys.executable, str(script), "--seed", str(args.seed)]
    for scenario in args.only or []:
        cmd.extend(["--only", scenario])
    return subprocess.call(cmd)


def cmd_train(args: argparse.Namespace) -> int:
    from .train import load_all_features, model_info, train_model

    config = _config_from_args(args)
    df, _ = load_all_features(config=config, use_cache=not args.no_cache)
    train_model(df, config)
    print(json.dumps(model_info(), indent=2))
    return 0


def cmd_analyze(args: argparse.Namespace) -> int:
    config = _config_from_args(args)

    model = None
    if not args.no_ml:
        model = load_model() if args.no_train else ensure_model(config)
        if model is None:
            print("  (no model available - running the signature layer only)")

    result = analyse_pcap(args.pcap, config=config, model=model)
    _print_overview(result, config)

    print(format_alerts_table(result.alerts, max_rows=args.max_rows))
    print()

    if args.explain:
        selected = [a for a in result.alerts if a.alert_id == args.explain]
        if not selected:
            print(f"  No alert with id {args.explain}")
        for alert in selected:
            print(format_alert_detail(alert))

    if args.detailed:
        for alert in result.alerts:
            print(format_alert_detail(alert))

    if not args.no_export:
        paths = export_result(result, Path(args.out))
        print(f"  written: {paths['json']}")
        print(f"  written: {paths['csv']}")

    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    model = None if args.no_ml else ensure_model(config)

    if not available_pcaps():
        print("No captures found. Run: python -m nids generate")
        return 1

    summary = evaluate_directory(config=config, model=model, only=args.only)
    evaluator = summary.pop("_evaluator", None)

    print()
    print(render_markdown(summary))
    print()
    print("Alert-level:")
    print(json.dumps(summary["alert_summary"], indent=2))
    print()
    print("Layer-2 (ARP/MITM):")
    print(json.dumps(summary["mitm_event_level"], indent=2))

    if args.charts and evaluator is not None:
        paths = render_evaluation_charts(summary, evaluator.flows)
        print()
        for name, path in paths.items():
            print(f"  chart: {path}")

    print(f"\n  Full results: {RESULTS_DIR / 'evaluation.json'}")
    return 0


def cmd_demo(args: argparse.Namespace) -> int:
    """Walk the five mandated demonstration scenarios in order."""
    config = _config_from_args(args)
    model = ensure_model(config)

    scenarios = args.scenarios or [
        "scenario_1_benign",
        "scenario_2_port_scan",
        "scenario_3_dos",
        "scenario_4_brute_force",
        "scenario_5_ambiguous",
        "scenario_6_mitm_arp",
    ]

    banners = {
        "scenario_1_benign": "SCENARIO 1 - Normal traffic baseline",
        "scenario_2_port_scan": "SCENARIO 2 - Reconnaissance / port scan",
        "scenario_3_dos": "SCENARIO 3 - Denial of service",
        "scenario_4_brute_force": "SCENARIO 4 - Additional attack: credential brute force",
        "scenario_5_ambiguous": "SCENARIO 5 - Ambiguous / missed cases",
        "scenario_6_mitm_arp": "BONUS - ARP cache poisoning / man-in-the-middle",
    }

    for name in scenarios:
        pcap = DATA_DIR / "pcaps" / f"{name}.pcap"
        if not pcap.exists():
            print(f"  missing capture: {pcap}")
            continue

        print()
        print("#" * 78)
        print(f"#  {banners.get(name, name)}")
        print("#" * 78)

        result = analyse_pcap(pcap, config=config, model=model)
        _print_overview(result, config)
        print(format_alerts_table(result.alerts))
        print()
        export_result(result, RESULTS_DIR)

        if args.explain_first and result.alerts:
            print(format_alert_detail(result.alerts[0]))

        if not args.pause:
            continue
        try:
            input("  -- press Enter for the next scenario --")
        except (EOFError, KeyboardInterrupt):
            break

    return 0


def cmd_rules(_: argparse.Namespace) -> int:
    from .rules import RULE_CATALOGUE

    print()
    print(f"{'ID':<8} {'NAME':<26} {'CATEGORY':<13} LOGIC")
    print("-" * 110)
    for rule in RULE_CATALOGUE:
        print(f"{rule['id']:<8} {rule['name']:<26} {rule['category']:<13} {rule['logic']}")
    print()
    return 0


def cmd_info(_: argparse.Namespace) -> int:
    from .train import model_info

    print(json.dumps(model_info(), indent=2))
    return 0


# --------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nids",
        description="AI-driven network traffic analysis and intrusion detection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--version", action="version", version="nids 1.0.0")
    sub = parser.add_subparsers(dest="command", required=True)

    def add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--min-severity", help="lowest severity to report (INFO|LOW|MEDIUM|HIGH|CRITICAL)")
        p.add_argument("--window", type=float, help="aggregation window in seconds (default 10)")
        p.add_argument("--scan-ports", type=int, help="distinct-port threshold for R-001")
        p.add_argument("--no-ml", action="store_true", help="signature layer only")

    # generate
    p_gen = sub.add_parser("generate", help="generate the labelled pcap dataset")
    p_gen.add_argument("--seed", type=int, default=7)
    p_gen.add_argument("--only", action="append", help="generate a single scenario (repeatable)")
    p_gen.set_defaults(func=cmd_generate)

    # train
    p_train = sub.add_parser("train", help="train the ML models")
    add_common(p_train)
    p_train.add_argument("--no-cache", action="store_true", help="re-extract features")
    p_train.set_defaults(func=cmd_train)

    # analyze
    p_an = sub.add_parser("analyze", help="analyse one capture")
    p_an.add_argument("-p", "--pcap", required=True, help="path to a .pcap file")
    add_common(p_an)
    p_an.add_argument("--explain", help="print the full explanation for one alert id")
    p_an.add_argument("--detailed", action="store_true", help="explain every alert")
    p_an.add_argument("--max-rows", type=int, default=25)
    p_an.add_argument("--out", default=str(RESULTS_DIR))
    p_an.add_argument("--no-export", action="store_true")
    p_an.add_argument("--no-train", action="store_true", help="never train automatically")
    p_an.set_defaults(func=cmd_analyze)

    # evaluate
    p_ev = sub.add_parser("evaluate", help="score the detector against ground truth")
    add_common(p_ev)
    p_ev.add_argument("--only", action="append", help="restrict to these scenarios")
    p_ev.add_argument("--charts", action="store_true", help="write PNG charts")
    p_ev.set_defaults(func=cmd_evaluate)

    # demo
    p_demo = sub.add_parser("demo", help="run the mandated demonstration scenarios")
    add_common(p_demo)
    p_demo.add_argument("--scenario", dest="scenarios", action="append",
                        help="run only these scenarios (repeatable)")
    p_demo.add_argument("--pause", action="store_true", help="wait for Enter between scenarios")
    p_demo.add_argument("--explain-first", action="store_true",
                        help="print the full explanation of the first alert")
    p_demo.set_defaults(func=cmd_demo)

    # rules / info
    p_rules = sub.add_parser("rules", help="print the signature rule catalogue")
    p_rules.set_defaults(func=cmd_rules)

    p_info = sub.add_parser("info", help="show trained-model metadata")
    p_info.set_defaults(func=cmd_info)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
