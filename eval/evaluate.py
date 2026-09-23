# SPDX-License-Identifier: AGPL-3.0-or-later

#!/usr/bin/env python3
"""Evaluate the Virgil triage pipeline against the labeled demo alert states.

The Jupyter notebook (SOC-Analyst-Virgil.ipynb) is the single source of truth
for the pipeline. This harness executes the notebook's code cells (skipping the
interactive demo cells), then runs `process_alert` over every labeled demo
state and scores the resulting dispositions against the ground-truth labels.

Runs with zero API keys (deterministic mock Jev + heuristic investigator) or
with real keys (TYPESAFE_API_KEY + an investigator provider key) for a live
evaluation. Mock-mode scores are plumbing tests, not calibrated model output -
see docs/EVALUATION.md for how to read the numbers.

Usage:
    python eval/evaluate.py                  # all 100 labeled states
    python eval/evaluate.py --set 001-040    # first batch only
    python eval/evaluate.py --set 041-100    # second batch only
    python eval/evaluate.py --limit 10       # smoke test
    python eval/evaluate.py --out eval/results
"""

import argparse
import contextlib
import io
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
NOTEBOOK = REPO_ROOT / "SOC-Analyst-Virgil.ipynb"

# Notebook cells containing any of these markers run the interactive demo
# rather than defining pipeline components, so the harness skips them.
SKIP_MARKERS = ("DEMO_NOTES", "ipywidgets", "RUN A SINGLE ALERT")

LABELS = ["benign", "malicious", "ambiguous"]

# Pipeline disposition -> predicted triage label.
DISPOSITION_TO_LABEL = {
    "closed_benign": "benign",        # gate closed it (pass 1 or after investigation)
    "auto_responded": "malicious",    # machine confident enough to act on its own
    "human_required": "ambiguous",    # escalated to a human analyst
}

# Actions that actually contain a threat (vs. observe / preserve).
CONTAINMENT_ACTIONS = ("block_indicator", "isolate_endpoint", "disable_account")


# ----------------------------------------------------------------------------
# Notebook loading
# ----------------------------------------------------------------------------

def load_pipeline_namespace(notebook_path=NOTEBOOK):
    """Execute the notebook's code cells and return the resulting namespace.

    The notebook locates questions.json / demo-states.json via the current
    working directory, so we execute with cwd pinned to the repo root.
    """
    nb = json.loads(Path(notebook_path).read_text(encoding="utf-8"))
    ns = {"__name__": "__virgil_notebook__"}
    prev_cwd = os.getcwd()
    os.chdir(REPO_ROOT)
    try:
        for i, cell in enumerate(nb["cells"]):
            if cell["cell_type"] != "code":
                continue
            src = "".join(cell["source"])
            if any(m in src for m in SKIP_MARKERS):
                continue
            code = compile(src, f"{Path(notebook_path).name}#cell-{i}", "exec")
            exec(code, ns)
    finally:
        os.chdir(prev_cwd)
    return ns


# ----------------------------------------------------------------------------
# States + ground truth
# ----------------------------------------------------------------------------

def _norm_id(case_id):
    """Normalize a case id to its zero-padded numeric suffix.

    The 001-040 ground truth was keyed 'JEV-001'.. while the states are
    'VIRGIL-001'... Matching on the numeric suffix absorbs that legacy quirk.
    """
    digits = re.search(r"(\d+)\s*$", str(case_id))
    if not digits:
        raise ValueError(f"cannot parse case id: {case_id!r}")
    return digits.group(1).zfill(3)


def load_labeled_cases(which="all"):
    """Return [{case_id, label, category, state}] for the requested batch(es)."""
    sources = []
    if which in ("all", "001-040"):
        sources.append((
            REPO_ROOT / "demo-states.json",
            REPO_ROOT / "data/ground_truth/demo_states_001_040_ground_truth.json"))
    if which in ("all", "041-100"):
        sources.append((
            REPO_ROOT / "data/demo_states_041_100.json",
            REPO_ROOT / "data/ground_truth/demo_states_041_100_ground_truth.json"))

    cases, unmatched = [], []
    for states_path, gt_path in sources:
        states = json.loads(states_path.read_text(encoding="utf-8"))
        gt_raw = json.loads(gt_path.read_text(encoding="utf-8"))
        gt = {}
        for key, val in gt_raw.items():
            # gt values are either a bare label string or {"category", "label"}
            gt[_norm_id(key)] = val if isinstance(val, dict) else {"category": None, "label": val}
        for state in states:
            entry = gt.get(_norm_id(state["case_id"]))
            if entry is None:
                unmatched.append(state["case_id"])
                continue
            cases.append({"case_id": state["case_id"], "label": entry["label"],
                          "category": entry.get("category"), "state": state})
    return cases, unmatched


# ----------------------------------------------------------------------------
# Metrics
# ----------------------------------------------------------------------------

def confusion_matrix(rows):
    m = {a: Counter() for a in LABELS}
    for r in rows:
        m[r["actual"]][r["predicted"]] += 1
    return m


def per_class_metrics(cm):
    out = {}
    for label in LABELS:
        tp = cm[label][label]
        pred_total = sum(cm[a][label] for a in LABELS)
        actual_total = sum(cm[label].values())
        p = tp / pred_total if pred_total else 0.0
        r = tp / actual_total if actual_total else 0.0
        f1 = 2 * p * r / (p + r) if (p + r) else 0.0
        out[label] = {"precision": p, "recall": r, "f1": f1, "support": actual_total}
    return out


def percentile(vals, pct):
    if not vals:
        return 0.0
    vals = sorted(vals)
    k = min(len(vals) - 1, max(0, round((pct / 100) * (len(vals) - 1))))
    return vals[k]


# ----------------------------------------------------------------------------
# Evaluation loop
# ----------------------------------------------------------------------------

def evaluate(cases, ns, show_traces=False):
    process_alert = ns["process_alert"]
    rows = []
    for i, case in enumerate(cases, 1):
        buf = io.StringIO()
        t0 = time.time()
        try:
            with contextlib.redirect_stdout(buf):
                trace = process_alert(dict(case["state"]), verbose=False)
            predicted = DISPOSITION_TO_LABEL.get(trace["disposition"], "ambiguous")
            row = {
                "case_id": case["case_id"],
                "category": case["category"],
                "actual": case["label"],
                "predicted": predicted,
                "correct": predicted == case["label"],
                "route": trace["route"],
                "disposition": trace["disposition"],
                "p1_true_positive": round(trace["pass1"]["true_positive"], 4),
                "p2_true_positive": (round(trace["pass2"]["true_positive"], 4)
                                     if "pass2" in trace else None),
                "executed": [q for q, _ in trace.get("executed", [])],
                "queued": [q for q, _ in trace.get("queued", [])],
                "containment": any(q in CONTAINMENT_ACTIONS
                                   for q, _ in trace.get("executed", []) + trace.get("queued", [])),
                "pass1_ms": trace.get("pass1_ms"),
                "pass2_ms": trace.get("pass2_ms"),
                "wall_ms": round((time.time() - t0) * 1000),
            }
        except Exception as e:  # a pipeline crash is scored as an error, not skipped
            row = {"case_id": case["case_id"], "category": case["category"],
                   "actual": case["label"], "predicted": "error", "correct": False,
                   "error": f"{type(e).__name__}: {e}"}
        rows.append(row)
        status = "ok" if row["correct"] else ("ERR" if row["predicted"] == "error"
                                              else f"miss ({row['actual']} -> {row['predicted']})")
        print(f"  [{i:>3}/{len(cases)}] {case['case_id']:<12} {status}")
        if show_traces and buf.getvalue().strip():
            print("    " + "\n    ".join(buf.getvalue().splitlines()[-12:]))
    return rows


def summarize(rows, elapsed_s):
    scored = [r for r in rows if r["predicted"] != "error"]
    errors = [r for r in rows if r["predicted"] == "error"]
    cm = confusion_matrix(scored)
    per_class = per_class_metrics(cm)
    n = len(scored)
    correct = sum(1 for r in scored if r["correct"])

    dangerous = [r["case_id"] for r in scored
                 if r["actual"] == "malicious" and r["predicted"] == "benign"]
    overreactions = [r["case_id"] for r in scored
                     if r["actual"] == "benign" and r["predicted"] == "malicious"]
    mal = [r for r in scored if r["actual"] == "malicious"]
    containment = sum(1 for r in mal if r.get("containment"))
    amb = [r for r in scored if r["actual"] == "ambiguous"]
    amb_escalated = sum(1 for r in amb if r["predicted"] == "ambiguous")

    p1_ms = [r["pass1_ms"] for r in scored if r.get("pass1_ms") is not None]
    p2_ms = [r["pass2_ms"] for r in scored if r.get("pass2_ms") is not None]

    by_category = {}
    for r in scored:
        if not r["category"]:
            continue
        c = by_category.setdefault(r["category"], Counter())
        c["n"] += 1
        c["correct"] += int(r["correct"])

    return {
        "total": len(rows), "scored": n, "errors": len(errors),
        "accuracy": correct / n if n else 0.0,
        "confusion_matrix": {a: dict(cm[a]) for a in LABELS},
        "per_class": per_class,
        "dangerous_misses": dangerous,
        "overreactions": overreactions,
        "malicious_containment_rate": containment / len(mal) if mal else None,
        "ambiguous_escalated": f"{amb_escalated}/{len(amb)}",
        "routing": dict(Counter(r["route"] for r in scored)),
        "dispositions": dict(Counter(r["disposition"] for r in scored)),
        "latency_ms": {"pass1_mean": round(sum(p1_ms) / len(p1_ms), 1) if p1_ms else None,
                       "pass2_mean": round(sum(p2_ms) / len(p2_ms), 1) if p2_ms else None,
                       "wall_p95": percentile([r.get("wall_ms", 0) for r in scored], 95)},
        "by_category": {k: dict(v) for k, v in sorted(by_category.items())},
        "elapsed_s": round(elapsed_s, 1),
        "error_cases": [{"case_id": r["case_id"], "error": r["error"]} for r in errors],
    }


def print_report(summary):
    s = summary
    print("\n" + "=" * 68)
    print(f"RESULTS — {s['scored']} scored, {s['errors']} errors "
          f"({s['elapsed_s']}s wall)")
    print("=" * 68)
    print(f"Overall accuracy:            {s['accuracy']:.1%}")
    print(f"Malicious containment rate:  "
          + (f"{s['malicious_containment_rate']:.1%}"
              if s['malicious_containment_rate'] is not None else "n/a"))
    print(f"Ambiguous sent to a human:   {s['ambiguous_escalated']}")
    print(f"Routing:    {s['routing']}")
    print(f"Latency ms: {s['latency_ms']}")

    print("\nConfusion matrix (actual -> predicted):")
    head = "".join(f"{l:>12}" for l in LABELS)
    print(f"{'':>12}{head}")
    for a in LABELS:
        cells = "".join(f"{s['confusion_matrix'][a].get(p, 0):>12}" for p in LABELS)
        print(f"{a:>12}{cells}")

    print("\nPer-class metrics:")
    print(f"{'':>12}{'precision':>10}{'recall':>10}{'f1':>10}{'support':>10}")
    for label, m in s["per_class"].items():
        print(f"{label:>12}{m['precision']:>10.2f}{m['recall']:>10.2f}"
              f"{m['f1']:>10.2f}{m['support']:>10}")

    print("\nSafety split:")
    print(f"  dangerous misses (malicious auto-closed): {len(s['dangerous_misses'])}"
          + (f"  <- {', '.join(s['dangerous_misses'][:8])}" if s["dangerous_misses"] else ""))
    print(f"  overreactions (benign auto-responded):  {len(s['overreactions'])}"
          + (f"  <- {', '.join(s['overreactions'][:8])}" if s["overreactions"] else ""))

    if s["by_category"]:
        print("\nBy attack category (041-100 set):")
        for cat, c in s["by_category"].items():
            print(f"  {cat:<42} {c['correct']}/{c['n']}")
    if s["error_cases"]:
        print("\nErrors:")
        for e in s["error_cases"]:
            print(f"  {e['case_id']}: {e['error']}")


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--set", dest="which", choices=["all", "001-040", "041-100"],
                    default="all", help="which labeled batch to evaluate (default: all)")
    ap.add_argument("--limit", type=int, default=None, help="evaluate only the first N cases")
    ap.add_argument("--out", type=Path, default=None,
                    help="directory for JSON + CSV results (default: no files written)")
    ap.add_argument("--show-traces", action="store_true",
                    help="print captured pipeline output for each alert")
    args = ap.parse_args()

    engine = ("Jev (live)" if os.environ.get("TYPESAFE_API_KEY") else "MOCK Jev")
    investigator = ("LLM (live)" if any(os.environ.get(k) for k in
                    ("GEMINI_API_KEY", "GOOGLE_API_KEY", "OPENAI_API_KEY",
                     "MINIMAX_API_KEY", "ANTHROPIC_API_KEY")) else "heuristic fallback")
    print(f"Loading pipeline from {NOTEBOOK.name} ...")
    print(f"Engine: {engine}   Investigator: {investigator}")

    ns = load_pipeline_namespace()

    cases, unmatched = load_labeled_cases(args.which)
    for cid in unmatched:
        print(f"  warning: no ground-truth label for {cid} (skipped)")
    if args.limit:
        cases = cases[:args.limit]
    print(f"Evaluating {len(cases)} labeled alerts "
          f"({Counter(c['label'] for c in cases)})\n")

    t0 = time.time()
    rows = evaluate(cases, ns, show_traces=args.show_traces)
    summary = summarize(rows, time.time() - t0)
    summary["engine"] = engine
    summary["investigator"] = investigator
    print_report(summary)

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y%m%d_%H%M%S")
        (args.out / f"eval_{stamp}.json").write_text(
            json.dumps({"summary": summary, "cases": rows}, indent=1), encoding="utf-8")
        import csv
        with open(args.out / f"eval_{stamp}.csv", "w", newline="", encoding="utf-8") as f:
            cols = ["case_id", "category", "actual", "predicted", "correct", "route",
                    "disposition", "p1_true_positive", "p2_true_positive",
                    "executed", "queued", "containment", "pass1_ms", "pass2_ms", "wall_ms"]
            w = csv.DictWriter(f, fieldnames=cols, extrasaction="ignore")
            w.writeheader()
            w.writerows(rows)
        print(f"\nWrote {args.out}/eval_{stamp}.json and .csv")

    # Non-zero exit if any case errored or accuracy is suspiciously low for
    # the deterministic mock pipeline (handy as a CI smoke gate).
    return 1 if summary["errors"] else 0


if __name__ == "__main__":
    sys.exit(main())
