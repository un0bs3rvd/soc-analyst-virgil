# Evaluation

`eval/evaluate.py` scores the triage pipeline against the 100 labeled demo alerts.

**The notebook is the single source of truth.** The harness executes the notebook's code
cells (skipping only the interactive demo cells), then calls the notebook's own
`process_alert` on every labeled state. If the pipeline changes in the notebook, the
evaluation measures the change — there is no second implementation to drift.

## Running

```bash
python eval/evaluate.py                  # all 100 labeled states
python eval/evaluate.py --set 001-040    # first batch only
python eval/evaluate.py --set 041-100    # second batch only
python eval/evaluate.py --limit 10       # smoke test
python eval/evaluate.py --show-traces    # include per-alert pipeline output
python eval/evaluate.py --out eval/results   # write per-case JSON + CSV
```

With no API keys the run is fully deterministic (mock Jev + heuristic investigator) and
takes seconds. With keys set, the same command evaluates the live stack — the harness
prints which engine/investigator it's using at the top. Exit code is non-zero if any
case crashes the pipeline, which makes it usable as a CI smoke gate.

## Scoring methodology

Ground truth labels: `benign`, `malicious`, `ambiguous`. The pipeline's disposition maps
onto them:

| Disposition | Predicted label |
|---|---|
| `closed_benign` | `benign` |
| `auto_responded` | `malicious` |
| `human_required` | `ambiguous` (i.e. escalated to a human) |

`ambiguous` ground truth means "a human should look at this", so escalation counts as
correct for those cases. Reported metrics:

- **Confusion matrix + per-class precision/recall/F1** and overall accuracy.
- **Safety split** — the two error classes a SOC actually cares about:
  - *dangerous misses*: malicious alerts the pipeline auto-closed (worst case),
  - *overreactions*: benign alerts the pipeline auto-responded to (wasted actions).
  Escalating a benign alert to a human is cautious, not dangerous, and is tracked
  separately rather than lumped in with real errors.
- **Malicious containment rate** — share of malicious cases where at least one
  containment action (`block_indicator`, `isolate_endpoint`, `disable_account`) was
  executed *or queued for approval*. A held isolation still counts as detection.
- **Per-category breakdown** for the 041–100 set (20 attack categories).
- **Routing distribution and latency** (pass-1/pass-2 wall time).

A pipeline exception is recorded as an `error` (never silently skipped) and fails the
run's exit code.

## Baseline — mock mode (no API keys)

Deterministic heuristics, commit-time pipeline, all 100 states
(38 benign / 43 malicious / 20 ambiguous):

| Metric | Value |
|---|---|
| Overall accuracy | 69.0% |
| Malicious recall | 100% (0 dangerous misses) |
| Malicious containment rate | 100% |
| Benign recall | 35% — most benign alerts escalate to a human instead of closing |
| Overreactions (benign → auto-responded) | 6 |
| Ambiguous correctly escalated | 13/20 |

**Read these as plumbing tests, not model quality.** The mock decision engine is a
keyword heuristic and the fallback investigator just surfaces the withheld telemetry;
the numbers say "the gates, merges, guardrails, and action policy behave sanely end to
end", nothing more. The mock is deliberately conservative on benign alerts — that's why
benign recall is low while dangerous misses are zero, which is the right failure
direction for a triage system. Re-run with real keys (`TYPESAFE_API_KEY` + an
investigator key) for numbers that mean something, and treat threshold tuning as its own
exercise against your own alert history.

## Data notes

- `demo-states.json` (repo root): alerts `VIRGIL-001`–`040` — endpoint/identity detections.
- `data/demo_states_041_100.json`: alerts `VIRGIL-041`–`100` — 20 attack categories
  including cloud/SaaS, phishing, and data exfiltration. Some of these states
  intentionally have no `host` section (e.g. a GitHub API-abuse alert) — the pipeline is
  tolerant of that.
- Ground truth lives in `data/ground_truth/`. Historical quirk: the 001–040 file keys its
  labels `JEV-001`–`JEV-040` while the states are `VIRGIL-001`–`VIRGIL-040`. The harness
  matches on the numeric suffix; if you regenerate that file, prefer the `VIRGIL-` prefix.
- The 041–100 ground truth also carries a `category` per alert, which powers the
  per-category breakdown.
