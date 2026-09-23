# SOC Analyst — Virgil

**Autonomous alert triage, with the LLM on a leash.** Virgil is a proof-of-concept SOC
triage pipeline that pairs [Jev](https://typesafe.ai) (TypeSafe's hosted decision engine)
with an LLM investigator in a two-pass, confidence-gated loop. It reads a security alert,
decides whether it's real, pulls evidence when it isn't sure, and takes — or deliberately
withholds — response actions based on auditable probability thresholds.

![status](https://img.shields.io/badge/status-POC%2Fdemo-orange)
![python](https://img.shields.io/badge/python-3.10%2B-blue)
![license](https://img.shields.io/badge/license-AGPL--3.0-blue)

```
ALERT
  │
  ▼
PASS 1 · Jev scores the raw alert (8 questions, one API call)
  │
  ▼
CONFIDENCE GATE ── not confident ──► INVESTIGATOR · LLM retrieves correlated telemetry
  │                                            │
  │◄──────────── enriched state ◄──────────────┘
  ▼
PASS 2 · Jev re-scores with evidence
  │
  ▼
RESPONSE · automated actions, or human review when under threshold
```

## Why it's built this way

- **The LLM never decides the verdict.** Jev produces calibrated probabilities for eight
  triage questions; deterministic threshold gates turn those into routing and response
  decisions. The LLM's only jobs are *choosing which telemetry to pull* and *writing the
  plain-English assessment* — tasks it's good at that don't require trusting it with the
  trigger.
- **Evidence is earned, not assumed.** Pass 1 sees only the raw alert. Backend telemetry
  (`enrichment`, `correlated_activity`) is withheld until the investigator explicitly
  retrieves it, and a whitelist guardrail (`sanitize_extra`) ensures the LLM can only
  append to those telemetry sections — it can't rewrite the alert itself.
- **Every decision is auditable.** Each alert prints its pass-1 scores, *why* the gate
  routed it, what the investigator retrieved, pass-2 scores with deltas, which actions
  fired or were held (with reasons), and a written assessment. The gates are plain
  `if` statements over thresholds in one config cell.
- **Impact-tiered automation.** Reversible actions (monitoring, evidence preservation)
  auto-fire at modest confidence; `isolate_endpoint` and `disable_account` require
  P ≥ 0.95 — and on critical assets they *always* queue for human sign-off.
- **Provider-agnostic investigator.** Gemini, any OpenAI-compatible endpoint (OpenAI,
  Minimax, …), or Claude — one flag in the config cell.
- **Runs with zero API keys.** Jev falls back to clearly-labeled mock scores and the
  investigator to a deterministic heuristic, so the full pipeline — and the evaluation
  harness — runs offline. Mock scores are plumbing tests, not calibrated output.

## Quickstart

```bash
git clone <this-repo> && cd soc-analyst-virgil
pip install -r requirements.txt

# Optional: the demo runs end-to-end without keys, in clearly-labeled mock mode.
cp .env.example .env    # then fill in what you have, or export the vars
```

Then launch Jupyter from the repo root (the notebook loads `questions.json` and
`demo-states.json` from its own directory):

```bash
jupyter notebook SOC-Analyst-Virgil.ipynb
```

Run the cells top to bottom. Cell 3 is a go/no-go connectivity check for whichever
services you configured; the **Run the demo** section walks three representative alerts
through all three routes, and the last cell gives you a dropdown to run any of the
100 demo alerts.

| Key | Service | Get one |
|---|---|---|
| `TYPESAFE_API_KEY` | Jev decision engine | [typesafe.ai](https://typesafe.ai) (early access) |
| `GEMINI_API_KEY` | Investigator — Gemini | [aistudio.google.com/apikey](https://aistudio.google.com/apikey) |
| `OPENAI_API_KEY` | Investigator — OpenAI-compatible | your endpoint (OpenAI, Minimax, ZAI, …) |
| `ANTHROPIC_API_KEY` | Investigator — Claude | [console.anthropic.com](https://console.anthropic.com) |

Pick the investigator with `INVESTIGATOR_PROVIDER` in the notebook's config cell.

## The eight triage questions

Every alert is scored against the same eight questions (`questions.json`); one Jev call
returns a probability for each:

| Question | Used for |
|---|---|
| `true_positive` | Gate + consensus for every action |
| `requires_immediate_response` | Context for urgency |
| `requires_investigation_before_action` | Gate: is it safe to act on what we know? |
| `increase_monitoring` | Action (low impact, threshold 0.60) |
| `preserve_evidence` | Action (low impact, threshold 0.70) |
| `block_indicator` | Action (medium impact, threshold 0.85) |
| `isolate_endpoint` | Action (high impact, threshold 0.95) |
| `disable_account` | Action (high impact, threshold 0.95) |

The gate: P(true_positive) ≤ 0.10 → **auto-close**; ≥ 0.95 with low investigation need →
**auto-act**; anything in between → **investigate**, then re-score with the retrieved
evidence. Full semantics in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), every knob in
[docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Evaluation

The repo ships with **100 labeled demo alerts** (38 benign / 43 malicious / 20 ambiguous —
the 041–100 batch spans 20 attack categories from LotL binaries to cloud misconfigurations)
and a harness that scores the pipeline against the ground truth. The notebook is the
single source of truth — the harness executes its cells, then runs `process_alert` over
every labeled state:

```bash
python eval/evaluate.py                 # all 100 labeled states
python eval/evaluate.py --set 041-100   # one batch
python eval/evaluate.py --limit 10      # smoke test
python eval/evaluate.py --out eval/results   # + JSON/CSV per-case results
```

Mock-mode baseline (no API keys, deterministic heuristics): **69% accuracy, 100%
malicious recall, zero dangerous misses** (no real incident auto-closed), benign alerts
mostly escalate to a human rather than closing. That trade is intentional — the mock
stands in for plumbing, not for Jev — read
[docs/EVALUATION.md](docs/EVALUATION.md) before quoting the numbers.

## Repository layout

```
├── SOC-Analyst-Virgil.ipynb     # the pipeline — single source of truth
├── questions.json               # the 8 triage questions
├── demo-states.json             # demo alerts 001–040
├── data/
│   ├── demo_states_041_100.json # demo alerts 041–100 (20 attack categories)
│   └── ground_truth/            # labels for all 100 states
├── eval/
│   └── evaluate.py              # evaluation harness (see docs/EVALUATION.md)
└── docs/
    ├── ARCHITECTURE.md          # two-pass design, gate, policy, guardrails
    ├── CONFIGURATION.md         # every knob, with guidance
    ├── EVALUATION.md            # methodology + baseline results
    └── ROADMAP.md               # POC → dev → production checklist
```

## Limitations (it's a POC)

- **Telemetry connectors are mocks.** The six tools in cell 8 read the demo states
  themselves; they are the seams where you'd wire real EDR/SIEM/TI/IdP/CMDB calls.
- **Action handlers are stubs** that return description strings — nothing is isolated,
  blocked, or disabled.
- **Mock-mode scores are not calibrated.** They're deterministic heuristics that keep the
  plumbing testable offline.
- **Thresholds are starting points**, not tuned values — calibrate them against your own
  historical alert outcomes before trusting them in a dev environment.

## License

Free software under [AGPLv3](LICENSE) — copyleft, including the network-use clause:
if you run a modified version as a service (e.g. wired to your SIEM), you must offer
that version's source to its users. The synthetic dataset and ground-truth labels in
[`data/`](data/) (including `demo-states.json`) are separately licensed under
[CC BY 4.0](data/LICENSE).

"VIRGIL" and associated project branding are trademarks of un0bs3rvd; the licenses
above grant no rights to the name.

This is a research/demo project: don't point it at production infrastructure, and
keep a human in the loop for high-impact actions.
