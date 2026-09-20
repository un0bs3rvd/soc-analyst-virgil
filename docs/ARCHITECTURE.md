# Architecture

Virgil separates **deciding** from **investigating** from **acting**. Each stage has a
narrow contract, and the stages are glued together by deterministic, auditable policy —
not by model vibes.

```
                         ┌─────────────────────────────────────────────┐
                         │                 one alert                   │
                         └─────────────────────────────────────────────┘
                                           │
                    raw alert only         ▼
             ┌────────────────────────────────────────┐
             │ PASS 1 — Jev scores 8 questions        │   one POST, returns
             │ {question_id: P(true)}                 │   8 probabilities
             └────────────────────────────────────────┘
                                           │
                                           ▼
             ┌────────────────────────────────────────┐
             │ CONFIDENCE GATE (plain thresholds)     │
             │  tp ≤ 0.10              → AUTO_CLOSE   │
             │  tp ≥ 0.95 & inv < 0.35 → AUTO_ACT     │
             │  else                   → INVESTIGATE  │
             └────────────────────────────────────────┘
                          │                 │
            confident     │                 │  not confident
                          ▼                 ▼
              ┌───────────────┐   ┌──────────────────────────────┐
              │ ACTION POLICY │   │ INVESTIGATOR (LLM)           │
              │               │   │  plan → retrieve → summarize │
              └───────────────┘   │  (sees raw alert only; may   │
                          ▲       │   append telemetry sections) │
                          │       └──────────────────────────────┘
                          │                     │ enriched state
                          │                     ▼
                          │       ┌──────────────────────────────┐
                          │       │ PASS 2 — Jev re-scores the   │
                          │       │ raw alert + retrieved        │
                          │       │ evidence                     │
                          │       └──────────────────────────────┘
                          │                     │
                          └─────────────────────┘
                                           │
                                           ▼
                              ┌────────────────────────┐
                              │ ASSESSMENT — the LLM   │
                              │ writes the plain-      │
                              │ English ticket summary │
                              └────────────────────────┘
```

## Component contracts

### Jev — the decision engine (notebook cell 6)

One `POST /v1/systemone` call carries the alert `state` and all eight `questions`
(`type: "noul"`, each with instructions and true/false criteria) and returns
`{question_id: P(true)}`. Probabilities, not labels — the gate and the action policy do
the labeling, in plain Python you can read and diff.

Mock mode (`MOCK_JEV`, or no `TYPESAFE_API_KEY`) swaps in deterministic heuristics so the
pipeline — and `eval/evaluate.py` — runs with zero keys. Mock scores exist to test the
plumbing; they are not calibrated model output.

### The two-pass information contract (cells 5, 13)

- `strip_for_pass1(state)` drops the sections listed in `HIDDEN_UNTIL_INVESTIGATION`
  (`enrichment`, `correlated_activity`) before scoring. Pass 1 is deliberately "blind" —
  it measures what the system can tell from the raw alert alone, which is what makes the
  pass-1 → pass-2 delta meaningful.
- In the demo, those withheld sections *play the role of backend telemetry* (EDR, SIEM,
  IdP, CMDB). Only the investigator may retrieve them, and pass 2 is the only pass that
  ever sees them.
- Pass-2 state = raw alert + retrieved evidence, nothing else (`deepcopy(raw)` then
  `deep_merge`). The original state is never mutated.

### The confidence gate (cell 7)

Pure function of pass-1 scores:

| Condition | Route |
|---|---|
| `true_positive ≤ FP_CLOSE_THRESHOLD` (0.10) | `AUTO_CLOSE` — benign / detection FP |
| `true_positive ≥ TP_ACT_THRESHOLD` (0.95) and `requires_investigation_before_action < INVESTIGATE_THRESHOLD` (0.35) | `AUTO_ACT` |
| anything else | `INVESTIGATE` |

After an investigation, pass-2 scores go through the same gate; an `AUTO_CLOSE` there is
recorded as `AUTO_CLOSE_AFTER_INVESTIGATION` so the trace shows the evidence changed the
verdict.

### Telemetry tools (cell 8)

Six functions — `get_process_tree`, `get_network_connections`, `get_threat_intel`,
`get_auth_log`, `get_related_alerts`, `get_asset_context` — each one a seam where a real
connector goes. In the demo they read the withheld sections of the current state; in a
dev deployment they would call your EDR / SIEM / threat intel / IdP / CMDB. The rest of
the pipeline only sees their return shape, so swapping backends is contained.

### The investigator (cells 9–11)

Provider-agnostic LLM (`gemini` | `openai_compatible` | `claude`), driven by three
prompts:

1. **PLAN** — given the raw alert and pass-1 scores, choose which tools to call and state
   a one-line hypothesis. (Fallback: call everything.)
2. **SUMMARIZE** — compress tool results into structured `enrichment` /
   `correlated_activity` fields to append to the state.
3. **EXPLAIN** — after the final decision, write the 3–5 sentence ticket assessment,
   citing the actual pass-1/pass-2 numbers.

Guardrails:

- The investigator sees the **raw alert only** — same view as pass 1. It cannot peek at
  the withheld sections except through the tools.
- `sanitize_extra` whitelists what may be merged back: only `enrichment` and
  `correlated_activity` dicts. The LLM cannot rewrite alert fields, scores, or
  thresholds.
- All LLM calls retry transient 429/503 failures with backoff; on hard failure the
  pipeline falls back to the deterministic `heuristic_investigate` / `heuristic_explain`
  rather than dying.

### The response policy (cell 12)

Three safeguards on top of per-action thresholds:

1. **Consensus** — an action auto-fires only if `true_positive ≥ 0.95` *and*
   `requires_investigation_before_action < 0.35`, on top of clearing its own bar.
2. **Impact-tiered bars** — monitoring 0.60 and evidence preservation 0.70 (reversible);
   indicator blocking 0.85; isolation and account disable 0.95.
3. **Human sign-off** — high-impact actions on critical assets (`HUMAN_APPROVAL_ON_CRITICAL`,
   `CRITICAL_HOST_LEVELS`) always queue for a human regardless of confidence.

Handler bodies (`do_isolate_endpoint`, …) are stubs returning description strings —
that's intentional; wire them to your firewall / EDR / IdP / case management.

### Dispositions (cell 13)

Every alert ends in exactly one:

| Disposition | Meaning | Eval label mapping |
|---|---|---|
| `closed_benign` | Gate closed it (pass 1 or after investigation) | `benign` |
| `auto_responded` | At least one action auto-executed | `malicious` |
| `human_required` | Actions queued and/or confidence still under the bar | `ambiguous` |

### The trace

`process_alert` returns a JSON-serializable trace per alert: pass-1/pass-2 scores with
timings, the gate route, the investigator's hypothesis and tool calls, executed/queued
actions, the disposition, and the written assessment. That object is the audit record —
persist it anywhere you keep case history.

## Design principles, restated

1. **Models propose probabilities; code makes decisions.** Anything reversible is a
   threshold away from anything irreversible.
2. **The LLM touches evidence and prose, never verdicts.** Its outputs pass through a
   whitelist before influencing scores.
3. **Everything is a pure function until the very edge.** Only the two API clients and
   the (stubbed) action handlers have side effects — which is what makes the whole thing
   replayable under evaluation.
