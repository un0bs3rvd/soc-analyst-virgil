# Demo data

Synthetic alerts for demo and evaluation. Nothing here is real telemetry.

## Files

| File | Contents |
|---|---|
| `questions.json` | The 8 triage questions Jev scores every alert against |
| `demo-states.json` | Alerts `VIRGIL-001`–`040` — endpoint & identity detections |
| `demo_states_041_100.json` | Alerts `VIRGIL-041`–`100` — 20 attack categories: brute force, impossible travel, MFA fatigue, LotL binaries, persistence, exfiltration, C2, recon, API abuse, cloud misconfig, shadow IT, phishing, malicious attachments, mass file access, policy violations, and three cross-category multi-stage incidents |
| `ground_truth/` | One file per batch: `VIRGIL-xxx → label` (`benign` / `malicious` / `ambiguous`), plus an attack `category` per alert in the 041–100 file |

The notebook loads `questions.json` and `demo-states.json` from this folder via its
`DATA_DIR` config (default `"data"`).

Label counts across both batches: **38 benign · 43 malicious · 20 ambiguous**.
`ambiguous` means "this one should reach a human" — the correct pipeline outcome is
escalation, not a verdict.

> Historical quirk: the 001–040 ground truth is keyed `JEV-001`–`JEV-040` while the
> states are `VIRGIL-001`–`VIRGIL-040`. `eval/evaluate.py` matches on the numeric
> suffix; prefer the `VIRGIL-` prefix if you regenerate it.

## Alert state schema

```jsonc
{
  "case_id": "VIRGIL-001",
  "alert":   {"rule": "...", "severity": "low|medium|high|critical", "risk_score": 0},
  "host":    {"name": "...", "role": "...", "criticality": "low|medium|high|critical"},
  "user":    {"name": "...", "role": "...", "is_admin": false},
  "trigger": {"...": "what the detection fired on (varies by rule)"},

  // Withheld from pass 1 and from the investigator's direct view — the mock
  // "backend telemetry" the investigator retrieves through its tools:
  "enrichment":          {"...": "point-in-time context (approvals, history, ...)"},
  "correlated_activity": {"...": "other activity tied to this alert (optional)"}
}
```

`host` / `user` are optional — cloud, SaaS, and email alerts in the 041–100 batch may
carry a `cloud` section instead of a host. New sections are fine; anything outside
`enrichment` / `correlated_activity` is visible to pass 1.

## Adding your own alerts

1. Append states to one of the JSON files (or drop in an export from your SIEM mapped to
   the schema above).
2. Add a label per state to the matching ground-truth file.
3. `python eval/evaluate.py` — that's it.

If a state has no ground-truth label the harness warns and skips it.
