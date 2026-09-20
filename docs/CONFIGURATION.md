# Configuration reference

Every knob lives in the notebook's **config cell (cell 2)**. Nothing else in the
pipeline hardcodes a value you should need to tune.

## Credentials

| Variable | Env var fallback | Purpose |
|---|---|---|
| `TYPESAFE_API_KEY` | `TYPESAFE_API_KEY` | Jev decision engine ([typesafe.ai](https://typesafe.ai), early access) |
| `GEMINI_API_KEY` | `GEMINI_API_KEY` / `GOOGLE_API_KEY` | Gemini investigator |
| `COMPAT_API_KEY` | `OPENAI_API_KEY` / `MINIMAX_API_KEY` | Any OpenAI-compatible investigator endpoint |
| `CLAUDE_API_KEY` | `ANTHROPIC_API_KEY` | Claude investigator |

Leave a value as `None` to read it from the environment (recommended; see `.env.example`).
With no keys at all, the pipeline runs in clearly-labeled mock mode.

## Models

| Variable | Default | Notes |
|---|---|---|
| `JEV_MODEL` | `"jev-latest"` | Jev model id |
| `GEMINI_MODEL` | `"gemini-3.8-flash"` | Fast/cheap is right here — the investigator plans and summarizes, it doesn't decide |
| `COMPAT_MODEL` | `"gpt-5.6-luna"` | Any chat model id your endpoint serves |
| `CLAUDE_MODEL` | `"claude-haiku-4-5"` | Same reasoning |
| `INVESTIGATOR_PROVIDER` | `"gemini"` | `"gemini"` \| `"openai_compatible"` \| `"claude"` |
| `COMPAT_BASE_URL` | `https://api.openai.com/v1` | No trailing slash. Minimax: `https://api.minimax.io/v1`, ZAI: `https://api.z.ai/v1` |

## Confidence gate

| Variable | Default | Meaning |
|---|---|---|
| `TP_ACT_THRESHOLD` | `0.95` | Auto-response requires P(true_positive) ≥ this |
| `FP_CLOSE_THRESHOLD` | `0.10` | P(true_positive) ≤ this → auto-close as benign |
| `INVESTIGATE_THRESHOLD` | `0.35` | P(needs investigation) ≥ this blocks auto-action and routes to the investigator |

The wide gap between 0.10 and 0.95 is the point: the machine may only act at the
extremes, and everything in between is investigated. Tighten the band as you gain trust
— widen it only as the eval shows the machine is right (see [EVALUATION.md](EVALUATION.md)).

## Response policy

```python
ACTION_POLICY = {
    "increase_monitoring": {"threshold": 0.60, "impact": "low"},     # reversible
    "preserve_evidence":   {"threshold": 0.70, "impact": "low"},     # reversible
    "block_indicator":     {"threshold": 0.85, "impact": "medium"},
    "isolate_endpoint":    {"threshold": 0.95, "impact": "high"},
    "disable_account":     {"threshold": 0.95, "impact": "high"},
}
HUMAN_APPROVAL_ON_CRITICAL = True
CRITICAL_HOST_LEVELS = {"critical"}
```

Each action fires only when its own question's probability clears its bar **and** the
global consensus holds (`true_positive ≥ TP_ACT_THRESHOLD` and
`requires_investigation_before_action < INVESTIGATE_THRESHOLD`). High-impact actions on
hosts whose `criticality` is in `CRITICAL_HOST_LEVELS` are queued for human approval even
when every bar is cleared.

Guidance: keep reversible actions cheap to trigger and irreversible actions expensive.
If you add an action, give it an `impact` tier and decide whether criticality should
force a human in the loop.

## Demo plumbing

| Variable | Default | Meaning |
|---|---|---|
| `MOCK_JEV` | `None` | `None` = mock iff no key · `True` = force mock (even with a key — useful for A/B) · `False` = require a key |
| `SHOW_RICH_TABLES` | `False` | Also render pandas tables alongside the text trace |
| `HIDDEN_UNTIL_INVESTIGATION` | `("enrichment", "correlated_activity")` | State sections withheld from pass 1 and from the investigator's direct view; also the merge whitelist in `sanitize_extra` |
| `DATA_DIR` | `"data"` | Folder containing `questions.json` / `demo-states.json`, resolved against the notebook's directory; set it to your own folder to point at real alerts |
