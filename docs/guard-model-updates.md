# Guard Model Updates

Guard runtime ships model parameters as JSON files in `models/guard/`.

The public runtime does not train models. It loads an accepted model file, combines the Markov-chain score with deterministic rules, and falls back to deterministic baseline scoring when the model does not know a state.

## Source of new models

Guard Lab owns model improvement:

```text
new traces/datasets
  -> ingestion + normalization
  -> weak labels / evaluation labels
  -> candidate Markov model
  -> benchmark against current shipped model
  -> promote only if better
  -> PR new JSON into kontext-cli/models/guard
```

## Promotion rule

A candidate model should not replace the shipped model unless it improves the agreed evaluation gate. At minimum, compare:

- precision/recall for risky events
- false positive rate on normal coding flows
- Brier/calibration where labels exist
- behavior on hand-written regression fixtures
- deterministic-rule compatibility

## Runtime contract

- Model files are local JSON artifacts.
- Guard mode must not call a hosted scoring service.
- Unknown model states must not crash runtime.
- Deterministic rules remain authoritative for obvious security risk.
