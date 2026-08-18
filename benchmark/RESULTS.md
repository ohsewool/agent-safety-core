# AP2 fault-injection ablation

Ground truth is the payment world: charges performed, not charges believed.

## Per-scenario charges performed

| scenario | A | B | C | D | E | F |
|---|---|---|---|---|---|---|
| happy_path | 1 | 1 | 1 | 1 | 1 | 1 |
| timeout_after_effect | 2 ⚠ | 2 ⚠ | 1 | 1 | 1 | 1 |
| timeout_before_effect | 1 | 1 | 0 | 1 | 1 | 1 |
| crash_after_effect | 2 ⚠ | 2 ⚠ | 1 | 1 | 1 | 1 |
| repeated_uncertainty | 3 ⚠ | 3 ⚠ | 1 | 1 | 1 | 1 |
| amount_escalation | 1 | 0 | 1 | 1 | 0 | 0 |
| processor_error | 0 | 0 | 0 | 0 | 0 | 0 |
| reconcile_unavailable | 2 ⚠ | 2 ⚠ | 1 | 1 | 1 | 1 |
| idempotent_processor | 2 ⚠ | 2 ⚠ | 1 | 1 | 1 | 1 |

## Totals across all scenarios

| arm | duplicate | unauthorized | false retries | unresolved | work left undone |
|---|---|---|---|---|---|
| A | 6 | 1 | 6 | 0 | 0 |
| B | 6 | 0 | 6 | 0 | 0 |
| C | 0 | 1 | 0 | 0 | 1 |
| D | 0 | 1 | 0 | 1 | 0 |
| E | 0 | 0 | 0 | 1 | 0 |
| F | 0 | 0 | 0 | 0 | 0 |

## Attribution (relative to arm A)

**B — exact scope binding**
- duplicate side effects prevented: 0
- unauthorized side effects prevented: 1
- false retries prevented: 0

**C — single-use lease**
- duplicate side effects prevented: 6
- unauthorized side effects prevented: 0
- false retries prevented: 6
- **cost**: 1 legitimate completion(s) lost

**D — UNKNOWN + reconciliation**
- duplicate side effects prevented: 6
- unauthorized side effects prevented: 0
- false retries prevented: 6

**E — full combination**
- duplicate side effects prevented: 6
- unauthorized side effects prevented: 1
- false retries prevented: 6
- no gain beyond the best single mechanism on these metrics

**F — E + postcondition verification (independent channel)**
- duplicate side effects prevented: 6
- unauthorized side effects prevented: 1
- false retries prevented: 6
- **outcomes E could not resolve, now resolved: 1** — asking the processor fails when the processor is what broke; observing the world does not

