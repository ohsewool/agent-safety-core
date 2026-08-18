# AP2 fault-injection ablation

Measures whether each proposed mechanism actually prevents harm, and what it
costs, by running five agent runtimes through the same set of payment failures.

```bash
python3 benchmark/run.py                 # markdown report
python3 benchmark/run.py --json          # raw measurements
python3 benchmark/run.py --out RESULTS.md
```

## What is measured

Ground truth is the payment world's own record of charges performed — not what
any arm believed happened. An arm that thinks it failed while the money moved is
counted as having moved the money.

| metric | meaning |
|---|---|
| duplicate side effects | charges beyond the first for one intent |
| unauthorized side effects | charges outside the approved scope |
| false retries | retries issued after the effect had already happened |
| unresolved | ended without establishing what happened |
| **work left undone** | correct work the arm refused to complete |

The last metric exists because without it an arm that simply gives up scores
perfectly. Refusing to retry buys zero duplicates at a price, and the price
should be visible.

## Arms

| arm | mechanism |
|---|---|
| A | ordinary approval + logging (the baseline most runtimes implement) |
| B | A + exact scope binding |
| C | A + single-use / expiring lease |
| D | A + explicit `UNKNOWN` + reconciliation before retry |
| E | B + C + D + verifiable evidence |

Arm A is not a strawman: it retries on timeout, which is the natural response
when a call fails. The scenarios are what make that response wrong.

## Findings (2026-08-19)

| arm | duplicate | unauthorized | false retries | unresolved | work left undone |
|---|---|---|---|---|---|
| A | 6 | 1 | 6 | 0 | 0 |
| B | 6 | 0 | 6 | 0 | 0 |
| C | 0 | 1 | 0 | 0 | 1 |
| D | 0 | 1 | 0 | 1 | 0 |
| E | 0 | 0 | 0 | 1 | 0 |

1. **Scope binding and duplicate prevention are independent.** B stops the
   unauthorized charge and prevents no duplicates; C and D prevent every
   duplicate and stop no unauthorized charge. Neither substitutes for the other.

2. **A lease alone prevents duplicates by never retrying, and that has a cost.**
   C loses a legitimate completion in `timeout_before_effect`, where nothing had
   happened and retrying was the correct action.

3. **Reconciliation gets the same protection without the cost.** D matches C on
   duplicates and false retries while leaving no work undone, because it
   establishes what happened rather than assuming.

4. **One case is honestly unresolvable.** When the processor cannot be queried,
   D and E end `PERMANENTLY_UNRESOLVED` rather than guessing. That is the
   intended behaviour, and the unresolved count is reported rather than hidden.

5. **No gain in E is unattributable.** Every improvement E shows is already
   produced by B, C, or D individually; E's contribution is covering all harm
   metrics at once, not a synergy. Reported as such rather than claimed as one.

## Limits

- Single-process simulation: concurrency is modelled as repeated attempts, not
  real parallel workers. The ledger's concurrent-claim behaviour is tested
  separately in `tests/test_ledger.py`.
- Deterministic, no sampling — these are exact counts for these scenarios, not
  estimates with confidence intervals.
- The scenario set is derived from the AP2 threat list and is not exhaustive.
