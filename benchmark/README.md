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

## 이 주장들이 실제 시스템에서도 성립하는가

위 arm들은 메커니즘 하나씩을 분리하려고 따로 만든 것이고, 그래서 당연한 반론이 남는다 — **그 arm들은 시스템이 아니다**.

`profiles/ap2/payment_guard.py`가 그 간극을 메운다. 실제 ledger·scope binder·access control 위에서 결제를 실행하며, `tests/test_payment_guard.py`의 19개 테스트가 벤치마크의 발견을 하나씩 재현한다 — 승인된 금액이 아닌 청구는 거부되고, lease는 두 번 쓰이지 않고, 응답을 잃으면 실패가 아니라 UNKNOWN이 되고, 조회 수단이 없으면 추측 대신 PERMANENTLY_UNRESOLVED로 끝난다. 지상 진실은 여기서도 프로세서가 기록한 실제 청구 횟수다.

## Limits

- Single-process simulation: concurrency is modelled as repeated attempts, not
  real parallel workers. The ledger's concurrent-claim behaviour is tested
  separately in `tests/test_ledger.py`, and the end-to-end payment path in
  `tests/test_payment_guard.py`.
- Deterministic, no sampling — these are exact counts for these scenarios, not
  estimates with confidence intervals.
- The scenario set is derived from the AP2 threat list and is not exhaustive.
