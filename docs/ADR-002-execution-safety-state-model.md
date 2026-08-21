# ADR-002: 실행 안전 상태 모델 — 단일 트랜잭션 원장

- 상태: 승인 (2026-08-19)
- 대체: ADR-001의 모듈 경계는 유효. 본 문서는 그 위의 상태·저장 모델을 확정한다.
- 계기: 적대적 설계 검증(`work/Agent-Execution-Safety-Core-적대적-설계-검증-결과.md`)이 **NO(재설계)** 판정. CRITICAL 3건(F-01 scope 결손, F-02 lease 비원자성, F-03 cross-store 원자성 부재)이 v0의 "JSONL 저널 + 별도 lease 원장" 모델에서 구조적으로 발생함.

## 1. 결정 요약

**단일 트랜잭션 저장소(SQLite)를 system of record로 삼고, 해시 체인 저널은 그 저장소로부터 파생되는 export/projection으로 강등한다.**

v0는 JSONL 저널이 곧 진실이었다. 그 결과 실행 권한(lease)과 감사 기록이 서로 다른 저장소에 있었고, 둘 사이에 트랜잭션 경계가 없어 "lease는 소비됐는데 증적이 없는" 모순 상태가 가능했다. 상태 전이와 증적을 하나의 원자적 커밋으로 묶는 것 외에 이를 해소하는 방법이 없다.

```
[변경 전]  JSONL 저널(진실) + lease 원장(별도 파일)   → 두 진실, 경계 없음
[변경 후]  SQLite 원장(유일한 진실) ──export──> 해시 체인 저널(검증 가능한 사본)
```

SQLite를 고르는 이유: 단일 파일·의존성 없음(1인 개발 제약), 실제 ACID 트랜잭션, `UNIQUE` 제약으로 CAS 구현 가능, WAL 모드로 crash-safe. "불필요한 분산 시스템 금지"라는 기존 제약과도 맞는다.

## 2. 실행 상태 기계

모든 side-effecting 실행은 하나의 `execution` 행으로 표현되며 아래 전이만 허용한다.

```
CREATED ──approve──> APPROVED ──claim──> LEASE_CLAIMED ──dispatch──> DISPATCHING
                          │                    │                          │
                          ├──revoke──> REVOKED │                          ├──> SUCCEEDED
                          └──expire──> EXPIRED └──release──> APPROVED     ├──> FAILED
                                                                          └──> UNKNOWN
                                                                                 │
                                            reconcile ──────────────────────────┤
                                                                                 ├──> SUCCEEDED
                                                                                 ├──> FAILED
                                                                                 └──> PERMANENTLY_UNRESOLVED
```

규칙:

- 전이는 저장소 트랜잭션 안에서만 일어나며, **전이와 그 증적 이벤트는 같은 커밋에 포함된다** (F-03 해소).
- `DISPATCHING` 진입은 외부 호출 **이전에** durable commit되어야 한다. 커밋 실패 시 외부 호출을 하지 않는다 (F-02·F-05 전제).
- `DISPATCHING`에서 프로세스가 죽으면 재시작 시 그 행은 자동으로 `UNKNOWN`으로 판정된다. 재시도가 아니라 reconciliation 대상이다.
- 에이전트는 어떤 최종 상태도 스스로 선언할 수 없다. 상태 전이는 코어만 기록한다 (F-10 해소).

## 3. 불변식 재정의

레드팀 판정에 따라 기존 불변식 3을 둘로 분리한다.

| # | 불변식 | 증명 범위 |
|---|---|---|
| 1 | 유효한 승인(ACTIVE 상태) 없이는 side-effecting 실행이 시작되지 않는다 | 코어 내부에서 증명 가능 |
| 2 | 승인 후 **바인딩된 scope의 어느 요소라도** 달라지면 실행이 거부된다 | 코어 내부에서 증명 가능 (§4의 scope 정의에 한해) |
| **3A** | **동일 lease는 최대 1회의 외부 dispatch만 허용한다** (at-most-once dispatch — 0회일 수 있음) | 코어 내부에서 증명 가능. 단 "consume이 외부 호출보다 먼저 durable commit"이 성립할 때만 |
| **3B** | `UNKNOWN` 상태의 동일 logical action은 reconciliation 또는 외부 idempotency 증거 없이 새 authorization을 발급받지 못한다 | 코어 내부에서 증명 가능 |
| 4 | 성공/실패를 증명할 수 없으면 `UNKNOWN`으로 기록하고 자동 재시도하지 않는다 | 코어 내부에서 증명 가능 |
| 5 | 이벤트의 수정·삭제·삽입·재정렬은 검증기가 탐지한다 (tamper-evident) | v0 범위. 전체 재작성 탐지는 §7 |

**명시적 비보장**: 외부 시스템 수준의 logical exactly-once. 외부가 idempotency key를 지원하면 `execution_id`를 key로 전파해 달성하고, 지원하지 않으면 그 한계를 증적에 기록한다. 이 경계를 문서와 README에 명시한다.

## 4. 승인 scope 정의 (F-01·F-06·F-07 해소)

`scope_digest`는 다음 요소 전부에 바인딩된다.

```
scope_digest = H(
    run_id,
    actor_effective_identity,     # core가 결정, caller 입력 아님
    tool_id,
    operation,
    arguments_digest,             # canonical, §5 규칙 적용
    resource_identity_digest,     # 문자열이 아닌 해석된 정체성 — 아래 참조
    policy_id, policy_version, policy_digest,   # 내용 해시까지 (F-06)
    execution_context_digest,     # 실행 의미에 영향을 주는 항목만 (F-01)
)
```

- **resource_identity_digest** (F-07): 경로는 canonical absolute path + 파일 정체성(가능하면 inode/device 또는 파일 핸들 기반), URL은 최종 해석된 origin. 승인 시 기록하고 **실행 직전 재해석해 비교**한다. symlink/junction 교체, DNS rebinding을 이 비교가 잡는다.
- **execution_context_digest** (F-01): `code_revision`, 도구 구현 버전, 실행 신원, 유효 작업 디렉터리, 환경 보안 프로파일. **무관한 환경 변화로 승인이 무효화되지 않도록 포함 항목을 화이트리스트로 고정**한다(잔존 위험 대응).
- **policy_digest** (F-06): 버전 문자열이 아니라 로딩된 정책 아티팩트의 내용 해시. 실행 시 재확인한다.

## 5. 입력 정규화 규칙 (F-14·F-15 해소)

untrusted 입력은 파싱 단계에서 다음을 강제한다.

- **중복 키는 무조건 거부** — 파싱 이후엔 중복이었다는 사실이 소실되어 복구 불가. (MCP 게이트웨이 `transport.py`에 이미 구현됨: `_reject_duplicate_keys`)
- 승인 경로와 실행 경로는 **동일한 파서·canonicalizer 구현**을 사용한다.
- arguments 계약: 키는 문자열만, `NaN`/`Infinity` 거부, 중첩 깊이·크기 상한, 유니코드 정규화 정책 고정(NFC).

## 6. 동시성·시간 (F-02·F-04·F-16 해소)

- **lease claim**: `UPDATE ... WHERE state='APPROVED' AND lease_id=?`의 영향 행 수로 CAS 판정. 1이면 획득, 0이면 이미 소비. 트랜잭션 커밋 후에만 외부 호출로 진행한다.
- **저널 직렬화**: `sequence`는 저장소가 단일 authority로 발급한다(AUTOINCREMENT). 다중 프로세스가 같은 tip을 읽고 분기하는 F-04 시나리오가 구조적으로 불가능해진다.
  **(2026-08-21 실측)** 이 문장은 프로세스에 대해 말하는데 동시성 테스트는 전부 스레드였다 — 한 프로세스 안의 스레드는 연결을 공유하고 GIL이 상당 부분을 직렬화하므로 각자 연결을 열고 OS 파일 락으로 경쟁하는 것과 다른 상황이다. **더 어려운 쪽이 시험되지 않은 쪽이었다.** 프로세스 6개 × 12회로 재보니 sequence 144개가 전부 고유하고 빈틈이 없으며, 8개가 같은 lease를 노려도 정확히 하나만 획득하고, export한 체인이 검증을 통과한다. 주장은 성립한다. `tests/test_multiprocess_ledger.py`가 고정한다.
- **만료 판정**: 런타임 TTL은 monotonic clock 기준. wall clock 역행이 감지되면 security-sensitive lease는 fail-closed. 재시작 후에는 persisted expiry + boot/session identity로 판정한다.

## 7. 증적과 무결성 (F-12·F-13 해소)

- 저널은 SQLite 원장에서 export되는 해시 체인 JSONL이며, 그 자체가 진실이 아니다. 검증기는 export의 내부 일관성과 원장 대조를 모두 지원한다.
- **anti-rollback (F-12)**: 체크포인트에 `log_id, checkpoint_sequence, journal_tip_hash, previous_checkpoint_hash, signed_at`을 포함한다. 서명만으로는 freshness가 없으므로, 검증기는 **독립된 append-only 외부 witness의 최신 sequence**를 조회해 과거 상태 복원을 탐지한다. 두 fork가 모두 유효 서명을 갖는 경우도 이 sequence로 판정한다. (M3 구현, 구조는 지금 확정)
- **redaction lifecycle (F-13)**: 민감 payload를 불변 감사 봉투에서 분리한다. 이벤트에는 `payload_digest`·`payload_reference`·`classification`만 남기고 실제 값은 별도 암호화 저장소에 둔다. 삭제는 기존 이벤트 수정이 아니라 **payload/키 삭제 + destruction 이벤트 append**로 수행한다. legal hold도 별도 상태 이벤트다.

## 8. 승인 수명주기와 fail-closed (F-08·F-09·F-11 해소)

- **승인 상태**: `ACTIVE / REVOKED / EXPIRED / CONSUMED`. 실행 직전 authoritative store에서 조회한다. 발급된 lease도 취소 가능해야 하며, 긴급 정지(emergency stop)를 별도로 정의한다. (F-08)
- **reconciliation 권한** (F-09): `UNKNOWN`의 최종 분류는 코어의 reconciler만 수행하며, reconciliation 이벤트에 `reconciler_identity, adapter_version, external_lookup_target, evidence_digest, observed_at, previous_state, new_state, decision_reason`을 기록한다. 해소 불가 시 `PERMANENTLY_UNRESOLVED`로 종결하고 사람 검토로 넘긴다. 에이전트가 제출한 최종 상태 주장은 거부한다.
- **fail-closed 분류 경로** (F-11): 위험 분류가 정책 엔진과 같은 fail domain에 있으면 장애 시 분류 자체가 불가능하다. 따라서 결정론적 로컬 규칙을 둔다 — `UNKNOWN RISK == BLOCK`, `UNKNOWN TOOL == BLOCK`, `POLICY UNAVAILABLE == BLOCK all consequential actions`. 가용성 DoS는 의도된 trade-off로 수용하고 rate limit·저장소 격리로 완화한다.

## 9. 개정된 M1 종료 조건

레드팀 "M1 전 필수 10개"를 종료 조건으로 승격한다. 아래 회귀 테스트가 전부 녹색이어야 M2로 간다.

| # | 회귀 테스트 | 대응 finding |
|---|---|---|
| 1 | 동일 lease를 100 프로세스가 동시 제출 → 인가 1, 외부 dispatch ≤1, 나머지 `lease_already_consumed` | F-02 |
| 2 | 각 durable write 사이 crash injection → 재시작 후 이중 dispatch 없음, 증적 없는 성공 상태 없음 | F-03 |
| 3 | 승인 후 `code_revision`/환경만 변경 → 거부 | F-01 |
| 4 | 승인 후 policy bytes만 변경(version 유지) → 거부 | F-06 |
| 5 | 승인 후 symlink target 변경 → 거부 | F-07 |
| 6 | 승인 → lease 발급 → 승인 철회 → 실행 시도 → 차단 | F-08 |
| 7 | caller가 `actor`/`sequence` 위조 제출 → 거부(코어가 발급) | F-10 |
| 8 | 정책 엔진 kill 상태에서 미분류 operation → 100% 차단 | F-11 |
| 9 | 중복 키 포함 입력 → validation error | F-14 |
| 10 | 응답 유실 강제 → 동일 lease 재제출 dispatch 0회 / 새 lease는 reconciliation 없이 차단 | F-05, 3B |

## 10. 폐기하는 것

- `core/event.py`의 `append_event()`를 진실의 기록자로 쓰는 방식 — export 경로로 재배치한다.
- caller가 `run_id`/`sequence`/`actor`/`status`를 지정하는 인터페이스 — 코어 발급으로 교체한다.
- 파일 기반 lease 원장 구상 — 트랜잭션 저장소로 흡수한다.

## 11. 남는 위험 (수용)

- 호스트·코어·키가 모두 침해되면 방어 불가 (범위 밖, 변함없음).
- 외부 시스템이 조회 API도 idempotency도 제공하지 않으면 logical exactly-once는 증명 불가 — 이 경우 `PERMANENTLY_UNRESOLVED`가 정직한 종착점이다.
- 고의적 감사 장애를 통한 가용성 DoS는 fail-closed의 대가로 수용한다.
