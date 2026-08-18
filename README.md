# Agent Execution Safety & Evidence Core

> 작업명 — 최종 명칭 미정. 이 저장소는 어떤 법률 준수도 보장하지 않으며, 기록은 위변조 **탐지 가능**(tamper-evident)일 뿐 위변조 불가능이 아니다.

AI 에이전트가 실제 부작용을 일으키는 작업(결제, 파일 쓰기, 외부 API 호출)을 할 때, **승인된 것만 정확히 한 번 실행되게 하고 그 사실을 나중에 증명할 수 있게** 하는 런타임 코어.

## 문제

에이전트에게 결제를 시켰다. 요청은 나갔는데 응답이 오지 않았다. 지금 재시도하면 두 번 결제될 수도 있고, 재시도하지 않으면 결제가 아예 안 됐을 수도 있다. **무슨 일이 일어났는지 모른다는 것 자체가 상태**인데, 대부분의 런타임은 이 상태를 표현하지 못하고 성공 아니면 실패로 뭉갠다.

이 코어가 지키는 다섯 가지:

| 불변식 | 의미 |
|---|---|
| 1 | 유효한 승인 없이는 부작용이 발생하지 않는다 |
| 2 | 승인 후 바인딩된 요소가 하나라도 달라지면 실행이 거부된다 |
| 3A | 동일 lease는 최대 1회만 외부로 dispatch된다 |
| 3B | `UNKNOWN` 상태의 작업은 reconciliation 없이 새 승인을 받지 못한다 |
| 4 | 결과를 증명할 수 없으면 `UNKNOWN`으로 기록하고 자동 재시도하지 않는다 |
| 5 | 이벤트의 수정·삭제·삽입·재정렬은 검증기가 탐지한다 |

3을 3A/3B로 나눈 이유: 외부 시스템 수준의 exactly-once는 코어 단독으로 증명할 수 없다. 증명할 수 있는 것만 약속한다.

## 무엇이 들어 있나

```
core/canonical.py   입력 정규화 — 중복 키·비유한수·과도한 중첩 거부, NFC 정규화
core/scope.py       승인 바인딩 — 해석된 resource identity, 정책 내용 digest, context allow-list
core/ledger.py      트랜잭션 실행 원장 (system of record) — 원자적 lease, 단일 커밋, 중단 복구
core/export.py      원장 → 해시 체인 JSONL + 파일만으로 동작하는 검증기
core/checkpoint.py  Ed25519 서명 + 외부 witness — 롤백·포크 탐지
core/payload.py     민감값 분리 저장(AES-256-GCM) — 삭제해도 감사 체인이 깨지지 않음
profiles/kr_ai_act/ 한국 AI 기본법 조항 → 런타임 증적 매핑
benchmark/          결함 주입 ablation (A~E)
```

```bash
python3 -m pytest tests/ -q          # 120 tests
python3 benchmark/run.py             # ablation 리포트
python3 -m core.export verify <file> # 증적 검증
```

## 실험 결과 — 각 메커니즘이 실제로 무엇을 막는가

지상 진실은 결제 세계가 기록한 **실제 청구 횟수**다. 각 arm이 무엇을 믿었는지가 아니다.

| arm | 중복 청구 | 미승인 청구 | 허위 재시도 | 미해결 | 작업 미완 |
|---|---|---|---|---|---|
| A 승인+로깅 (일반적인 런타임) | 6 | 1 | 6 | 0 | 0 |
| B A + scope 바인딩 | 6 | **0** | 6 | 0 | 0 |
| C A + 1회용 lease | **0** | 1 | **0** | 0 | **1** |
| D A + UNKNOWN + reconciliation | **0** | 1 | **0** | 1 | 0 |
| E 전부 | **0** | **0** | **0** | 1 | 0 |

1. **scope 바인딩과 중복 방지는 서로 대체할 수 없다.** B는 미승인 청구를 막지만 중복은 하나도 못 막고, C·D는 그 반대다.
2. **lease 단독은 재시도를 아예 하지 않아 중복 0을 얻는다.** 그 대가로 "아무 일도 일어나지 않았으니 재시도가 옳았던" 경우에 정당한 작업을 잃는다. 이 비용이 보이지 않으면 포기하는 구현이 완벽해 보인다.
3. **reconciliation은 그 비용 없이 같은 보호를 얻는다.** 가정하는 대신 무슨 일이 있었는지 확인하기 때문이다.
4. **한 시나리오는 정직하게 해결 불가다.** 조회 API가 없으면 D·E는 추측하지 않고 `PERMANENTLY_UNRESOLVED`로 끝낸다.
5. **E의 이득은 전부 개별 메커니즘에 귀속된다.** 시너지 주장은 하지 않는다.

## 설계 이력 — 이 저장소가 한 번 반려된 기록

v0 설계는 적대적 검증에서 **NO(재설계)** 판정을 받았다. CRITICAL 3건 — 승인 scope에 실행 컨텍스트가 없어 코드가 바뀌어도 통과, lease 검증과 소비가 원자적이지 않아 두 워커가 동시 통과, 저널과 lease 원장 사이에 트랜잭션 경계가 없어 "권한은 썼는데 증적이 없는" 상태 도달 가능 — 은 전부 "JSONL 저널이 진실"이라는 모델의 구조적 결함이었다.

`docs/ADR-002`가 그 재설계다: SQLite 트랜잭션 원장을 system of record로 삼고 해시 체인 저널을 export로 강등했다. `tests/test_ledger.py`가 각 finding을 닫으며, 그중 하나는 **24개 스레드가 같은 lease를 동시에 노려도 dispatch가 정확히 1회**임을 확인한다.

## 남은 작업

- 조직 RBAC, 장기 보존 정책 연동
- 외부 witness의 배포 형태 결정 (transparency log / 객체 스토리지 버저닝 / 제3자)

근거 문서: `docs/ADR-001`, `docs/ADR-002`, `docs/threat-model-and-non-goals.md`, `benchmark/README.md`.
