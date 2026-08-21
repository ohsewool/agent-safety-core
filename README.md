# Agent Execution Safety & Evidence Core

[![tests](https://github.com/ohsewool/agent-safety-core/actions/workflows/tests.yml/badge.svg)](https://github.com/ohsewool/agent-safety-core/actions/workflows/tests.yml)

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
core/binding.py     인자 동등성 — 무엇이 "다른 호출"인지 명시적으로 선언
core/ledger.py      트랜잭션 실행 원장 (system of record) — 원자적 lease, 단일 커밋, 중단 복구
core/export.py      원장 → 해시 체인 JSONL + 파일만으로 동작하는 검증기
core/checkpoint.py  Ed25519 서명 + 외부 witness — 롤백·포크 탐지
core/payload.py     민감값 분리 저장(AES-256-GCM) — 삭제해도 감사 체인이 깨지지 않음
core/access.py      역할·권한 분리 — 자기 승인 금지, 감사자와 파기 권한 분리
core/verification.py 후조건 검증 — 되묻지 않고 세계 상태를 관찰해 UNKNOWN 해소
core/retention.py   보존 기간 — 라벨이 아니라 강제되는 규칙, legal hold가 우선
profiles/kr_ai_act/ 한국 AI 기본법 조항 → 런타임 증적 매핑
profiles/ap2/       결제 vertical — 벤치마크의 주장을 실제 코어 위에서 재현
adapters/           기존 도구를 감싸 코어의 규칙 아래로 넣는 최소 표면
benchmark/          결함 주입 ablation (A~E)
```

```bash
python3 -m pytest tests/ -q          # 359 tests
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
| F E + 후조건 검증 | **0** | **0** | **0** | **0** | 0 |

1. **scope 바인딩과 중복 방지는 서로 대체할 수 없다.** B는 미승인 청구를 막지만 중복은 하나도 못 막고, C·D는 그 반대다.
2. **lease 단독은 재시도를 아예 하지 않아 중복 0을 얻는다.** 그 대가로 "아무 일도 일어나지 않았으니 재시도가 옳았던" 경우에 정당한 작업을 잃는다. 이 비용이 보이지 않으면 포기하는 구현이 완벽해 보인다.
3. **reconciliation은 그 비용 없이 같은 보호를 얻는다.** 가정하는 대신 무슨 일이 있었는지 확인하기 때문이다.
4. **한 시나리오는 정직하게 해결 불가다.** 조회 API가 없으면 D·E는 추측하지 않고 `PERMANENTLY_UNRESOLVED`로 끝낸다.
5. **E의 이득은 전부 개별 메커니즘에 귀속된다.** 시너지 주장은 하지 않는다.

6. **되묻는 것과 보는 것은 다르다.** E는 프로세서에게 "무슨 일이 있었나"를 되묻는데, 정작 프로세서가 고장 난 경우엔 그 질문이 응답이 사라진 경로를 그대로 지나간다. F는 대신 독립 채널에서 후조건을 관찰해, E가 미해결로만 남길 수 있었던 건을 해소한다. (arXiv:2608.02645 — 재시도 정책이 아니라 검증이 중복을 줄인다는 측정 결과)

위 arm들은 메커니즘을 분리하려 따로 만든 것이라 "그건 시스템이 아니다"라는 반론이 남는다. `profiles/ap2/`가 같은 속성을 **실제 ledger·scope binder·access control 위에서** 재현한다.

## 무엇이 "다른 호출"인가

승인은 인자 digest에 묶이고, 기본은 엄격하다 — `1000`과 `1000.0`은 다르고 `["a","b"]`와 `["b","a"]`도 다르다. 안전한 기본값이지만 공짜는 아니다. 플래너가 요청 내용을 바꾸지 않고 표현만 바꿔도 승인이 거부되고, 맞는 일을 거부하는 시스템은 사람에게 두 번 승인하는 습관을 들인다.

그렇다고 전부 정규화하면 문제가 더 커진다. `["alice","bob"]`이 `["bob","alice"]`와 같다는 판단은 도메인에 대한 주장이고, 순서대로 결재하는 승인자 목록에서는 틀린 주장이다.

그래서 동등성은 **인자별로 선언**하고 추론하지 않는다. 그리고 정책 자체가 digest에 포함된다 — 승인을 받은 뒤 규칙을 느슨하게 바꾸면 그 승인이 허용하는 범위가 넓어지므로, 대신 승인이 무효가 된다.

```python
policy = ArgumentPolicy({"amount": Equivalence.NUMERIC, "tags": Equivalence.UNORDERED})
# amount는 1000 == 1000.0, tags는 순서 무관. 나머지는 전부 엄격.
```

## 기존 에이전트에 붙이기

이미 동작하는 에이전트를 다시 짜야 한다면 이 코어의 보장은 값이 없다. 어댑터는 부작용을 일으키는 함수 하나를 감싸는 것이 전부다.

```python
charge = guard.guarded(charge_customer, tool_id="payments")

charge(amount=1000, payee="m1")                  # ApprovalRequired — 아무것도 청구되지 않음
charge(amount=1000, payee="m1", _lease=lease)    # 정확히 한 번 청구
charge(amount=9999, payee="m1", _lease=lease)    # LeaseRefused — 승인된 청구가 아님
```

자동 승인 옵션도, 재시도 헬퍼도 없다. 응답을 잃으면 falsy 값이 아니라 예외가 난다 — 타임아웃 뒤에 `if not result:`를 쓰는 순간 불확실한 청구가 실패로 둔갑하기 때문이다. 승인은 어댑터가 아니라 별도 객체에 두었다. 같은 객체에 있으면 자기 승인이 한 줄 수정이 된다.

## 설계 이력 — 이 저장소가 한 번 반려된 기록

v0 설계는 적대적 검증에서 **NO(재설계)** 판정을 받았다. CRITICAL 3건 — 승인 scope에 실행 컨텍스트가 없어 코드가 바뀌어도 통과, lease 검증과 소비가 원자적이지 않아 두 워커가 동시 통과, 저널과 lease 원장 사이에 트랜잭션 경계가 없어 "권한은 썼는데 증적이 없는" 상태 도달 가능 — 은 전부 "JSONL 저널이 진실"이라는 모델의 구조적 결함이었다.

[`docs/ADR-002`](docs/ADR-002-execution-safety-state-model.md)가 그 재설계다: SQLite 트랜잭션 원장을 system of record로 삼고 해시 체인 저널을 export로 강등했다. `tests/test_ledger.py`가 각 finding을 닫으며, 그중 하나는 **24개 스레드가 같은 lease를 동시에 노려도 dispatch가 정확히 1회**임을 확인한다.

## 권한 분리 (`core/access.py`)

감사 로그는 자신이 기록하는 시스템보다 더 매력적인 표적이다 — 프롬프트·도구 인자·거쳐간 개인정보가 한곳에 모이기 때문이다. 그래서 분리는 정돈이 아니라 구체적 남용을 겨냥한다.

| 분리 | 막는 것 |
|---|---|
| 승인자 ≠ 요청자 | 자기 승인. 이게 허용되면 승인 게이트는 장식이다 |
| 감사자 ≠ 파기 권한 | 검토할 대상을 검토자가 지울 수 있는 상태 |
| payload 열람 ≠ 기록 열람 | 실행이 있었다는 사실을 보는 것과 그 내용을 보는 것은 다른 권한 |

기본은 거부다. 모르는 주체는 아무것도 갖지 못하고, 부여되지 않은 권한은 보유하지 않은 것이다. 역할 표 자체의 불변식(어떤 역할도 승인과 실행을 동시에 갖지 못한다 등)도 테스트로 고정된다.

## 남은 작업

- 계약을 만족하는 참조 witness 서버는 제공하지 않는다 — 두면 그것이 사실상 벤더가 되어 ADR-003의 결정이 무의미해진다

근거 문서: [ADR-001](docs/ADR-001-module-boundaries.md), [ADR-002](docs/ADR-002-execution-safety-state-model.md), [ADR-003](docs/ADR-003-witness-deployment.md), [위협 모델](docs/threat-model-and-non-goals.md), [PACKAGING](docs/PACKAGING.md), [벤치마크](benchmark/README.md).

## 라이선스

Apache License 2.0. [`LICENSE`](LICENSE) 참조.

## 함께 보기

이 저장소는 다섯 개 중 하나다. 전체 지도와 각각이 무엇을 발견했는지는 [프로필](https://github.com/ohsewool)에 있다.

- [`modelmate`](https://github.com/ohsewool/modelmate) — 증거가 없으면 확신하지 않는 모델링 도우미
- [`rag-profile-selector`](https://github.com/ohsewool/rag-profile-selector) — 인용이 어디를 가리키는지 측정 · 한국어 법령 코퍼스
- [`mcp-gateway`](https://github.com/ohsewool/mcp-gateway) — MCP 서버 앞의 보안 프록시
- [`document-intelligence`](https://github.com/ohsewool/document-intelligence) — 파서에 의존하지 않는 문서 증거 모델
