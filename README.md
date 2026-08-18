# Agent Execution Safety & Evidence Core (작업명 — 최종 명칭 미정)

> 상태: **M0 스캐폴드** (2026-08-19). 독립 외부 검증(GO/NARROW/MERGE/BENCHMARK/STOP) 대기 중.
> 이 저장소는 어떤 법률 준수도 보장하지 않으며, 기록은 위변조 탐지 가능(tamper-evident)일 뿐 위변조 불가능(tamper-proof)이 아니다.

side-effecting AI 에이전트 실행의 안전성·증적을 다루는 좁은 런타임 코어.
검증된 기존 구현(Coordinator, 테스트 215개)에서 다음 프리미티브를 추출·범용화한다:

1. 승인-실행 정밀 바인딩 (exact approval-to-execution binding)
2. 1회성/만료 실행 lease (single-use / expiring execution lease)
3. crash-safe 실행 상태 전이
4. 명시적 `UNKNOWN_OUTCOME` (성공/실패를 증명할 수 없는 상태의 1급 취급)
5. 재시도 전 reconciliation
6. 검증 가능한 실행 증적 (canonical serialization + hash chain)

## 모듈 경계 (ADR-001)

```
core/      — event, policy, lease, journal, evidence. 도메인(payment/법령/MCP)을 알지 못함
profiles/  — ap2 (결제 검증 프로파일), kr_ai_act (한국 AI 기본법 evidence profile)
adapters/  — 프레임워크/실행환경 어댑터 (범용 인터페이스)
schema/    — event schema (JSON Schema, 버전 관리)
```

도메인 요구가 core의 event model·journal semantics를 오염시키면 설계를 재검토한다.

## 현재 구현 상태

- [x] event schema v0 (`schema/event.schema.json`)
- [x] 해시 체인 이벤트 기록 + 변조 탐지 (`core/event.py`) — **저널은 export 경로로 강등됨(ADR-002)**
- [x] **트랜잭션 실행 원장 (`core/ledger.py`)** — system of record. 원자적 lease claim, 상태 전이와 증적의 단일 커밋, 중단 복구(→UNKNOWN), 승인 철회, reconciliation 권한 분리
- [x] **입력 canonicalizer (`core/canonical.py`)** — 중복키·비유한수·과도한 중첩 거부, NFC 정규화
- [x] **scope binder (`core/scope.py`)** — 해석된 resource identity(inode/origin), policy 내용 digest, context allow-list. `rebind()`가 dispatch 직전 재해석
- [x] **증적 export + 검증기 (`core/export.py`)** — 원장→해시체인 JSONL, `python -m core.export verify <file>`
- [x] **M2 조기 달성**: MCP 게이트웨이가 `ExecutionLedger`를 authority로 사용 (`mcp-gateway` 커밋 69d56ad)
- [x] **AP2 결함주입 ablation (`benchmark/`)** — arm A~E × 시나리오 9종, 지상 진실(실제 charge 수) 기준 측정. 결과: `benchmark/README.md`
- [x] **서명·anti-rollback 체크포인트 (`core/checkpoint.py`)** — Ed25519 서명 + monotonic sequence + 외부 witness. 유효 서명을 가진 과거 상태 복원(rollback)과 미발행 fork를 탐지
- [x] **redaction lifecycle (`core/payload.py`)** — 민감 payload를 불변 감사 봉투와 분리 저장. 삭제 = payload/키 파기 + destruction 이벤트 append(체인 수정 없음), legal hold 우선

- [x] **한국 AI 기본법 evidence profile (`profiles/kr_ai_act/`)** — 조항별 지원수준(직접/간접/미지원/적용대상 확인 필요) 분류, 증적 패키지 생성(JSON·Markdown), "준수 보장 아님"과 런타임 외 증거 목록을 모든 패키지에 포함

## 남은 작업

- 실 배포용 암호화 교체(현재 XOR 키스트림은 "키를 파기하면 payload가 사라진다"를 보이기 위한 것 — AES-GCM으로 교체 시 `_obfuscate` 하나만 바뀜)
- 조직 RBAC, 장기 보존 정책 연동
- 외부 witness의 실제 배포 형태 결정(transparency log / 객체 스토리지 버저닝 / 제3자)

## 검증 이력

적대적 설계 검증(2026-08-19)에서 v0 설계가 **NO(재설계)** 판정을 받았다. CRITICAL 3건(승인 scope 결손, lease 비원자성, cross-store 원자성 부재)은 "JSONL 저널 + 별도 lease 원장" 모델의 구조적 결함이었다. `docs/ADR-002-execution-safety-state-model.md`가 그 재설계이며, `tests/test_ledger.py`의 21개 회귀 테스트가 각 finding을 닫는다(동시 24스레드 lease 경합에서 dispatch 정확히 1회 포함).

근거 문서: `work/Agent-Execution-Safety-Core-적대적-설계-검증-결과.md`, `work/AI-Research-work/M0-자산검증-보고서.md`.
