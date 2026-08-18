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
- [x] 정규화 이벤트 기록 + 해시 체인 + 변조 탐지 (`core/event.py`) — M0 종료 조건
- [ ] M1: append-only journal, redaction, 검증 CLI
- [ ] M2: 정책 엔진·승인 lease (Coordinator에서 이식)
- [ ] 이후는 외부 검증 판정에 따름

근거 문서: `work/AI-Research-work/M0-자산검증-보고서.md`, 계획서 v2 2종.
