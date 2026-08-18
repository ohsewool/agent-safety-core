# ADR-001: 모듈 경계 — core는 도메인을 모른다

- 상태: 승인 (2026-08-19)
- 근거: 외부 리뷰 2건(2026-08-18)과 Deep Research 3건이 공통 지시한 구조

## 결정

`core/`(event, policy, lease, journal, evidence)는 payment, merchant, 법령, MCP, 특정 프레임워크를 알지 못한다.
도메인 로직은 `profiles/`(ap2, kr_ai_act)와 `adapters/`에만 둔다.

## 강제 규칙

1. `core/` 안에서 `profiles/`·`adapters/`를 import하면 위반.
2. 도메인 필드가 event schema의 required로 승격되면 위반 — 도메인 데이터는 profile이 정의하는 확장 필드로만.
3. AP2 schema 변경·한국법 개정이 `core/`의 journal semantics 수정을 요구하면 설계 재검토.

## 결과

- 결제 vertical(P1~)은 `profiles/ap2` + `adapters/mock_payment`로 구현된다.
- 한국법 profile은 조항→이벤트 매핑과 support_level(직접/간접/미지원/적용대상 확인)을 담은 데이터+생성기이며, core 기능이 아니다.
- 외부 판정이 MERGE(기존 OSS 확장)로 나와도 core 프리미티브는 해당 OSS의 모듈/PR로 이식 가능한 단위를 유지한다.
