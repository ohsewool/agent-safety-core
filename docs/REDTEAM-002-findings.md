# 레드팀 2차 — ADR-002 이후 코드 (2026-08-19)

1차 레드팀은 **설계**에 NO를 냈고 ADR-002가 그에 답했다. 이건 그 뒤에 지어진 것에 대한 공격이다. 네 개를 시도했고 **넷 다 뚫렸다.**

| # | 공격 | 심각도 | 상태 |
|---|---|---|---|
| R2-01 | 요청한 에이전트가 자기 실행을 승인 | HIGH | 고침 |
| R2-02 | UNKNOWN으로 끝난 에이전트가 스스로 SUCCEEDED로 종결 | HIGH | 고침 |
| R2-03 | 시계 되감기로 만료된 승인이 부활 | MEDIUM | 고침(관측 한계 명시) |
| R2-04 | 한 워커의 재시작이 다른 워커의 진행 중 호출을 UNKNOWN으로 오분류 | HIGH | 고침 |

## R2-01 · R2-02 — 통제가 배선되지 않았다

둘의 원인은 하나다. `core/access.py`에는 `EXECUTION_RECONCILE` 권한도, `RECONCILER` 역할도, 승인 분리 헬퍼(`require_approval_separation`)도 있다. 그리고 **`core/ledger.py`는 그중 아무것도 import하지 않았다.**

`reconcile()`의 docstring은 "Agents may not perform this transition"이라고 적혀 있었고, `reconciler_id`는 검증되지 않는 자유 문자열이었다. 즉 UNKNOWN으로 끝난 에이전트가 자기 id를 넣어 "성공했다"고 선언할 수 있었다 — **에이전트가 무슨 일이 일어났는지 스스로 정하지 못하게 하려고 존재하는 상태를 바로 그 에이전트가 종결한 것이다.**

이건 이 프로젝트가 이미 만난 병이다. `retention.py`가 자기 영역에서 고쳤던 그것:

> 아무것도 강제하지 않는 라벨은 라벨이 없느니만 못하다. 감사에서는 통제처럼 읽히고 동작은 주석과 같다.

통제는 존재했고, 연결되지 않았다.

**수정**: 설정이 필요 없는 검사는 무조건 적용한다. 요청자와 승인자, 요청자와 조정자가 같으면 거부한다 — 둘 다 이미 행에 있는 정보라 외부 설정 없이 판단할 수 있다. 역할 기반 검사는 `access.py`가 계속 담당한다.

## R2-03 — TTL은 시계가 앞으로 갈 때만 경계다

`time.time()`은 단조가 아니다. NTP 보정이나 VM 스냅샷 복원이 시각을 뒤로 옮기면, 이미 지난 승인이 다시 유효해 보인다.

첫 수정은 승인 시각과만 비교했는데 부족했다. 흥미로운 경우는 시계가 **마감을 지나 갔다가 마감 이전으로 돌아오는** 것이고, 그러면 행의 어떤 값도 변하지 않은 채 승인이 살아 있는 것처럼 보인다.

**수정**: 원장이 관측한 시각의 최고점(high-water)을 유지하고, 모든 쓰기가 이를 갱신한다. 그보다 이전으로 돌아간 읽기는 정당한 상태가 아니므로 거부하고, 사유를 `clock_moved_backwards`로 남긴다 — "만료됨"과 "당신의 시계가 틀렸다"는 다른 대응이 필요하기 때문이다.

임계값은 두지 않았다. 여기서의 허용 오차는 검사를 조용하게 만들려고 발명한 숫자가 될 것이고, 거부가 안전한 방향이다.

### 탐지되지 않는 경우 — 숨기지 않는다

원장은 **자기가 관측한 시각**에 대해서만 반박할 수 있다. 시계가 마감을 지나 갔다가 돌아오는 동안 원장이 완전히 놀고 있었다면 그 사실은 어디에도 기록되지 않고, 어떤 검사도 복원할 수 없다 — 정보가 존재하지 않는다.

이 테스트의 첫 버전은 정확히 그걸 탐지하라고 요구했고 틀렸다. 지금은 한계를 `test_an_unwitnessed_excursion_is_documented_as_undetectable`로 고정해 둔다. 동작하는 시스템은 그 사이 다른 일을 하므로 실제로는 관측되지만, 그건 보장이 아니라 정황이다.

## R2-04 — 복구가 남의 실행을 건드렸다

`recover_interrupted()`가 `DISPATCHING` 상태의 **모든** 행을 UNKNOWN으로 바꿨다. 소유자 개념이 없었다.

두 워커가 원장을 공유할 때, 워커2가 재시작하면 워커1이 **지금 외부 호출 중인** 실행을 UNKNOWN으로 선언한다. 그리고 진짜 피해는 라벨이 아니다 — `record_outcome`이 `DISPATCHING`을 요구하므로, **실제로 성공한 호출을 워커1이 기록할 방법이 사라진다.** 아무 관계도 없는 프로세스 때문에 영구 미해결로 남는다.

**수정**: lease를 claim한 dispatcher를 행에 기록하고, 복구는 자기 것만 회수한다. 재시작한 워커는 같은 논리적 정체성(`dispatcher_id="worker-1"`)을 유지하면 자기 것을 정상적으로 회수한다.

전체 일괄 회수는 `all_dispatchers=True`로 남겼다. 옵트인인 이유는 **살아 있는 dispatcher가 없다는 사실을 원장이 확인할 수 없기 때문이다.** 그건 운영자가 아는 것이지 코드가 아는 것이 아니다.

## 회귀

`tests/test_redteam_round2.py` 15개. 각 테스트는 이 문서 이전 코드에서 실패한다. 전체 288개 통과.

## 다음 표적

- `record_outcome`의 evidence는 검증되지 않는다 — 신뢰 경계 안이지만 명시할 가치가 있다
- 단일 프로세스 다중 스레드에서 `dispatcher_id`가 같으므로, 스레드 단위 복구는 여전히 구분하지 못한다
- `events()`는 전량을 메모리에 올린다 — 원장이 커지면 문제

## Finding 7 — the rollback check disarmed itself the first time it fired

Found by mutation rather than by reading: `_observe_clock` was changed to record
the clock reading unconditionally instead of only when it advances, and all 331
tests still passed.

The change is not cosmetic. A high-water mark that follows the clock downward
still refuses the *first* claim under a rolled-back clock, because the
comparison happens before the mark is written — so a suite that checks one claim
sees correct behaviour and reports the mechanism as working. By then the refused
reading has replaced the mark, and every later claim compares against the
lowered one and is allowed.

That is the worst shape available for a safety check: the log shows a rollback
detected, and the next lease goes through.

The code was already correct. What was missing was any test that a *second*
claim is also refused — the suite checked that the alarm sounds, never that it
is still armed afterwards. Three tests now pin it: the second claim, a
three-deep retry loop, and the opposite direction (a mark that stops advancing
would refuse every honest reading a moment later).

**Method note.** Thirteen deliberate breakages were applied across the five
repositories; twelve were caught. A negative control was run first — harmless
whitespace edits to the same files, confirming the probe was not simply
failing for unrelated reasons. Without that control the twelve passes would
have proved nothing.

## Finding 8 — 경로 traversal 검사가 발동할 수 없었다

커버리지로 훑었더니 `canonical.py` 85%, `scope.py` 88%였고 **실행되지 않는 줄이
거의 전부 거부 분기**였다. 입력 정규화와 스코프가 막는다고 적어둔 것들이 한 번도
발동한 적이 없었다. 전부 쏴봤고 **하나가 통과했다.**

```python
resolved = candidate.resolve()
if ".." in PurePosixPath(str(resolved)).parts:
    raise ScopeError("path escapes through traversal components")
```

`.resolve()`가 `..`를 **이미 접어 없앤 뒤에** `..`를 찾는다. `/tmp/../etc/passwd`는
`/etc/passwd`로 접히고 `parts`에 `..`가 남지 않는다. **어떤 입력으로도 발동할 수 없는
검사**였고, 메시지는 traversal을 거부한다고 말하고 있었다.

실질적 영향은 좁다 — 해석된 경로가 실제 inode에 고정되므로 결속 자체는 정직했고,
위험은 `requested` 문자열을 보고 판단하는 소비자에게 있다. 그러나 **검사가 있다고
적혀 있는데 없었다**는 것이 문제다. 활성 검사처럼 보이는 죽은 코드는 없는 검사보다
나쁘다: 없으면 사람이 조심하고, 있으면 보호받고 있다고 믿는다.

형제 저장소 `mcp-gateway`는 처음부터 원시 요청에서 `..`를 거부하고 그 이유까지
주석에 적혀 있다("해석하면 서버가 나중에 하는 것과 어긋난다"). **같은 규칙을 두 곳에
다르게 구현했고 한쪽만 동작했다.**

이제 원시 입력을 본다. `..foo`처럼 점으로 시작하는 이름은 통과한다 — 문자열에 `..`가
들어있다는 이유로 막으면 정상 경로가 막히고, 그런 검사는 꺼진다.

`tests/test_rejections.py`가 26개로 고정한다. 옛 코드로 되돌리면 4개가 실패한다.

**방법 기록.** 이 결함은 코드를 읽어서가 아니라 **커버리지가 그 줄을 한 번도
실행하지 않았다고 알려줘서** 나왔다. 그 줄을 발동시키려다 발동시킬 수 없다는 것을
알았다. 미실행 거부 분기는 목록으로 만들어 하나씩 쏴볼 가치가 있다.
