"""거부 하나하나가 실제로 거부하는가 — 그리고 하나는 아니었다.

커버리지로 훑었더니 `canonical.py` 85%, `scope.py` 88%였고, **실행되지 않는 줄이
거의 전부 거부 분기**였다. 입력 정규화가 막는다고 적어둔 것들 — 과대 payload,
중복 키, 비유한수, 키 과다, 지원하지 않는 타입 — 과 스코프가 막는다고 적어둔
것들이 한 번도 발동한 적이 없었다.

**전부 쏴봤고 하나가 통과했다.**

`resolve_path("/tmp/../etc/passwd")`가 거부되지 않았다. 검사는 이렇게 돼 있었다:

    resolved = candidate.resolve()
    if ".." in PurePosixPath(str(resolved)).parts:
        raise ScopeError("path escapes through traversal components")

`.resolve()`가 `..`를 **이미 접어 없앤 뒤에** `..`를 찾는다. `/tmp/../etc/passwd`는
`/etc/passwd`로 접히고 `parts`에 `..`가 남지 않는다. 어떤 입력으로도 발동할 수 없는
검사였고, 메시지는 "traversal을 거부한다"고 말하고 있었다.

**활성 검사처럼 보이는 죽은 코드는 없는 검사보다 나쁘다.** 없으면 사람이 알아서
조심하지만, 있으면 보호받고 있다고 믿는다.

형제 저장소 `mcp-gateway`의 정책은 처음부터 원시 요청에서 `..`를 거부하고, 그
이유까지 주석에 적혀 있다("해석하면 서버가 나중에 하는 것과 어긋난다"). 같은
규칙을 두 곳에서 다르게 구현했고 한쪽만 동작했다.

실질적 영향은 좁다. 해석된 경로가 실제 inode에 고정되므로 결속 자체는 정직했다.
위험은 `requested` 문자열을 보고 판단하는 소비자에게 있고, 무엇보다 **검사가
있다고 적혀 있는데 없었다**는 것이 문제다.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.canonical import (  # noqa: E402
    MAX_KEYS,
    MAX_STRING,
    CanonicalizationError,
    loads,
    normalize,
)
from core.scope import ScopeError, resolve_opaque, resolve_path, resolve_url  # noqa: E402


class TestPathTraversalIsActuallyRefused:
    """고친 것. 이 클래스 전체가 예전에는 통과하지 않았다."""

    @pytest.mark.parametrize("raw", [
        "/tmp/../etc/passwd",
        "/a/b/../../c",
        "/tmp/..",
        "/tmp/./../x",
    ])
    def test_a_path_with_traversal_components_is_refused(self, raw):
        with pytest.raises(ScopeError, match="traversal"):
            resolve_path(raw)

    def test_a_name_that_merely_starts_with_dots_is_not_traversal(self):
        """`..foo`는 상위 이동이 아니라 그냥 이름이다. 문자열에 `..`가 들어있다는
        이유로 막으면 정상 경로가 막히고, 그런 검사는 꺼진다."""
        assert resolve_path("/tmp/..foo").kind == "path"

    def test_ordinary_absolute_paths_still_resolve(self):
        """거부만 확인하면 전부 거부하는 구현도 통과한다."""
        for raw in ("/tmp", "/etc/passwd", "/usr/lib"):
            assert resolve_path(raw).kind == "path"

    def test_the_check_reads_the_raw_input_not_the_resolved_one(self):
        """결함의 정체를 그대로 고정한다. 해석 뒤에 보면 `..`가 남지 않는다."""
        from pathlib import Path as _Path, PurePosixPath

        assert ".." not in PurePosixPath(str(_Path("/tmp/../etc/passwd").resolve())).parts


class TestScopeRefusesWhatItCannotBind:
    @pytest.mark.parametrize("raw", ["", None])
    def test_an_empty_path_is_refused(self, raw):
        with pytest.raises(ScopeError, match="non-empty string"):
            resolve_path(raw)

    def test_a_relative_path_is_refused(self):
        """상대 경로의 뜻은 cwd에 달려 있고, 승인은 cwd를 모른다."""
        with pytest.raises(ScopeError, match="relative paths"):
            resolve_path("tmp/thing")

    def test_an_empty_url_is_refused(self):
        with pytest.raises(ScopeError, match="url resource requires"):
            resolve_url("")

    def test_an_empty_opaque_identifier_is_refused(self):
        with pytest.raises(ScopeError, match="requires an identifier"):
            resolve_opaque("thing", "")


class TestCanonicalizationRefusesMalformedInput:
    """정규화는 모든 해시의 입구다. 여기서 받아들인 것은 이후 전부가 받아들인다."""

    def test_an_oversized_payload_is_refused(self):
        with pytest.raises(CanonicalizationError, match="maximum accepted size"):
            loads("0" * (10 * 1024 * 1024 + 1))

    def test_text_that_is_not_json_is_refused(self):
        with pytest.raises(CanonicalizationError, match="not valid JSON"):
            loads("{not json")

    def test_a_duplicate_key_is_refused(self):
        """JSON은 중복 키를 허용하고 파서마다 다르게 고른다. 어느 쪽을 고르든
        해시가 갈리므로, 고르지 않고 거부한다."""
        with pytest.raises(CanonicalizationError, match="duplicate JSON key"):
            loads('{"a": 1, "a": 2}')

    @pytest.mark.parametrize("constant", ["NaN", "Infinity", "-Infinity"])
    def test_a_non_finite_constant_is_refused(self, constant):
        """JSON 표준에 없는 값이고, 동등 비교가 자기 자신과도 실패한다."""
        with pytest.raises(CanonicalizationError, match="non-finite"):
            loads(f'{{"a": {constant}}}')

    def test_an_oversized_string_is_refused(self):
        with pytest.raises(CanonicalizationError, match="maximum accepted length"):
            normalize("x" * (MAX_STRING + 1))

    def test_too_many_keys_is_refused(self):
        with pytest.raises(CanonicalizationError, match="more than"):
            normalize({str(index): index for index in range(MAX_KEYS + 1)})

    def test_a_non_string_key_is_refused(self):
        with pytest.raises(CanonicalizationError, match="keys must be strings"):
            normalize({1: "a"})

    def test_too_many_array_items_is_refused(self):
        with pytest.raises(CanonicalizationError, match="more than"):
            normalize(list(range(MAX_KEYS + 1)))

    def test_an_unsupported_type_is_refused(self):
        with pytest.raises(CanonicalizationError, match="unsupported type"):
            normalize({"a": object()})


class TestCanonicalizationStillAcceptsWhatItShould:
    def test_ordinary_values_normalize(self):
        assert normalize({"b": 1, "a": "가"}) == {"b": 1, "a": "가"}

    def test_a_value_at_the_limit_is_accepted(self):
        """경계에서 거부하면 한도가 문서보다 하나 작다."""
        assert normalize("x" * MAX_STRING)
        assert normalize(list(range(MAX_KEYS)))

    def test_valid_json_round_trips(self):
        assert loads('{"a": [1, 2], "b": null}') == {"a": [1, 2], "b": None}
