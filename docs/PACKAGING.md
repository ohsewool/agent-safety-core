# 최상위 이름을 차지한다는 것

이 배포판은 최상위 패키지 셋을 설치한다 — `core`, `adapters`, `profiles`.
셋 다 남의 프로젝트에도 흔히 있는 디렉터리 이름이다.

## 고친 것 — `core`가 namespace 패키지였다

`core/__init__.py`가 없어서 `core`는 namespace 패키지였다. namespace 조각은
**경쟁하지 않고 합쳐진다.** 작업 디렉터리에 `core/`가 있으면 같은 패키지에
합류하고, `sys.path` 앞쪽이라 먼저 이긴다.

측정해서 확인했다. `core/ledger.py`에 무조건 승인하는 `ExecutionLedger`를 두고
`from core.ledger import ExecutionLedger`를 했더니 그쪽이 import됐다.
**승인이 강제된다는 것이 존재 이유인 라이브러리에서**, 경고 하나 없이.

`__init__.py`를 넣으면 정규 패키지가 되고, import 시스템은 조각을 합치는 대신
경로에서 처음 만난 정규 패키지에서 멈춘다. 확인:

| | 로컬 `core/ledger.py` | 결과 |
|---|---|---|
| `__init__.py` 없음 | 있음 | **로컬 파일이 import됨** |
| `__init__.py` 있음 | 있음 | 설치된 패키지가 import됨 |

`tests/test_package_resolution.py`가 이걸 고정한다. 하위 프로세스로 돌린다 —
이미 `core`를 import한 세션 안에서 단언하면 아무것도 검사하지 않기 때문이다.

## 남은 것 — `adapters`가 형제 저장소와 겹친다

`adapters`는 원래부터 정규 패키지였고, 그래서 **이 배포판이 설치되면
`document-intelligence`의 저장소 로컬 `adapters/`를 가린다.**
그쪽 README가 안내하는 `from adapters.pdfplumber_adapter import parse_pdf`가
`ModuleNotFoundError`가 된다. 재현:

```
pip install agent-safety-core --target /tmp/asc
cd document-intelligence
PYTHONPATH=/tmp/asc python3 -c "from adapters.pdfplumber_adapter import parse_pdf"
# ModuleNotFoundError: No module named 'adapters.pdfplumber_adapter'
```

이건 `core` 문제를 고치다 생긴 게 아니라 **원래 있던 것**이다. 처음엔 내가 만든
결함으로 오해했는데, git 기록을 보니 `adapters/__init__.py`는 계속 있었다.
(그 오해의 원인도 기록해둔다 — 최상위 패키지를 훑는 스크립트가 틀려서 셋 다
namespace라고 보고했다. 검사기가 틀리면 결론도 틀린다.)

**해소는 `document-intelligence` 쪽에서 한다.** 최상위 이름을 요구하는 쪽이
라이브러리가 아니라 저장소 로컬 디렉터리이고, 그쪽은 `document_intelligence.adapters`
라는 모호하지 않은 경로를 가질 수 있다. 여기서 `adapters`를 개명하면
`benchmark/`와 문서의 참조가 전부 깨지는데, 그건 더 큰 비용이다.
