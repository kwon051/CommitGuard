# 워크플로 안내 (GitHub Actions)

PR을 올리거나 develop·main에 push하면 아래 검사가 자동으로 돈다.
PR은 워크플로가 모두 초록색(✅)이어야 머지한다.

| 워크플로 | 하는 일 | 파일 |
|---|---|---|
| lint | 문법 오류, 없는 이름, 안 쓰는 import 검사 (flake8) | `.github/workflows/lint.yml` |
| unit-test | `tests/`, `worker/tests/`의 테스트 실행 (pytest) | `.github/workflows/unit-test.yml` |

## 실패했을 때 확인하는 법

1. PR 화면 아래 검사 목록에서 빨간 ❌ 옆의 **Details**를 누른다. (또는 저장소의 **Actions** 탭 → 실패한 실행)
2. 왼쪽에서 실패한 작업(flake8 / pytest)을 누른다.
3. 빨간 ❌가 붙은 단계를 펼치면 오류 내용이 보인다.
4. 고쳐서 같은 브랜치에 다시 push하면 검사가 자동으로 다시 돈다.

## 올리기 전에 내 컴퓨터에서 먼저 돌려 보기

저장소 맨 위 폴더에서 실행한다.

```bash
pip install flake8 pytest -r requirements.txt
flake8 . --select=E9,F --show-source      # lint와 같은 검사
python -m pytest tests worker/tests -v    # unit-test와 같은 검사
```

## 자주 나오는 오류

| 오류 메시지 | 뜻 | 고치는 법 |
|---|---|---|
| `F401 'x' imported but unused` | import만 하고 안 씀 | 그 import 줄을 지운다 |
| `F821 undefined name 'x'` | 없는 이름을 씀 (오타) | 이름을 고치거나 import를 추가한다 |
| `F841 local variable 'x' is assigned to but never used` | 변수를 만들고 안 씀 | 변수를 지우거나 사용한다 |
| `E999 SyntaxError` | 문법 오류 | 표시된 줄의 괄호·따옴표·들여쓰기를 확인한다 |
| `ModuleNotFoundError: No module named 'x'` | 테스트에 필요한 패키지가 없음 | `requirements.txt`에 추가한다 |
| `AssertionError` | 테스트 기대값과 실제 값이 다름 | 로그의 `assert` 줄에서 두 값을 비교해 코드를 고친다 |

## 참고

- 줄 길이(120자)·빈 줄 같은 스타일은 lint의 "스타일 참고 목록" 단계에 보이지만 실패시키지 않는다.
- unit-test는 Gitleaks를 설치하고 돈다. Trivy로 실제 검사하는 테스트 1개는 건너뛴다(image-scan 워크플로에서 다룬다).
- 새 테스트 파일은 `tests/` 또는 `worker/tests/`에 `test_*.py` 이름으로 두면 자동으로 실행된다.
