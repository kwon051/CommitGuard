# 워크플로 안내 (GitHub Actions)

PR을 올리거나 develop·main에 push하면 아래 검사가 자동으로 돈다.
PR은 워크플로가 모두 초록색(✅)이어야 머지한다.

| 워크플로 | 하는 일 | 파일 |
|---|---|---|
| lint | 문법 오류, 없는 이름, 안 쓰는 import 검사 (flake8) | `.github/workflows/lint.yml` |
| unit-test | `tests/`, `worker/tests/`의 테스트 실행 (pytest) | `.github/workflows/unit-test.yml` |
| secret-scan | 우리 저장소 Git 이력 전체에 비밀키·개인정보가 있는지 검사 (Gitleaks) | `.github/workflows/secret-scan.yml`, `.gitleaks.toml` |
| image-scan | web·worker 이미지의 알려진 취약점(CVE) 검사 (Trivy) | `.github/workflows/image-scan.yml` |
| compose-test | 컨테이너 4개를 띄워 검사 1건이 web → queue → worker → db까지 도는지 확인 | `.github/workflows/compose-test.yml`, `scripts/compose_test.sh` |

## 실패했을 때 확인하는 법

1. PR 화면 아래 검사 목록에서 빨간 ❌ 옆의 **Details**를 누른다. (또는 저장소의 **Actions** 탭 → 실패한 실행)
2. 왼쪽에서 실패한 작업(flake8 / pytest / gitleaks / trivy / compose)을 누른다.
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

## secret-scan (Gitleaks)

- **검사하는 것**: 마지막 커밋만이 아니라 **Git 이력 전체**. 지운 파일이라도 예전 커밋에 키가 있으면 걸린다.
- **규칙**: worker와 같은 `worker/gitleaks.toml`(기본 규칙 + 국내 규칙 4종)을 `.gitleaks.toml`이 가져다 쓴다.
- **빼는 곳**: 탐지 테스트용 가짜 키가 있는 `tests/`, `worker/tests/`, `samples/`, `scripts/make_*_repo.py`만 뺀다.
- **실패하면**: `gitleaks` 작업 → "Git 이력 전체 검사" 단계에서 `File`, `Line`, `Commit`, `RuleID`를 본다. 값은 `REDACTED`로 가려져 있다.
  1. 진짜 키라면 **먼저 키를 폐기·재발급**한다. 코드에서 지워도 이력에는 남는다.
  2. 테스트용 가짜 값이라면 위의 테스트 폴더로 옮긴다. `.gitleaks.toml`에 빼는 곳을 늘리려면 PR에 이유를 적는다.
- **내 컴퓨터에서**: `gitleaks git . --config .gitleaks.toml --redact --verbose`

## image-scan (Trivy)

- **검사하는 것**: `Dockerfile`(web)과 `worker/Dockerfile`(worker)로 이미지를 만들고, 그 안의 OS 패키지·파이썬 패키지·프로그램에 알려진 취약점이 있는지 본다. web과 worker는 따로 돈다.
- **비밀키는 보지 않는다**: `--scanners vuln`으로 취약점만 본다. 비밀키는 secret-scan이 맡는다.
- **실패 기준**: **CRITICAL(가장 위험한 등급)이 하나라도 있으면 실패**한다. 고칠 버전이 아직 없어도 실패한다. HIGH는 표로 보여 주기만 한다.
- **결과 보는 곳**: PR의 Checks → image-scan → **Summary** 화면 맨 앞에 등급별 건수 표가 나온다(`scripts/trivy_summary.sh`가 만든다). 1건 = 보안 구멍 1개 × 그 구멍이 든 부품 1개.
- **실패하면**: "CRITICAL 검사" 단계의 표에서 `Library`, `Installed Version`, `Fixed Version`을 본다. `Fixed Version`이 있으면 Dockerfile의 기본 이미지나 `requirements.txt`의 버전을 올린다. 비어 있으면(고칠 버전 없음) 기본 이미지를 바꾸거나 그 부품을 빼는 방법을 팀과 정한다.
- **내 컴퓨터에서**:

```bash
docker build -t commitguard-worker:ci ./worker
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock aquasec/trivy:0.76.2 \
  image --scanners vuln --severity CRITICAL --exit-code 1 commitguard-worker:ci
```

## compose-test

- **검사하는 것**: `.env.example`을 `.env`로 복사 → `docker compose up -d --build --wait` → `scripts/compose_test.sh`.
  스크립트는 web에 검사를 요청하고, queue의 상태(`commitguard:scan:status:<작업 번호>`)가 `done`이 될 때까지 5초마다 확인한 뒤, db `findings`에 결과가 있는지 본다.
  처음 검사는 worker의 Trivy가 취약점 DB를 받느라 약 3분 걸린다(러너는 매번 처음). 그래서 안전망은 10분이다.
- **검사 대상**: 공개 저장소인 `https://github.com/kwon051/CommitGuard`. 테스트용 가짜 키가 있어 결과가 1건 이상 나와야 정상이다.
- **실패하면** 메시지로 어디서 멈췄는지 안다.

| 메시지 | 뜻 | 볼 곳 |
|---|---|---|
| `web이 요청을 받지 못했습니다` | web이 안 떴거나 queue에 못 넣음 | "실패 시 컨테이너 로그"의 web |
| `worker가 검사에 실패했습니다: ...` | clone·Gitleaks·Trivy·DB 저장 중 오류 (이유가 함께 나옴) | 바로 아래 worker 로그 |
| `600초 안에 끝나지 않았습니다` | worker가 죽었거나 멈췄거나 요청을 못 꺼냄 | worker 로그, `docker compose ps` |
| `db에 결과가 없습니다` | 검사는 끝났는데 저장이 안 됨 | worker 로그의 "저장 N건" |
| 컨테이너 띄우기 단계에서 실패 | 이미지 빌드 오류이거나 healthcheck 통과 못 함 | 그 단계 로그 |

- **내 컴퓨터에서** (진짜 `.env`가 있으면 덮어쓰지 않게 주의):

```bash
docker compose up -d --build --wait
bash scripts/compose_test.sh
docker compose down          # -v를 붙이면 db 데이터까지 지워진다
```

## 참고

- 줄 길이(120자)·빈 줄 같은 스타일은 lint의 "스타일 참고 목록" 단계에 보이지만 실패시키지 않는다.
- unit-test는 Gitleaks를 설치하고 돈다. Trivy로 실제 검사하는 테스트 1개는 건너뛴다(image-scan 워크플로에서 다룬다).
- 새 테스트 파일은 `tests/` 또는 `worker/tests/`에 `test_*.py` 이름으로 두면 자동으로 실행된다.
