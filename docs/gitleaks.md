# 기능 1: Gitleaks 검사 모듈

가짜 키가 든 샘플 저장소를 Gitleaks로 검사하고, 결과를 공통 형식 v1(`docs/finding-format.md`)으로 바꾼다.

## 파일

| 파일 | 내용 |
| --- | --- |
| `scripts/make_sample_repo.py` | 기본 규칙용 가짜 키가 든 테스트 저장소를 만든다 (커밋 5개, 키를 지운 커밋 포함) |
| `tests/test_rules.py` | 위 저장소에 국내 예시 40개를 커밋해 기본·국내 규칙을 함께 검사. 옵션으로 공유용 JSON 재생성 |
| `samples/gitleaks-raw.json` | 기본·국내 규칙 원본 27건. 개인정보는 식별 숫자를 전부 가리고 API 키는 앞 최대 4자리만 남김 |
| `samples/gitleaks-findings.json` | 공통 형식 26건(기본 6 + 국내 20). 원본 `Fingerprint`를 그대로 전달하며 중복 1건 제거 |
| `worker/scanners/gitleaks.py` | 실행 + 가리기 + 공통 형식 변환. worker는 `scan(저장소경로)`만 호출 |
| `worker/tests/test_gitleaks.py` | 변환·마스킹·fingerprint 및 실제 Git 검사 테스트 |
| `worker/Dockerfile` | Gitleaks v8.30.1·국내 규칙 설정·Trivy와 검사 모듈을 담은 worker 이미지 |

## 실행

```bash
# 기본·국내 규칙을 함께 검사하고 공유용 JSON 두 파일을 재생성
REQUIRE_GITLEAKS=1 python -m pytest tests/test_rules.py -v --gitleaks-report-dir samples
python -m pytest worker/tests -q

# 외부 저장소는 clone한 로컬 경로를 전달
python -m worker.scanners.gitleaks /path/to/cloned-repo \
  --raw /tmp/gitleaks-raw.json --out /tmp/gitleaks-findings.json
```

## Docker에서 검증

저장소 루트에서 실행한다. 아래 명령은 기본 규칙 샘플을 별도로 검사한다. 국내 규칙까지 포함한 공유용 결과는 위 pytest 명령으로 재생성한다. `scripts/make_sample_repo.py`는 대상 폴더가 이미 있으면 삭제한 뒤 다시 만든다.

```bash
python scripts/make_sample_repo.py
docker build -f worker/Dockerfile -t commitguard-gitleaks:feature1 worker
RESULT_DIR=$(mktemp -d)
docker run --rm --entrypoint python \
  --mount type=bind,source="$PWD/samples/leaky-repo",target=/scan,readonly \
  --mount type=bind,source="$RESULT_DIR",target=/result \
  commitguard-gitleaks:feature1 -m scanners.gitleaks /scan \
  --raw /result/gitleaks-raw.json \
  --out /result/gitleaks-findings.json
echo "$RESULT_DIR"
```

위 명령은 worker 이미지에서 Gitleaks 검사 모듈을 직접 실행한다. 기본 실행 대상인 `worker.py`는 현재 시작 메시지만 출력하므로 queue 소비와 DB 저장까지의 통합은 별도 작업이다.

## 샘플 저장소에서 잡히는 것

| 규칙 | 파일 | 확인하는 점 |
| --- | --- | --- |
| aws-access-token, generic-api-key | config/settings.py | 다음 커밋에서 지웠지만 Git 이력에서 잡힘 |
| github-pat, generic-api-key | .env | .env 커밋, 변수 이름(DB_PASSWORD) 표시 |
| slack-bot-token | notify/slack.py | 일반 토큰 |
| private-key | deploy/id_rsa | 개인 키는 전부 가림 |
| kr-rrn, kr-mobile, kr-student-id, kr-service-api-key | kr/*_hit_*.txt | 국내 규칙별 5건씩 탐지. 상세 범위는 `docs/kr-rules.md` 참고 |
| (잡히면 안 됨) | kr/*_miss_*.txt | 국내 규칙별 비탐지 예시 5건씩 제외 |
| (잡히면 안 됨) | docs/aws-example.md | AWS 문서 예시 키 오탐 없음 |
| (잡히면 안 됨) | app.py | os.environ으로 읽는 올바른 코드 |

## 키 값 보호

- Gitleaks를 `--redact=80`으로 실행해 키 전체가 임시 파일에도 남지 않는다.
- 저장·전달하는 원본 JSON은 `Secret`·`Match`를 다시 `앞 최대 4자리 + ****`로 바꾼다. 개인 키와 국내 개인정보의 식별 숫자는 전부 가린다.
- 가짜 키는 스크립트가 실행할 때 만든다. 이 저장소의 어떤 파일에도 키 문자열이 없어서 secret-scan Workflow와 GitHub push protection에 걸리지 않는다.

## 넘겨받는 사람에게

- 김기령(기능 3): `fingerprint`는 Gitleaks 원본의 `Fingerprint`를 변경 없이 전달한다. `rule_id`는 Gitleaks 규칙 이름 그대로다. 공통 형식 예시의 `aws-access-key`는 실제로는 `aws-access-token`이다. 원본에 있는 `Commit`·`Author`·`Date`는 담당자 표시에 쓸 수 있도록 남겨 두었다.
- 은하(인프라): worker 이미지에 Gitleaks·Trivy 실행 파일과 `gitleaks.toml` 복사가 반영되어 있다. queue 처리와 통합할 때도 이 설정 파일을 사용하는 검사 모듈을 호출한다.
