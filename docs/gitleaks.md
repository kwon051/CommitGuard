# 기능 1: Gitleaks 검사 모듈

가짜 키가 든 샘플 저장소를 Gitleaks로 검사하고, 결과를 공통 형식 v1(`docs/finding-format.md`)으로 바꾼다.

## 파일

| 파일 | 내용 |
| --- | --- |
| `scripts/make_sample_repo.py` | 가짜 키가 든 테스트 저장소를 `samples/leaky-repo`에 만든다 (커밋 5개, 키를 지운 커밋 포함) |
| `samples/gitleaks-raw.json` | Gitleaks 원본 결과 6건. 키 값은 앞 4자리만 남기고 가림 |
| `samples/gitleaks-findings.json` | 위 결과를 공통 형식으로 바꾼 것. 원본의 `Fingerprint`를 `fingerprint`에 그대로 담음 |
| `worker/scanners/gitleaks.py` | 실행 + 가리기 + 공통 형식 변환. worker는 `scan(저장소경로)`만 호출 |
| `worker/tests/test_gitleaks.py` | 변환 테스트 11개 + 통합 테스트 1개(gitleaks 설치 시) |
| `worker/Dockerfile` | Gitleaks v8.30.1과 검사 모듈을 담은 단독 검증 이미지 |

## 실행

```bash
python scripts/make_sample_repo.py
cd worker
python -m scanners.gitleaks ../samples/leaky-repo --raw ../samples/gitleaks-raw.json --out ../samples/gitleaks-findings.json
cd ..
python -m pytest worker/tests -q
```

## Docker에서 검증

저장소 루트에서 실행한다. `scripts/make_sample_repo.py`는 대상 폴더가 이미 있으면 삭제한 뒤 다시 만든다.

```bash
python scripts/make_sample_repo.py
docker build -f worker/Dockerfile -t commitguard-gitleaks:feature1 worker
RESULT_DIR=$(mktemp -d)
docker run --rm \
  --mount type=bind,source="$PWD/samples/leaky-repo",target=/scan,readonly \
  --mount type=bind,source="$RESULT_DIR",target=/result \
  commitguard-gitleaks:feature1 /scan \
  --raw /result/gitleaks-raw.json \
  --out /result/gitleaks-findings.json
echo "$RESULT_DIR"
```

이 이미지는 Gitleaks 검사 모듈을 직접 실행한다. 그림의 `queue` 요청을 소비하는 공용 worker 코드와 Trivy는 이 폴더에 아직 없으므로, 해당 서비스의 Dockerfile에 Gitleaks 이미지 단계, `git` 설치, 실행 파일 복사를 합쳐야 한다.

## 샘플 저장소에서 잡히는 것

| 규칙 | 파일 | 확인하는 점 |
| --- | --- | --- |
| aws-access-token, generic-api-key | config/settings.py | 다음 커밋에서 지웠지만 Git 이력에서 잡힘 |
| github-pat, generic-api-key | .env | .env 커밋, 변수 이름(DB_PASSWORD) 표시 |
| slack-bot-token | notify/slack.py | 일반 토큰 |
| private-key | deploy/id_rsa | 개인 키는 전부 가림 |
| (잡히면 안 됨) | docs/aws-example.md | AWS 문서 예시 키 오탐 없음 |
| (잡히면 안 됨) | app.py | os.environ으로 읽는 올바른 코드 |

## 키 값 보호

- Gitleaks를 `--redact=80`으로 실행해 키 전체가 임시 파일에도 남지 않는다.
- 저장·전달하는 원본 JSON은 `Secret`·`Match`를 다시 `앞 4자리 + ****`로 바꾼다. 개인 키는 전부 가린다.
- 가짜 키는 스크립트가 실행할 때 만든다. 이 저장소의 어떤 파일에도 키 문자열이 없어서 secret-scan Workflow와 GitHub push protection에 걸리지 않는다.

## 넘겨받는 사람에게

- 김기령(기능 3): `fingerprint`는 Gitleaks 원본의 `Fingerprint`를 변경 없이 전달한다. `rule_id`는 Gitleaks 규칙 이름 그대로다. 공통 형식 예시의 `aws-access-key`는 실제로는 `aws-access-token`이다. 원본에 있는 `Commit`·`Author`·`Date`는 담당자 표시에 쓸 수 있도록 남겨 두었다.
- 은하(인프라): 공용 worker Dockerfile에 Gitleaks 이미지 단계, `git` 설치, 실행 파일 복사를 합친다. 공용 worker의 `CMD`와 Trivy 설치 부분은 유지한다.
