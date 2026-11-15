# 기능 2: Trivy 검사 모듈

오래된 패키지가 든 샘플 저장소를 Trivy로 검사하고, 결과를 공통 형식 v1(`docs/finding-format.md`)으로 바꾼다.

## 파일

| 파일 | 내용 |
| --- | --- |
| `samples/vuln-repo/requirements.txt` | 일부러 오래된 버전을 적은 패키지 목록 (테스트용, 실제 프로젝트 의존성 아님) |
| `samples/trivy-raw.json` | Trivy 원본 결과 30건 |
| `samples/trivy-findings.json` | 위 결과를 공통 형식으로 바꾼 것 |
| `samples/trivy-upgrades.json` | 위 결과를 패키지별로 묶은 업그레이드 정리 |
| `worker/scanners/trivy.py` | 실행 + 공통 형식 변환 + 업그레이드 정리. worker는 `scan(저장소경로)`만 호출 |
| `worker/tests/test_trivy.py` | 변환·정리 테스트 17개 + 통합 테스트 1개(trivy 설치 시) |

## fingerprint 규칙

`trivy:CVE번호:패키지명:파일` (finding-format.md 기준)

- 파일은 검사한 저장소 최상위 기준 경로다. `samples/vuln-repo`를 저장소로 보고 검사하므로 `requirements.txt`로 잡힌다.
- 같은 CVE라도 패키지나 파일이 다르면 다른 결과로 본다.

## 실행

PC에 Trivy가 없어도 되도록 공식 Docker 이미지로 원본을 만들고, 변환은 Python으로 한다. 저장소 루트에서 실행한다.

```bash
# 0) 검사 대상 샘플 저장소 만들기 (.gitignore라 저장소에 없음)
python scripts/make_vuln_repo.py

# 1) 원본 JSON 만들기
docker run --rm -v "$PWD:/src" -v trivy-cache:/root/.cache/ aquasec/trivy \
  fs --scanners vuln --format json -o /src/samples/trivy-raw.json /src/samples/vuln-repo

# 2) 공통 형식으로 변환
cd worker
python -m scanners.trivy --from-raw ../samples/trivy-raw.json --out ../samples/trivy-findings.json
cd ..

# 3) 테스트
python -m pytest worker/tests -q
```

Windows PowerShell에서는 `"$PWD:/src"` 대신 `"${PWD}:/src"`를 쓴다. 경로에 공백이 있어도 깨지지 않는다.

trivy가 설치된 환경(worker 이미지)에서는 한 번에 검사와 변환을 할 수 있다.

```bash
python -m scanners.trivy <저장소경로> --raw raw.json --out findings.json
```

## 샘플 저장소에서 잡히는 것

| 패키지 | 현재 버전 | 취약점 수 | 최고 위험도 |
| --- | --- | --- | --- |
| urllib3 | 1.24.1 | 13 | HIGH |
| jinja2 | 2.10 | 6 | HIGH |
| requests | 2.19.0 | 5 | HIGH |
| flask | 0.12.2 | 4 | HIGH |
| pyyaml | 5.3 | 2 | CRITICAL |

취약점 DB는 계속 갱신되므로, 원본을 다시 만들면 개수가 달라질 수 있다.

## 참고

- Trivy 취약점 결과에는 줄 번호가 없어서 `line`은 항상 `null`이다.
- `FixedVersion`이 `2.3.2, 2.2.5`처럼 여러 개면 가장 높은 버전을 `fix`에 적는다. 낮은 쪽을 적으면 그 사이 버전(예: 2.3.0)이 안전한 것처럼 보이기 때문이다.
- 고쳐진 버전이 없는 취약점은 `fix`에 "아직 고쳐진 버전이 없습니다"라고 적는다.
- `title`·`why`·`fix`의 한국어 문장은 임시다. 기능 3의 취약 패키지 안내 템플릿(11/22)으로 바뀔 수 있다.
- 비밀키 검사는 Gitleaks 담당이므로 `--scanners vuln`으로 취약점만 검사한다.

## 업그레이드 정리

같은 패키지의 취약점을 묶어 "X를 Y 버전으로 올리면 N개 해결" 형태로 정리한다 (`summarize_upgrades()`).

```bash
cd worker
python -m scanners.trivy --from-raw ../samples/trivy-raw.json --upgrades ../samples/trivy-upgrades.json
```

| 필드 | 설명 |
| --- | --- |
| package | 패키지명 |
| current_version | 현재 버전 |
| recommended_version | 추천 버전 (고친 버전 중 가장 높은 것, 없으면 null) |
| fixed_count | 추천 버전으로 올리면 해결되는 취약점 수 |
| max_severity | 묶인 취약점 중 가장 높은 위험도 |
| file | 패키지가 적힌 파일 |
| cves | 해결되는 CVE 목록 (finding의 rule_id와 연결할 때 사용) |
| unfixed_count | 고쳐진 버전이 없어 업그레이드로 해결 안 되는 취약점 수 |
| unfixed_cves | 업그레이드해도 남는 CVE 목록 (위험도 높은 순, 요약에는 3개까지 표시) |
| prerelease | 추천 버전이 rc·beta 같은 출시 전 버전이면 true |
| major_upgrade | 앞자리 버전이 바뀌면 true (예: 0.12.2 → 3.1.3, 코드 수정이 필요할 수 있음) |
| summary | 화면에 바로 쓸 한 줄 요약 |

- 추천 버전은 묶인 취약점들의 고친 버전 중 가장 높은 것이다. 그래야 한 번 올려서 전부 해결된다.
- 정렬: 위험도 높은 순 → 해결 수 많은 순
- 예시 결과: `samples/trivy-upgrades.json`

## Docker에서 실행

저장소 루트에서 실행한다. worker 이미지에는 Trivy가 들어 있으므로 실제 검사부터 업그레이드 정리까지 한 번에 확인할 수 있다. 처음 실행할 때는 취약점 DB를 받느라 몇 분 걸리고, 이후에는 `trivy-cache` 볼륨을 재사용한다.

```bash
python scripts/make_vuln_repo.py
docker build -f worker/Dockerfile -t commitguard-worker:feature2 worker
RESULT_DIR=$(mktemp -d)
docker run --rm --entrypoint python \
  -v trivy-cache:/root/.cache/trivy \
  --mount "type=bind,source=$PWD/samples/vuln-repo,target=/scan,readonly" \
  --mount "type=bind,source=$RESULT_DIR,target=/result" \
  commitguard-worker:feature2 -m scanners.trivy /scan \
  --raw /result/trivy-raw.json \
  --out /result/trivy-findings.json \
  --upgrades /result/trivy-upgrades.json
echo "$RESULT_DIR"
```

위 명령은 worker 이미지에서 Trivy 검사 모듈을 직접 실행한다. 기본 실행 대상인 `worker.py`는 현재 시작 메시지만 출력하므로, queue 소비와 DB 저장까지의 통합은 별도 작업이다. `summarize_upgrades()`도 아직 worker 흐름(`scan()`)에는 연결되어 있지 않다.