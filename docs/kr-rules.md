# 국내 비밀정보 탐지 규칙 4종

관련 업무: [#16](https://github.com/kwon051/CommitGuard/issues/16) · 담당: 임두연 · 검증일: 2026-11-15

`worker/gitleaks.toml`은 `[extend] useDefault = true`로 Gitleaks 기본 규칙을 유지하고 국내 규칙 4종을 추가한다. 실제 개인정보나 발급된 키는 테스트에 사용하지 않는다. 테스트 값은 실행 시에만 조립한다.

## 규칙과 범위

| rule_id | 탐지 범위 | 위험도 |
| --- | --- | --- |
| `kr-rrn` | 하이픈이 있는 주민번호 형식. 월별 일수·윤년 검사. 뒤 첫 자리 1·2는 1900년대, 3·4는 2000년대로 해석 | CRITICAL |
| `kr-mobile` | `010` 또는 `+82 10`, 가운데 네 자리가 2~9로 시작. 하이픈·점·공백 또는 구분자 없음 | HIGH |
| `kr-student-id` | `학번`, `hakbun`, `student_id`, `STUID`, `STUNO` 등 이름 뒤의 2000~2039년으로 시작하는 8~10자리 숫자 | MEDIUM |
| `kr-service-api-key` | 카카오·네이버·네이버 클라우드(NCP) 관련 변수와 공공데이터포털 `serviceKey=` 값. 허용 문자 10~150자, entropy 3.0 이상 | HIGH |

주민번호는 검증번호 불일치를 이유로 제외하지 않는다. 날짜와 형식 검사는 실제 발급 여부나 개인정보의 진위를 증명하지 않는다.

예외는 제한적으로 적용한다. 주민번호는 특정 교재용 예시 한 건만, 휴대폰은 특정 반복 예시 한 건만 제외한다. 뒷자리 패턴이 같거나 전화번호가 `0000`으로 끝난다는 이유로 모두 제외하지 않는다. API 키는 자리표시자(`your`, `example`, `dummy` 등)가 들어간 값을 제외한다.

## 검증 결과

Gitleaks **8.30.1**로 원래의 규칙별 탐지 대상 5개·비탐지 대상 5개를 실제 검사했다. 이 수치는 아래 합성 예시에 대한 결과이며 일반 저장소 전체의 정확도를 의미하지 않는다.

| 규칙 | 탐지 대상에서 탐지 | 비탐지 대상에서 탐지 |
| --- | --- | --- |
| `kr-rrn` | 5 / 5 | 0 / 5 |
| `kr-mobile` | 5 / 5 | 0 / 5 |
| `kr-student-id` | 5 / 5 | 0 / 5 |
| `kr-service-api-key` | 5 / 5 | 0 / 5 |

추가한 경계 예시 12개도 통과했다. 2월 31일·4월 31일·평년의 2월 29일을 제외하고, 1900/2000년의 윤년 차이를 구분한다. 과도한 allowlist로 제외되던 번호, 구분자 없는 학번 변수 이름, NCP Access/Secret 키도 확인한다.

- allowlist 세 종류는 예외를 제거하면 잡히고 적용하면 제외됨을 테스트한다.
- 기본 규칙도 계속 탐지한다. 기존 샘플의 finding 6건과 fingerprint를 유지하면서 국내 규칙 20건을 같은 결과에 추가했다.
- worker의 실제 Git 검사에서 개인정보 마스킹과 원본 `Fingerprint` 보존을 확인한다.
- 검사 대상에 별도 `.gitleaks.toml`이 있어도 기본 호출은 worker 설정을 사용한다. 명시적인 `config_path`/`--config` 지정도 유지한다.
- 전체 테스트: **103 passed, 1 skipped, 3 subtests passed**. 건너뛴 항목은 로컬 Trivy 실행 파일이 필요한 기존 Trivy 통합 테스트다. Gitleaks 통합 테스트는 실행했다.
- worker Docker 이미지 빌드 성공. 컨테이너의 `/app/gitleaks.toml`로 국내 규칙 4종의 실제 Git 검사·변환·마스킹·fingerprint 보존을 확인했다.
- 현재 파일을 `gitleaks dir`로 검사한 결과 0건. 이는 과거 Git 이력까지 0건이라는 의미는 아니다.

## 공유용 결과 파일

기존 기본 규칙 샘플에 국내 규칙 예시 40개(탐지 대상 20개, 비탐지 대상 20개)를 추가한 Git 저장소를 만들고, 전체 Git 이력을 한 번 검사한 결과를 저장소에 보관한다. 국내 규칙 전용 JSON을 따로 만들지 않는다.

| 파일 | 내용 |
| --- | --- |
| `samples/gitleaks-raw.json` | 비밀값을 가린 원본 27건: 기본 규칙 6건 + 국내 규칙 21건. 동일 fingerprint의 중복 1건 포함 |
| `samples/gitleaks-findings.json` | 공통 형식 26건: 기본 규칙 6건 + 국내 규칙별 5건씩 20건. fingerprint 기준 중복 제거 |

비탐지 예시에는 탐지 결과가 없으므로 JSON에 항목이 생기지 않는다. 추가 경계·allowlist 테스트의 임시 결과는 포함하지 않는다. 원본과 공통 형식은 구조가 달라 두 파일로 유지한다. 현재 결과 화면도 이 공통 형식 파일을 읽으므로 기본·국내 규칙을 함께 보여 준다.

`gitleaks git`으로 검사한 결과라 `File`은 저장소 안의 상대 경로이며 `Commit`·`Author`·`Date`를 포함한다. `Fingerprint`는 Gitleaks가 생성한 값을 그대로 유지한다. 기존 5개 커밋 뒤에 국내 예시를 넣은 커밋을 추가하므로 기존 기본 규칙의 fingerprint도 유지된다. 기본 예시는 `scripts/make_sample_repo.py`, 국내 예시는 `tests/test_rules.py`의 `CASES`에서 재생성한다. 개인정보의 식별 숫자는 전부 가리고 API 키는 기존 공통 형식처럼 앞 최대 4자리만 남긴다.

저장소 루트에서 다음 명령으로 공유용 결과를 재생성한다.

```bash
REQUIRE_GITLEAKS=1 python -m pytest tests/test_rules.py -v --gitleaks-report-dir samples
```

옵션을 생략하면 테스트는 임시 폴더만 사용한다.

## 실행

저장소 루트에서 실행한다. Python 테스트 환경에 pytest와 기존 프로젝트 의존성이 필요하다.

```bash
gitleaks version  # 8.30.1
REQUIRE_GITLEAKS=1 python -m pytest tests worker/tests -q

# 현재 파일 검사. 테스트용 예시는 실행 시에만 조립한다.
gitleaks dir . --config worker/gitleaks.toml --redact

# 외부 저장소는 로컬로 clone한 경로를 전달한다.
python -m worker.scanners.gitleaks /path/to/cloned-repo \
  --raw /tmp/gitleaks-raw.json --out /tmp/gitleaks-findings.json

docker build -f worker/Dockerfile -t commitguard-worker:kr-rules worker
docker run --rm --entrypoint python \
  -v /absolute/path/to/cloned-repo:/target:ro \
  commitguard-worker:kr-rules -m scanners.gitleaks /target
```

## 전달 사항

- **김기령(기능 3)**: 국내 rule_id 네 개의 위험도·한국어 안내를 기존 변환기에 추가했다. 최신 공통 형식의 `fingerprint`와 fingerprint 기준 중복 제거는 유지했다. 주민번호·전화번호·학번은 식별 숫자를 남기지 않도록 마스킹하며, 이 예외를 `docs/finding-format.md`에도 명시했다.
- **은하(인프라)**: Dockerfile이 `gitleaks.toml`을 `/app/gitleaks.toml`로 복사한다. 기본 호출은 이 설정을 명시적으로 사용한다. 현재 develop에는 Actions 워크플로가 없으므로, 추후 secret-scan에는 `--config worker/gitleaks.toml`을 전달하고 규칙 테스트에는 `REQUIRE_GITLEAKS=1`을 설정한다.

## 한계와 다음 작업

- 하이픈 없는 주민번호, 뒤 첫 자리가 1~4가 아닌 번호는 범위 밖이다.
- 전화번호의 앞자리 범위, 학번의 입학년도·길이는 위 형식으로 제한한다. 학번 이름과 값이 다른 줄에 있는 CSV 등은 놓칠 수 있다.
- 특정 예시를 제외하는 allowlist도 같은 값을 쓰는 실제 데이터를 놓칠 수 있다. API의 자리표시자 부분 문자열 제외도 같은 한계가 있다.
- API 키는 서비스가 드러나는 변수·쿼리 이름과 문자 범위·길이·entropy 조건을 사용한다. 환경 변수 참조는 이 테스트의 예시에서 제외되지만, 모든 언어의 참조 문법을 해석하는 것은 아니다.
- 같은 위치의 중복 원본은 원본 `Fingerprint` 기준으로 합친다. 값이 같은 경우라도 fingerprint가 다르면 서로 다른 finding으로 유지한다.
- 이 작업은 규칙과 검사 모듈 검증이다. 현재 `worker/worker.py`는 시작 메시지를 출력하는 자리표시자여서, 웹 요청→queue→외부 저장소 clone→DB 저장까지의 통합은 별도 작업이다.
- 규칙별 10/10 확장은 [#17](https://github.com/kwon051/CommitGuard/issues/17) 범위다.

설정 형식과 `--config` 우선순위는 [Gitleaks v8.30.1 공식 문서](https://github.com/gitleaks/gitleaks/blob/v8.30.1/README.md#configuration)를 따른다.
