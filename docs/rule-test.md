# 국내 Gitleaks 규칙별 검증 결과

[이슈 #17](https://github.com/kwon051/CommitGuard/issues/17) · 검증일 2026-11-22 · Gitleaks v8.30.1

국내 규칙 4종마다 탐지 대상 10개와 비탐지 대상 10개를 만들어 기본 규칙 샘플과 같은 임시 Git 저장소에서 검사했다. 정탐은 탐지 대상에서 예상한 규칙이 나온 건수, 미탐은 해당 규칙이 나오지 않은 건수다. 오탐은 비탐지 대상에서 해당 규칙이 나온 건수다. 각 파일에 다른 국내 규칙이 추가로 잡히는지도 검사했다.

| 규칙 | 탐지 대상 | 비탐지 대상 | 정탐 | 미탐 | 오탐 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `kr-rrn` | 10 | 10 | 10 | 0 | 0 |
| `kr-mobile` | 10 | 10 | 10 | 0 | 0 |
| `kr-student-id` | 10 | 10 | 10 | 0 | 0 |
| `kr-service-api-key` | 10 | 10 | 10 | 0 | 0 |
| **합계** | **40** | **40** | **40** | **0** | **0** |

- 주민등록번호는 날짜와 하이픈, 휴대폰은 국내·국제 표기와 국번·구분자를 검증했다.
- 학번은 변수 이름과 연도·자릿수 범위, 국내 서비스 API 키는 서비스별 표기와 환경 변수 참조·키 길이·entropy·자리표시자를 검증했다.
- 결과표는 [테스트 코드](../tests/test_rules.py)의 합성 예시 80개를 기준으로 한다. [실제 검사에 적용되는 규칙 범위와 한계](kr-rules.md#한계와-다음-작업)는 별도로 정리되어 있다.

## 재현 방법

저장소 루트에서 Gitleaks v8.30.1과 pytest로 실행한다.

```bash
REQUIRE_GITLEAKS=1 python -m pytest tests/test_rules.py -q
```

결과표에 집계한 80개와 기본 규칙·경계 조건·allowlist 검사를 포함해 **97개**가 통과했다. 아래처럼 결과 경로를 지정하면 기본·국내 규칙을 합친 원본 JSON과 공통 형식 JSON을 출력한다. 공통 형식에는 기본 규칙 6건과 국내 규칙 40건이 들어간다.

```bash
report_dir=$(mktemp -d)
REQUIRE_GITLEAKS=1 python -m pytest tests/test_rules.py -q --gitleaks-report-dir "$report_dir"
ls "$report_dir"
```

저장소의 `samples/`에는 [기존 시연용 통합 결과](kr-rules.md#공유용-결과-파일)가 있다.
