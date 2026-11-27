# Gitleaks 저장소 공개 전환 판정

검사가 완료되면 이번 작업의 Gitleaks 기본 규칙과 국내 규칙 탐지 결과로 판정한다. 탐지 항목이 0건이면 **공개 가능**, 1건 이상이면 **공개 불가**로 표시한다. 현재 파일에서 지운 값도 검사한 Git 이력에 남아 탐지되면 공개를 막는다. Trivy와 가짜 패키지 탐지 결과는 기존 검사 결과에서 확인할 수 있다.

## 웹에서 확인

1. CommitGuard에서 검사할 GitHub 저장소 주소를 제출한다.
2. **검사 완료 후 결과 확인** 링크를 연다. 검사 중이면 완료 후 새로고침한다.
3. **저장소 공개 전환 판정**에서 판정과 차단 항목을 확인한다.

작업 번호가 있는 결과 링크는 해당 검사 1회의 판정을 표시한다. 검사 중이거나 실패했거나 판정 기록이 만료되면 **판정 보류**로 표시한다. 판정은 worker가 가져온 Git 이력과 적용된 Gitleaks 규칙의 범위에서 유효하다. 검사 후에 커밋을 추가하거나 수정했다면 다시 검사한다.

## 로컬 클론 검사

권한이 있는 비공개 저장소도 전체 이력을 포함한 로컬 클론으로 검사할 수 있다. 검사 전에 확인하려는 브랜치와 태그를 최신 상태로 가져온다. Gitleaks가 설치된 환경에서 CommitGuard 저장소 루트 기준으로 실행한다.

```bash
python -m worker.scanners.gitleaks /path/to/local-clone --out findings.json --readiness readiness.json
```

`--readiness`는 판정을 지정 경로에 저장한다. 이력이 잘린 shallow 클론이거나 검사에 실패하면 해당 실행의 판정은 생성되지 않는다.

## 결과 계약

worker는 검사 결과를 DB에 저장한 뒤 작업 상태를 `done`으로 바꾸고, Valkey의 `commitguard:scan:status:<job_id>` 문서에 `public_readiness` 객체를 추가한다. 이 상태 문서는 24시간 뒤 만료된다. 기존 공통 Finding 형식과 DB 스키마는 그대로 사용한다. 로컬 CLI의 `readiness.json`에는 아래 객체가 저장된다.

탐지 항목이 없는 경우

```json
{
  "can_publish": true,
  "reasons": []
}
```

합성 테스트 사례인 `seed.txt`에서 국내 규칙이 탐지한 경우의 차단 사유 예시

```json
{
  "can_publish": false,
  "reasons": [
    {
      "rule_id": "kr-rrn",
      "severity": "CRITICAL",
      "file": "seed.txt",
      "line": 1
    }
  ]
}
```

차단 사유는 탐지 규칙, 위험도, 저장소 내부 경로, 줄 번호를 제공한다. 줄 번호를 알 수 없으면 `null`이다. 탐지된 값과 일치한 원문은 판정 객체에 포함하지 않는다.

관련 이슈 [#18 저장소 공개 전환 가능 여부 판정](https://github.com/kwon051/CommitGuard/issues/18)
