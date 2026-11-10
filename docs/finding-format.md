# 검사 결과 공통 형식 v1

Gitleaks·Trivy 결과를 모두 이 형식으로 바꿔서 DB에 저장하고 화면에 보여 준다.

| 필드 | 타입 | 설명 | 예시 |
|---|---|---|---|
| tool | 문자열 | 결과를 낸 도구 | gitleaks / trivy |
| rule_id | 문자열 | 규칙 또는 취약점 ID | aws-access-key / CVE-2018-18074 |
| severity | 문자열 | 위험도 | CRITICAL / HIGH / MEDIUM / LOW |
| file | 문자열 | 발견된 파일 경로 | config/settings.py |
| line | 숫자 | 줄 번호 (없으면 null) | 12 |
| title | 문자열 | 한 줄 요약 (한국어) | AWS 접근 키 노출 |
| why | 문자열 | 왜 위험한지 (한국어) | 누구나 이 키로 AWS 계정을 쓸 수 있음 |
| fix | 문자열 | 어떻게 고치는지 (한국어) | 키 폐기 → 새로 발급 → 기록 삭제 |
| status | 문자열 | 처리 상태 | open / fixed / ignored |
| fingerprint | 문자열 | 같은 결과를 검사마다 구분하는 고유값 | trivy:CVE-2018-18074:requests:requirements.txt |

※ 키 값 자체는 저장하지 않고, 앞 4자리만 남겨 가린다 (예: AKIA****).

## fingerprint 만드는 방법

- Gitleaks: 결과에 있는 `Fingerprint` 값을 그대로 사용
- Trivy: `trivy:CVE번호:패키지명:파일` 형태로 만들어서 사용

## status 바뀌는 규칙

- open: 처음 발견됨
- fixed: 이전 검사에 있던 fingerprint가 재검사 결과에 없음
- ignored: 팀원이 "문제 아님"으로 표시함 (재검사에서 나와도 무시)

## 예시 1 — 비밀키 유출 (Gitleaks)
```json
{
  "tool": "gitleaks",
  "rule_id": "aws-access-key",
  "severity": "CRITICAL",
  "file": "config/settings.py",
  "line": 12,
  "title": "AWS 접근 키 노출 (AKIA****)",
  "why": "저장소를 볼 수 있는 사람은 누구나 이 키로 AWS 계정을 사용할 수 있습니다.",
  "fix": "1) AWS 콘솔에서 키 폐기 2) 새 키 발급 후 .env에 저장 3) Git 기록에서 삭제",
  "status": "open",
  "fingerprint": "6333f03a:config/settings.py:aws-access-key:12"
}
```

## 예시 2 — 취약 패키지 (Trivy)
```json
{
  "tool": "trivy",
  "rule_id": "CVE-2018-18074",
  "severity": "HIGH",
  "file": "requirements.txt",
  "line": null,
  "title": "requests 2.19.0 버전에 알려진 취약점",
  "why": "리다이렉트될 때 인증 정보가 다른 서버로 새어 나갈 수 있습니다.",
  "fix": "requirements.txt에서 requests를 2.20.0 이상으로 올리세요.",
  "status": "open",
  "fingerprint": "trivy:CVE-2018-18074:requests:requirements.txt"
}
```
