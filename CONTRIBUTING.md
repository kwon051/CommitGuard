# CommitGuard 기여 및 협업 가이드

CommitGuard(커밋 지킴이)는 학생 팀 프로젝트를 위한 셀프호스팅 보안 점검 웹 서비스입니다.

본 문서는 팀원들이 일관된 방식으로 코드를 작성하고 검토하기 위한 협업 규칙을 정의합니다.

## 1. 브랜치 전략

프로젝트는 Git Flow를 간소화한 브랜치 전략을 사용합니다.

| 브랜치 | 용도 |
|---|---|
| main | 발표 및 배포용 안정 버전 |
| develop | 기능 통합 및 개발 |
| feature/* | 개별 기능 개발 |
| hotfix/* | 긴급 오류 수정 |

### 브랜치 이름 예시

- feature/web
- feature/secret-scan
- feature/image-scan
- feature/report
- feature/k8s
- hotfix/db-connection

모든 기능 개발은 develop에서 새 feature 브랜치를 생성하여 진행합니다.

main과 develop에는 직접 push하지 않습니다.

## 2. 커밋 메시지 규칙

커밋 메시지는 다음 형식을 사용합니다.

**형식: 유형: 변경 내용**

| 유형 | 설명 |
|---|---|
| feat | 새로운 기능 추가 |
| fix | 오류 수정 |
| docs | 문서 수정 |
| test | 테스트 코드 추가 또는 수정 |
| refactor | 코드 구조 개선 |
| chore | 환경 설정 및 기타 작업 |

### 작성 예시

- feat: add repository input page
- feat: add gitleaks scanner
- fix: resolve database connection error
- docs: update README
- test: add scanner unit tests
- chore: configure docker compose

커밋 메시지는 변경 사항을 이해할 수 있도록 구체적으로 작성합니다.

## 3. Pull Request 규칙

1. 모든 기능은 feature 브랜치에서 개발합니다.
2. 작업을 완료하면 develop 브랜치를 대상으로 Pull Request를 생성합니다.
3. PR에는 관련 Issue 번호, 변경 내용, 테스트 방법과 결과를 작성합니다.
4. 지정된 리뷰어 1명 이상의 승인을 받아야 병합할 수 있습니다.
5. 필수 GitHub Actions 검사가 설정된 경우, 검사를 통과해야 병합할 수 있습니다.
6. PR 병합 이후 완료된 feature 브랜치는 삭제할 수 있습니다.

main 브랜치에는 안정화된 develop 버전만 PR을 통해 병합합니다.

긴급 수정은 main에서 hotfix 브랜치를 만들고, 수정 결과를 main과 develop 모두에 반영합니다.

## 4. 팀원별 PR 리뷰 담당자

| PR 작성자 | 리뷰어 |
|---|---|
| 권은빈 (PM·화면) | 김기령 |
| 은하 (인프라) | 권은빈 |
| 임두연 (기능 1) | 정은서 |
| 정은서 (기능 2) | 임두연 |
| 김기령 (기능 3) | 은하 |

### 리뷰 규칙

- PR 등록 후 24시간 이내에 리뷰합니다.
- 리뷰어가 24시간 이상 응답하지 않으면 PM이 다른 리뷰어를 지정합니다.
- 수정 요청은 다음 마감일까지 반영합니다.
- 코드 동결 이후에는 PM의 확인을 거쳐 버그 수정만 병합합니다.

## 5. 보안 규칙

CommitGuard는 보안 점검 서비스이므로 개발 과정에서도 민감정보 관리 규칙을 준수합니다.

- 실제 API 키, 비밀번호, 개인정보를 GitHub에 올리지 않습니다.
- 환경 변수와 비밀번호는 .env 파일에서 관리합니다.
- .env 파일은 .gitignore에 등록하여 추적하지 않습니다.
- 공유할 환경 변수 예시는 .env.example에 작성하며 실제 비밀값을 넣지 않습니다.
- 테스트에는 가짜 키와 가짜 개인정보만 사용합니다.
- 실제 민감정보를 AI 도구에 입력하지 않습니다.

## 6. 작업 제출 및 일정 관리

- 모든 코드 산출물은 GitHub PR로 제출합니다.
- 문서와 발표 자료는 팀 공유 폴더에 업로드합니다.
- 제출 후 팀 카카오톡방에 링크를 공유합니다.
- 일반 작업 마감은 수요일과 일요일 23:59입니다.
- 마감을 지키기 어려우면 최소 24시간 전에 PM에게 알립니다.
- 매주 금요일 수업 직후 정기 회의를 진행합니다.

## 7. GitHub Actions

프로젝트에서는 다음 6개 워크플로를 단계적으로 구현합니다.

1. lint: 코드 스타일 검사
2. unit-test: 단위 테스트
3. secret-scan: Gitleaks 비밀정보 검사
4. image-scan: Trivy 이미지 취약점 검사
5. compose-test: Docker Compose 통합 테스트
6. deploy: 배포 자동화

워크플로가 구현되고 필수 검사로 지정된 이후에는 해당 검사를 통과한 PR만 병합합니다.

## 8. 협업 원칙

모든 팀원은 맡은 기능을 독립적으로 개발하되, 공통 형식과 인터페이스를 준수합니다.

문제가 발생하면 GitHub Issue 또는 팀 카카오톡방을 통해 공유합니다.

CommitGuard는 코드 리뷰와 협업을 통해 안전하고 일관된 개발 과정을 유지하는 것을 목표로 합니다.
