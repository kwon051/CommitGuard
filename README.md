# CommitGuard
학생 팀 프로젝트를 위한 셀프호스팅 보안 점검 웹 서비스


## 실행 방법

1. Docker Desktop을 켭니다.
2. 터미널에서 저장소 폴더(CommitGuard)로 이동한 뒤 아래 명령어를 실행합니다.
   ```bash
   cp .env.example .env
   ```
3. .env 파일에서 change-me 부분을 수정해 mysql 비밀번호를 설정합니다.
3. 컨테이너를 실행합니다.
   ```bash
   docker compose up -d --build
   ```
4. 브라우저에서 http://localhost:5001 에 접속합니다.
5. 종료 -  `docker compose down`을 실행합니다. DB 데이터는 db-data 볼륨에 남게 됩니다.


## 자주 나는 오류

| 오류 | 해결 방법 |
|---|---|
| Cannot connect to the Docker daemon | Docker Desktop을 켜고 다시 실행해주세요. |
| no configuration file provided | CommitGuard 폴더 안에서 실행해주세요. |
| address already in use | 다른 프로그램이 같은 포트를 쓰고 있습니다. 맥은 AirPlay 수신 모드가 5000번을 써서 5001로 열어두었습니다. |
| Access denied (DB) | .env 비밀번호를 바꾼 경우입니다. `docker compose down -v` 후 다시 실행해주세요. DB 데이터는 삭제됩니다. |