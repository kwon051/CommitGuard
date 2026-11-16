# Gitleaks(기능 1)·Trivy(기능 2) 검증용 이미지.
# 공용 worker 이미지에는 Gitleaks·Trivy 단계와 git 설치/COPY 부분을 합친다.
FROM ghcr.io/gitleaks/gitleaks:v8.30.1 AS gitleaks
FROM aquasec/trivy:0.76.2 AS trivy

FROM python:3.12-slim

# Gitleaks가 Git 이력을 검사할 수 있도록 git을 설치한다.
# ca-certificates는 Trivy가 취약점 DB를 받을 때도 쓴다.
RUN apt-get update \
 && apt-get install -y --no-install-recommends git ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=gitleaks /usr/bin/gitleaks /usr/local/bin/gitleaks
RUN gitleaks version

# Trivy 실행 파일만 복사한다. 취약점 DB는 trivy-cache 볼륨(/root/.cache/trivy)에 받는다.
COPY --from=trivy /usr/local/bin/trivy /usr/local/bin/trivy
RUN trivy --version

WORKDIR /app

# 큐(valkey)에서 요청을 꺼내고 DB(pymysql)에 저장할 때 쓴다.
# cryptography는 MySQL 8.4 기본 인증 방식 때문에 pymysql이 필요로 한다.
RUN pip install --no-cache-dir valkey==6.2.0 pymysql==1.1.1 cryptography

COPY scanners/ /app/scanners/
COPY gitleaks.toml /app/gitleaks.toml

# compose에서는 queue를 지켜보는 main.py를 실행한다.
# (파일 이름이 worker.py이면 테스트의 `import worker.scanners`가 이 파일을 잡아 실패한다)
# 검사 모듈만 따로 시험할 때: docker run --entrypoint python <이미지> -m scanners.gitleaks
COPY aggregator.py main.py ./
# -u: 로그가 docker compose logs에 바로 보이게 한다.
CMD ["python", "-u", "main.py"]
