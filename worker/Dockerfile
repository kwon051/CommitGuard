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
COPY scanners/ /app/scanners/

# compose에서는 queue를 지켜보는 worker.py를 실행한다.
# 검사 모듈만 따로 시험할 때: docker run --entrypoint python <이미지> -m scanners.gitleaks
COPY worker.py .
CMD ["python", "worker.py"]