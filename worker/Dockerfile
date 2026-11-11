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

# 이 폴더에는 queue를 소비하는 worker.py가 아직 없으므로
# 샘플 저장소를 마운트해 검사 모듈을 직접 실행한다.
# (Trivy는 --entrypoint python ... -m scanners.trivy 로 실행)
ENTRYPOINT ["python", "-m", "scanners.gitleaks"]
CMD ["--help"]