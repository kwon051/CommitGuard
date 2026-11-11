-- 커밋 지킴이 DB 초기화 (MySQL이 처음 켜질 때 자동 실행)
-- 공통 형식 v1 (docs/finding-format.md)의 필드를 그대로 칸으로 만든다

CREATE TABLE IF NOT EXISTS findings (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  repo_url    VARCHAR(255) NOT NULL,              -- 검사한 GitHub 저장소 주소
  tool        VARCHAR(20)  NOT NULL,              -- gitleaks / trivy
  rule_id     VARCHAR(100) NOT NULL,              -- 규칙 또는 CVE 번호
  severity    VARCHAR(10)  NOT NULL,              -- CRITICAL / HIGH / MEDIUM / LOW
  file        VARCHAR(255) NOT NULL,              -- 발견된 파일 경로
  line        INT NULL,                           -- 줄 번호 (없으면 NULL)
  title       VARCHAR(255) NOT NULL,              -- 한 줄 요약 (키는 가려서 저장)
  why         TEXT,                               -- 왜 위험한지
  fix         TEXT,                               -- 어떻게 고치는지
  status      VARCHAR(10)  NOT NULL DEFAULT 'open', -- open / fixed / ignored
  fingerprint VARCHAR(255) NOT NULL,              -- 검사마다 같은 결과를 구분하는 값
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  UNIQUE KEY uq_repo_fingerprint (repo_url, fingerprint)
) DEFAULT CHARSET = utf8mb4;
