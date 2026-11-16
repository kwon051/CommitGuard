"""결과 수집기 (기능 3)

Gitleaks·Trivy 결과(공통 형식 JSON)를 하나로 모아
중복을 없애고, 위험도 순으로 정렬한 뒤, DB에 저장한다.

사용 예)
  # 합친 결과를 화면에 요약 출력
  python worker/aggregator.py samples/gitleaks-findings.json samples/trivy-findings.json

  # 합친 결과를 파일로 저장
  python worker/aggregator.py samples/gitleaks-findings.json samples/trivy-findings.json --out all-findings.json

  # DB에 저장 (worker 컨테이너 안에서, pymysql 필요)
  python aggregator.py gitleaks.json trivy.json --db --repo https://github.com/user/repo
"""
import argparse
import json
import os
import sys

# 위험도 순서 (숫자가 작을수록 위험)
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}

# 공통 형식 v1 필드 10개 (docs/finding-format.md)
FIELDS = ["tool", "rule_id", "severity", "file", "line",
          "title", "why", "fix", "status", "fingerprint"]


def load_findings(paths):
    """공통 형식 JSON 파일 여러 개를 읽어 하나의 목록으로 만든다. 없는 파일은 건너뛴다."""
    findings = []
    for path in paths:
        if not os.path.exists(path):
            print(f"[aggregator] 파일이 없어 건너뜀: {path}", file=sys.stderr)
            continue
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, list):
            raise ValueError(f"{path}: 결과는 목록(list) 형태여야 합니다")
        findings.extend(data)
    return findings


def normalize(item):
    """공통 형식 10개 필드만 남기고, 빠진 값은 기본값으로 채운다."""
    f = {key: item.get(key) for key in FIELDS}
    severity = str(f["severity"] or "UNKNOWN").upper()
    f["severity"] = severity if severity in SEVERITY_ORDER else "UNKNOWN"
    f["status"] = f["status"] or "open"
    if not f["fingerprint"]:
        # fingerprint가 없으면 도구:규칙:파일:줄 로 만든다
        f["fingerprint"] = f"{f['tool']}:{f['rule_id']}:{f['file']}:{f['line']}"
    return f


def merge(findings):
    """같은 fingerprint는 하나만 남기고(더 위험한 쪽 유지), 위험도 순으로 정렬한다."""
    unique = {}
    for item in findings:
        f = normalize(item)
        old = unique.get(f["fingerprint"])
        if old is None or SEVERITY_ORDER[f["severity"]] < SEVERITY_ORDER[old["severity"]]:
            unique[f["fingerprint"]] = f
    return sorted(
        unique.values(),
        key=lambda f: (SEVERITY_ORDER[f["severity"]], str(f["tool"]), str(f["file"])),
    )


def summarize(findings):
    """위험도별 건수를 센다."""
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for f in findings:
        counts[f["severity"]] += 1
    return counts


# 같은 저장소 + 같은 fingerprint면 새로 넣지 않고 내용만 갱신한다.
# 팀원이 ignored로 표시한 항목은 그대로 두고, 나머지는 다시 open으로 만든다.
UPSERT_SQL = """
INSERT INTO findings
  (repo_url, tool, rule_id, severity, file, line, title, why, fix, status, fingerprint)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s) AS new
ON DUPLICATE KEY UPDATE
  severity = new.severity,
  file = new.file,
  line = new.line,
  title = new.title,
  why = new.why,
  fix = new.fix,
  status = IF(findings.status = 'ignored', 'ignored', 'open')
"""


def mark_fixed_sql(count):
    """이번 검사에 없는 open 항목을 fixed로 바꾸는 SQL."""
    sql = "UPDATE findings SET status = 'fixed' WHERE repo_url = %s AND status = 'open'"
    if count:
        sql += " AND fingerprint NOT IN (" + ", ".join(["%s"] * count) + ")"
    return sql


def save_to_db(conn, repo_url, findings):
    """결과를 findings 테이블에 저장하고, 사라진 항목은 fixed로 바꾼다."""
    rows = [
        (repo_url, f["tool"], f["rule_id"], f["severity"], f["file"], f["line"],
         f["title"], f["why"], f["fix"], f["status"], f["fingerprint"])
        for f in findings
    ]
    fingerprints = [f["fingerprint"] for f in findings]
    cur = conn.cursor()
    try:
        if rows:
            cur.executemany(UPSERT_SQL, rows)
        cur.execute(mark_fixed_sql(len(fingerprints)), [repo_url] + fingerprints)
        fixed = cur.rowcount
        conn.commit()
    finally:
        cur.close()
    return {"saved": len(rows), "fixed": fixed}


def get_connection():
    """docker-compose 환경변수로 MySQL에 접속한다."""
    import pymysql  # DB 저장할 때만 필요

    return pymysql.connect(
        host=os.environ.get("DB_HOST", "db"),
        user=os.environ.get("MYSQL_USER", "commitguard"),
        password=os.environ.get("MYSQL_PASSWORD", ""),
        database=os.environ.get("MYSQL_DATABASE", "commitguard"),
        charset="utf8mb4",
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gitleaks·Trivy 결과 수집기")
    parser.add_argument("files", nargs="+", help="공통 형식 JSON 파일들")
    parser.add_argument("--out", help="합친 결과를 저장할 JSON 파일")
    parser.add_argument("--db", action="store_true", help="MySQL findings 테이블에 저장")
    parser.add_argument("--repo", help="검사한 저장소 주소 (--db와 함께 사용)")
    args = parser.parse_args(argv)

    raw = load_findings(args.files)
    merged = merge(raw)
    counts = summarize(merged)
    detail = ", ".join(f"{k} {v}" for k, v in counts.items())
    print(f"[aggregator] 입력 {len(raw)}건 -> 중복 제거 후 {len(merged)}건 ({detail})")

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(merged, f, ensure_ascii=False, indent=2)
        print(f"[aggregator] 저장: {args.out}")

    if args.db:
        if not args.repo:
            parser.error("--db를 쓸 때는 --repo 저장소 주소가 필요합니다")
        conn = get_connection()
        try:
            result = save_to_db(conn, args.repo, merged)
        finally:
            conn.close()
        print(f"[aggregator] DB 저장 {result['saved']}건, fixed 처리 {result['fixed']}건")

    return merged


if __name__ == "__main__":
    main()