
import html
import json
import os
import re
import uuid
import secrets

from pathlib import Path
import valkey
from flask import Flask, render_template, request, url_for, session, redirect

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)

# 입력과 조회에서 동일한 GitHub 저장소 URL만 허용한다.
REPO_PATTERN = re.compile(r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+/?")

# Valkey 연결 설정
queue = valkey.Valkey(
    host=os.getenv("VALKEY_HOST", "127.0.0.1"),
    port=int(os.getenv("VALKEY_PORT", "6379")),
    socket_connect_timeout=3,
    socket_timeout=3,
)

# 임시 작업 대기열 이름 (팀원과 협의 후 확정)
QUEUE_NAME = "commitguard:scan:pending"
STATUS_PREFIX = "commitguard:scan:status:"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    repo_url = request.form.get("repo_url", "").strip()

    if not REPO_PATTERN.fullmatch(repo_url):
        return "올바른 GitHub 저장소 주소를 입력해 주세요.", 400

    # 검사 작업 정보 생성
    job = {
        "job_id": str(uuid.uuid4()),
        "repo_url": repo_url,
        "status": "queued",
    }

    # Valkey 대기열에 작업 등록
    try:
        queue.rpush(QUEUE_NAME, json.dumps(job))
    except valkey.exceptions.ValkeyError:
        app.logger.exception("Valkey 작업 등록 실패")
        return "검사 요청을 등록할 수 없습니다.", 503

    # 등록한 검사 작업의 결과를 DB에서 조회할 수 있도록 링크를 제공한다.
    results_url = url_for("results", repo_url=repo_url, job_id=job["job_id"])
    return (
        f'검사 요청 등록 성공! 작업 번호: {job["job_id"]}. '
        f'<a href="{html.escape(results_url)}">검사 완료 후 결과 확인</a>',
        202,
    )



def load_db_findings(repo_url):
    """실제 검사 결과를 MySQL findings 테이블에서 조회한다."""
    import pymysql

    conn = pymysql.connect(
        host=os.getenv("DB_HOST", "db"),
        user=os.getenv("MYSQL_USER", "commitguard"),
        password=os.getenv("MYSQL_PASSWORD", ""),
        database=os.getenv("MYSQL_DATABASE", "commitguard"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
        read_timeout=10,
    )
    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """SELECT id, tool, rule_id, fingerprint, severity, file, line,
          title, why, fix, status, assignee
   FROM findings
                   WHERE repo_url = %s
                   ORDER BY CASE severity
                     WHEN 'CRITICAL' THEN 0
                     WHEN 'HIGH' THEN 1
                     WHEN 'MEDIUM' THEN 2
                     WHEN 'LOW' THEN 3
                     ELSE 4 END, id DESC""",
                (repo_url,),
            )
            return cursor.fetchall()
    finally:
        conn.close()


# 보안 검사 결과 샘플 파일 위치
SAMPLE_DIR = Path(__file__).resolve().parent / "samples"

# 위험도 정렬 순서 (숫자가 작을수록 위험)
SEVERITY_ORDER = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}


def load_sample_findings():
    """Gitleaks와 Trivy 샘플 JSON을 불러온다."""
    findings = []

    sample_files = [
        "gitleaks-findings.json",
        "trivy-findings.json",
    ]

    for filename in sample_files:
        file_path = SAMPLE_DIR / filename

        with file_path.open("r", encoding="utf-8") as f:
            data = json.load(f)

        findings.extend(data)

    # 위험도가 높은 결과부터 정렬
    findings.sort(
        key=lambda item: SEVERITY_ORDER.get(
            str(item.get("severity", "UNKNOWN")).upper(),
            4,
        )
    )

    return findings


def load_scan_job(repo_url, job_id):
    """저장소와 일치하는 검사 작업의 상태를 조회한다."""
    try:
        if str(uuid.UUID(job_id)) != job_id:
            return None
        payload = queue.get(STATUS_PREFIX + job_id)
        if payload is None:
            return None
        job = json.loads(payload)
    except (ValueError, valkey.exceptions.ValkeyError):
        return None
    if (
        not isinstance(job, dict)
        or job.get("repo_url") != repo_url
        or job.get("status") not in ("queued", "running", "done", "failed")
    ):
        return None
    return job


def public_readiness_from_job(job):
    """완료된 작업의 공개 전환 판정만 반환한다."""
    if job is None or job.get("status") != "done":
        return None
    verdict = job.get("public_readiness")
    if not isinstance(verdict, dict):
        return None
    reasons = verdict.get("reasons")
    can_publish = verdict.get("can_publish")
    if not isinstance(reasons, list) or not isinstance(can_publish, bool):
        return None
    if can_publish != (not reasons):
        return None
    return verdict


def load_public_readiness(repo_url, job_id):
    """해당 저장소의 완료된 검사 작업에서 판정 결과를 가져온다."""
    return public_readiness_from_job(load_scan_job(repo_url, job_id))


@app.route("/results")
def results():
    """저장소 주소가 지정되면 DB를, 아니면 시연용 샘플을 보여준다."""
    repo_url = request.args.get("repo_url", "").strip()
    if repo_url:
        if not REPO_PATTERN.fullmatch(repo_url):
            return "올바른 GitHub 저장소 주소를 입력해 주세요.", 400
        try:
            findings = load_db_findings(repo_url)
        except Exception:
            app.logger.exception("MySQL 검사 결과 조회 실패")
            return "검사 결과 DB에 연결할 수 없습니다. 잠시 후 다시 확인해 주세요.", 503
        job_id = request.args.get("job_id", "").strip()
        job = load_scan_job(repo_url, job_id) if job_id else None
        public_readiness = public_readiness_from_job(job)
        scan_status = job["status"] if job else "unknown"
        return render_template(
            "result.html", findings=findings, missing_files=[],
            repo_url=repo_url, source="database",
            job_id=job_id, public_readiness=public_readiness,
            scan_status=scan_status,
        )

    sample_files = [
        "gitleaks-findings.json",
        "trivy-findings.json",
    ]

    # 필요한 샘플 JSON 파일이 있는지 확인
    missing_files = [
        filename
        for filename in sample_files
        if not (SAMPLE_DIR / filename).is_file()
    ]

    # 파일이 없으면 안내 화면 표시
    if missing_files:
        return render_template(
            "result.html",
            findings=[],
            missing_files=missing_files,
        ), 503

    findings = load_sample_findings()

    return render_template(
        "result.html",
        findings=findings,
        missing_files=[],
    )

# 검사 이력 화면: DB에 저장된 저장소별 보안 항목 조회
def load_history_records():
    """저장소별 검사 결과와 처리 상태를 조회한다."""
    import pymysql

    conn = pymysql.connect(
        host=os.getenv("DB_HOST", "db"),
        user=os.getenv("MYSQL_USER", "commitguard"),
        password=os.getenv("MYSQL_PASSWORD", ""),
        database=os.getenv("MYSQL_DATABASE", "commitguard"),
        charset="utf8mb4",
        cursorclass=pymysql.cursors.DictCursor,
        connect_timeout=5,
        read_timeout=10,
    )

    try:
        with conn.cursor() as cursor:
            cursor.execute(
                """
                SELECT
                    repo_url,
                    COUNT(*) AS total,
                    SUM(CASE WHEN status = 'open'
                        THEN 1 ELSE 0 END) AS open_count,
                    SUM(CASE WHEN status = 'fixed'
                        THEN 1 ELSE 0 END) AS fixed_count,
                    SUM(CASE WHEN status = 'ignored'
                        THEN 1 ELSE 0 END) AS ignored_count,
                    MAX(updated_at) AS last_updated
                FROM findings
                GROUP BY repo_url
                ORDER BY last_updated DESC
                """
            )
            return cursor.fetchall()
    finally:
        conn.close()


@app.route("/history")
def history():
    """검사 결과 이력 화면을 보여준다."""
    try:
        records = load_history_records()
    except Exception:
        app.logger.exception("검사 이력 DB 조회 실패")
        return "검사 이력을 불러올 수 없습니다.", 503

    return render_template(
        "history.html",
        records=records,
    )


@app.context_processor
def inject_csrf_token():
    def csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_urlsafe(32)
        return session["csrf_token"]

    return {"csrf_token": csrf_token}


@app.route("/findings/<int:finding_id>/update", methods=["POST"])
def update_finding(finding_id):
    """보안 항목의 담당자와 처리 상태를 변경한다."""

    saved_token = session.get("csrf_token")
    submitted_token = request.form.get("csrf_token", "")

    if not saved_token or not secrets.compare_digest(
        saved_token, submitted_token
    ):
        return "잘못된 요청입니다.", 403

    repo_url = request.form.get("repo_url", "").strip()
    assignee = request.form.get("assignee", "").strip()
    status = request.form.get("status", "").strip()

    if not REPO_PATTERN.fullmatch(repo_url):
        return "올바르지 않은 저장소 주소입니다.", 400

    if len(assignee) > 100:
        return "담당자 이름이 너무 깁니다.", 400

    if status not in ("open", "fixed", "ignored"):
        return "올바르지 않은 처리 상태입니다.", 400

    import pymysql

    conn = None
    try:
        conn = pymysql.connect(
            host=os.getenv("DB_HOST", "db"),
            user=os.getenv("MYSQL_USER", "commitguard"),
            password=os.getenv("MYSQL_PASSWORD", ""),
            database=os.getenv("MYSQL_DATABASE", "commitguard"),
            charset="utf8mb4",
        )

        with conn.cursor() as cursor:
            cursor.execute(
                """
                UPDATE findings
                SET assignee = %s, status = %s
                WHERE id = %s AND repo_url = %s
                """,
                (assignee or None, status, finding_id, repo_url),
            )

        conn.commit()

    except Exception:
        if conn:
            conn.rollback()
        app.logger.exception("담당자 및 상태 변경 실패")
        return "변경 사항을 저장하지 못했습니다.", 503

    finally:
        if conn:
            conn.close()

    job_id = request.form.get("job_id", "").strip()
    result_args = {"repo_url": repo_url}
    if job_id:
        try:
            if str(uuid.UUID(job_id)) == job_id:
                result_args["job_id"] = job_id
        except ValueError:
            pass
    return redirect(url_for("results", **result_args), code=303)
