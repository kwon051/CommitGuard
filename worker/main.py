"""worker: 큐에서 검사 요청을 꺼내 검사하고 결과를 DB에 저장한다.

흐름: web이 큐(Valkey)에 넣은 요청 → 저장소 clone → Gitleaks·Trivy·가짜 패키지 검사
      → 수집기(aggregator)로 합치기 → MySQL findings 테이블에 저장
"""
import json
import os
import re
import subprocess
import tempfile
import time

import valkey

import aggregator
from scanners import fake_package, gitleaks, trivy

# web(app.py)과 같은 대기열 이름을 쓴다.
QUEUE_NAME = "commitguard:scan:pending"
# web과 같은 규칙: GitHub 저장소 주소만 받는다.
REPO_PATTERN = re.compile(r"https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9_.-]+/?")
CLONE_TIMEOUT = 300
# 검사 상태를 적어 두는 곳: commitguard:scan:status:<작업 번호>
# 값은 JSON이고 status는 running(검사 중) / done(완료) / failed(실패) 중 하나다.
STATUS_PREFIX = "commitguard:scan:status:"
STATUS_TTL = 60 * 60 * 24  # 하루 뒤 자동 삭제


def log(message):
    print(f"[worker] {message}")


def connect_queue():
    return valkey.Valkey(
        host=os.environ.get("VALKEY_HOST", "queue"),
        port=int(os.environ.get("VALKEY_PORT", "6379")),
    )


def set_status(queue, job, status, **extra):
    """web이 읽을 수 있게 검사 상태를 Valkey에 적는다."""
    job_id = job.get("job_id")
    if not job_id:
        return
    value = {"job_id": job_id, "repo_url": job.get("repo_url"), "status": status}
    value.update(extra)
    try:
        queue.set(STATUS_PREFIX + str(job_id),
                  json.dumps(value, ensure_ascii=False), ex=STATUS_TTL)
    except valkey.exceptions.ValkeyError as e:
        log(f"상태 기록 실패 {job_id}: {e}")


def clone_repo(repo_url, target):
    """저장소를 내려받는다. Gitleaks가 이력 전체를 보도록 전부 받는다."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")  # 비공개 저장소에서 멈추지 않게
    try:
        subprocess.run(
            ["git", "clone", "--quiet", "--", repo_url, target],
            check=True, capture_output=True, text=True,
            timeout=CLONE_TIMEOUT, env=env,
        )
    except subprocess.CalledProcessError as e:
        raise RuntimeError(
            "저장소를 내려받지 못했습니다 (주소가 틀렸거나 비공개 저장소)") from e
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"저장소 내려받기 시간 초과({CLONE_TIMEOUT}초)") from e


def process_job(job):
    """검사 요청 1건을 처리하고, 저장한 결과를 돌려준다."""
    repo_url = str(job.get("repo_url", "")).strip()
    if not REPO_PATTERN.fullmatch(repo_url):
        raise ValueError(f"GitHub 저장소 주소가 아닙니다: {repo_url}")

    with tempfile.TemporaryDirectory() as tmp:
        repo_path = os.path.join(tmp, "repo")
        clone_repo(repo_url, repo_path)
        # 도구 하나라도 실패하면 여기서 오류가 나서 DB에 저장하지 않는다.
        # (일부 결과만 저장하면 안 고친 항목이 fixed로 바뀐다)
        findings = gitleaks.scan(repo_path) + trivy.scan(repo_path)
        # 가짜 패키지 탐지는 조회 실패를 '확인 불가' 결과로 돌려주고 예외를 내지 않는다
        findings += fake_package.scan(repo_path) 

    merged = aggregator.merge(findings)
    conn = aggregator.get_connection()
    try:
        return aggregator.save_to_db(conn, repo_url, merged)
    finally:
        conn.close()


def main():
    queue = connect_queue()
    log(f"대기 시작: {QUEUE_NAME}")
    while True:
        try:
            item = queue.blpop(QUEUE_NAME, timeout=5)
        except valkey.exceptions.ValkeyError as e:
            log(f"큐 연결 실패, 3초 뒤 다시 시도: {e}")
            time.sleep(3)
            continue
        if item is None:
            continue  # 요청이 없으면 다시 기다린다

        try:
            job = json.loads(item[1])
            if not isinstance(job, dict):
                raise ValueError("요청이 JSON 객체가 아닙니다")
        except ValueError as e:
            log(f"요청을 읽을 수 없어 건너뜀: {e}")
            continue

        job_id = job.get("job_id", "?")
        try:
            log(f"검사 시작 {job_id}: {job.get('repo_url')}")
            set_status(queue, job, "running")
            result = process_job(job)
            set_status(queue, job, "done",
                       saved=result["saved"], fixed=result["fixed"])
            log(f"검사 완료 {job_id}: 저장 {result['saved']}건, fixed {result['fixed']}건")
        except Exception as e:  # 한 건이 실패해도 worker는 계속 돈다
            set_status(queue, job, "failed", error=str(e))
            log(f"검사 실패 {job_id}: {e}")


if __name__ == "__main__":
    main()
