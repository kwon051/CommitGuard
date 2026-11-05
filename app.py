
import json
import os
import re
import uuid

import valkey
from flask import Flask, render_template, request

app = Flask(__name__)

# Valkey 연결 설정
queue = valkey.Valkey(
    host=os.getenv("VALKEY_HOST", "127.0.0.1"),
    port=int(os.getenv("VALKEY_PORT", "6379")),
    socket_connect_timeout=3,
    socket_timeout=3,
)

# 임시 작업 대기열 이름 (팀원과 협의 후 확정)
QUEUE_NAME = "commitguard:scan:pending"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    repo_url = request.form.get("repo_url", "").strip()

    pattern = (
        r"https://github\.com/"
        r"[A-Za-z0-9-]+/"
        r"[A-Za-z0-9_.-]+/?"
    )

    if not re.fullmatch(pattern, repo_url):
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

    return (
        f"검사 요청 등록 성공! 작업 번호: {job['job_id']}",
        202,
    )
