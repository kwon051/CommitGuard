"""Regression tests for result status, summary and job ID preservation."""
import json
from unittest.mock import MagicMock, patch

import app as web

REPO = "https://github.com/example/repository"
JOB = "00000000-0000-4000-8000-000000000001"


def finding(status):
    return dict(tool="gitleaks", rule_id="test", severity="CRITICAL",
                file="test.py", line=1, title="Test", why="Test", fix="Test",
                status=status)


def test_done_summary():
    job = {"repo_url": REPO, "status": "done",
           "public_readiness": {"can_publish": True, "reasons": []}}
    with patch("app.queue.get", return_value=json.dumps(job)), patch(
        "app.load_db_findings", return_value=[finding("fixed")]
    ):
        page = web.app.test_client().get("/results", query_string={
            "repo_url": REPO, "job_id": JOB,
        }).get_data(as_text=True)
    assert "검사 완료</strong>" in page
    assert "검사 진행 중</strong>" not in page
    assert "누적 보안 항목: <strong>1건</strong>" in page
    assert "미해결: <strong>0건</strong>" in page
    assert "해결: 1건" in page
    assert "공개 가능" in page
    assert "CRITICAL (매우 위험):</strong>" in page


def test_status_running_and_failed():
    for status, label in [("running", "검사 진행 중"), ("failed", "검사 실패")]:
        with patch("app.queue.get", return_value=json.dumps({
            "repo_url": REPO, "status": status,
        })), patch("app.load_db_findings", return_value=[]):
            page = web.app.test_client().get("/results", query_string={
                "repo_url": REPO, "job_id": JOB,
            }).get_data(as_text=True)
        assert label + "</strong>" in page
        assert "판정 보류" in page


def test_update_preserves_job_id():
    client = web.app.test_client()
    with client.session_transaction() as session:
        session["csrf_token"] = "test-token"
    with patch("pymysql.connect", return_value=MagicMock()):
        response = client.post("/findings/1/update", data={
            "repo_url": REPO, "job_id": JOB, "csrf_token": "test-token",
            "assignee": "", "status": "fixed",
        })
    assert response.status_code == 303
    assert "job_id=" + JOB in response.headers["Location"]
