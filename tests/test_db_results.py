"""실제 검사 결과 DB 조회 화면 테스트 (MySQL 서버 없이 Mock 사용)."""
import json
import unittest
from unittest.mock import patch, MagicMock

import app as web


REPO = "https://github.com/example/repository"
JOB_ID = "00000000-0000-4000-8000-000000000001"


class TestDBResults(unittest.TestCase):
    def setUp(self):
        self.client = web.app.test_client()

    @patch("app.load_db_findings")
    def test_results_from_db(self, mock_load):
        mock_load.return_value = [{
            "tool": "gitleaks", "rule_id": "secret",
            "severity": "CRITICAL", "file": "config.py", "line": 10,
            "title": "실제 검사 결과 테스트", "why": "키가 노출됨",
            "fix": "키를 교체하세요", "status": "open",
        }]
        response = self.client.get("/results", query_string={"repo_url": REPO})
        self.assertEqual(response.status_code, 200)
        page = response.get_data(as_text=True)
        self.assertIn("실제 검사 결과 테스트", page)
        self.assertIn("실제 검사 결과", page)
        self.assertNotIn("시연용 샘플 데이터", page)
        mock_load.assert_called_once_with(REPO)

    @patch("app.load_db_findings")
    def test_no_db_findings(self, mock_load):
        mock_load.return_value = []
        response = self.client.get("/results", query_string={"repo_url": REPO})
        self.assertEqual(response.status_code, 200)
        self.assertIn("표시할 보안 검사 결과가 없습니다", response.get_data(as_text=True))

    @patch("app.load_db_findings")
    def test_db_error_is_not_sample_fallback(self, mock_load):
        mock_load.side_effect = RuntimeError("secret diagnostic")
        response = self.client.get("/results", query_string={"repo_url": REPO})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("secret diagnostic", response.get_data(as_text=True))
        self.assertNotIn("시연용 샘플 데이터", response.get_data(as_text=True))

    @patch("app.load_db_findings")
    def test_invalid_repo_url(self, mock_load):
        response = self.client.get("/results", query_string={
            "repo_url": "https://github.com.evil.example/owner/repo"
        })
        self.assertEqual(response.status_code, 400)
        mock_load.assert_not_called()

    @patch("pymysql.connect")
    def test_db_connection_closes_and_parameterizes(self, mock_connect):
        conn = MagicMock()
        cursor = MagicMock()
        conn.cursor.return_value.__enter__.return_value = cursor
        cursor.fetchall.return_value = []
        mock_connect.return_value = conn
        result = web.load_db_findings(REPO)
        self.assertEqual(result, [])
        sql, values = cursor.execute.call_args.args
        self.assertIn("WHERE repo_url = %s", sql)
        self.assertEqual(values, (REPO,))
        conn.close.assert_called_once()

    @patch("app.queue.rpush")
    def test_scan_returns_results_link(self, mock_queue):
        response = self.client.post("/scan", data={"repo_url": REPO})
        self.assertEqual(response.status_code, 202)
        page = response.get_data(as_text=True)
        self.assertIn("/results?repo_url=", page)
        job = json.loads(mock_queue.call_args.args[1])
        self.assertIn("&amp;job_id=" + job["job_id"], page)

    @patch("app.load_db_findings", return_value=[])
    @patch("app.queue.get")
    def test_readiness_from_completed_job(self, mock_status, mock_load):
        job = {"repo_url": REPO, "status": "done"}
        reason = {"rule_id": "kr-rrn", "severity": "CRITICAL", "file": "config.py", "line": 10}
        for reasons, label in [([], "공개 가능"), ([reason], "공개 불가")]:
            with self.subTest(label=label):
                job["public_readiness"] = {"can_publish": not reasons, "reasons": reasons}
                mock_status.return_value = json.dumps(job)
                response = self.client.get("/results", query_string={"repo_url": REPO, "job_id": JOB_ID})
                self.assertEqual(response.status_code, 200)
                page = response.get_data(as_text=True)
                self.assertIn(label, page)
                if reasons:
                    self.assertIn("kr-rrn", page)
                    self.assertIn("config.py:10", page)
                self.assertEqual(mock_status.call_args.args, (web.STATUS_PREFIX + JOB_ID,))

    @patch("app.load_db_findings", return_value=[])
    @patch("app.queue.get")
    def test_readiness_pending_without_completed_matching_job(self, mock_status, mock_load):
        verdict = {"can_publish": True, "reasons": []}
        for repo, status in [(REPO, "running"), (REPO, "failed"), (REPO + "-other", "done")]:
            with self.subTest(repo=repo, status=status):
                mock_status.return_value = json.dumps({
                    "repo_url": repo, "status": status, "public_readiness": verdict,
                })
                response = self.client.get("/results", query_string={"repo_url": REPO, "job_id": JOB_ID})
                page = response.get_data(as_text=True)
                self.assertIn("판정 보류", page)
                self.assertNotIn("공개 가능", page)

        mock_status.return_value = None
        response = self.client.get("/results", query_string={"repo_url": REPO, "job_id": JOB_ID})
        self.assertIn("판정 보류", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
