"""실제 검사 결과 DB 조회 화면 테스트 (MySQL 서버 없이 Mock 사용)."""
import unittest
from unittest.mock import patch, MagicMock

import app as web


REPO = "https://github.com/example/repository"


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
        self.assertIn("/results?repo_url=", response.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
