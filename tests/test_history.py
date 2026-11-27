
import unittest
from unittest.mock import MagicMock, patch

import app as web


REPO = "https://github.com/kwon051/CommitGuard"


class TestHistory(unittest.TestCase):

    def setUp(self):
        web.app.config["TESTING"] = True
        self.client = web.app.test_client()

    @patch("app.load_history_records")
    def test_history_page(self, mock_load):
        """검사 이력 화면에 실제 저장소 정보가 표시되는지 확인"""
        mock_load.return_value = [{
            "repo_url": REPO,
            "total": 2,
            "open_count": 1,
            "fixed_count": 1,
            "ignored_count": 0,
            "last_updated": "2026-11-23",
        }]

        response = self.client.get("/history")

        self.assertEqual(response.status_code, 200)
        html = response.get_data(as_text=True)
        self.assertIn("검사 이력", html)
        self.assertIn(REPO, html)
        self.assertIn("전체 2건", html)

    @patch("app.load_history_records")
    def test_empty_history(self, mock_load):
        """검사 결과가 없을 때 안내 문구 표시"""
        mock_load.return_value = []

        response = self.client.get("/history")

        self.assertEqual(response.status_code, 200)
        self.assertIn(
            "저장된 검사 결과가 없습니다",
            response.get_data(as_text=True),
        )

    @patch("app.load_history_records")
    def test_history_db_error(self, mock_load):
        """DB 연결 실패 시 503 오류 반환"""
        mock_load.side_effect = RuntimeError("DB error")

        response = self.client.get("/history")

        self.assertEqual(response.status_code, 503)

    @patch("pymysql.connect")
    def test_update_finding(self, mock_connect):
        """담당자 및 처리 상태가 올바르게 저장되는지 확인"""
        conn = MagicMock()
        cursor = MagicMock()

        conn.cursor.return_value.__enter__.return_value = cursor
        mock_connect.return_value = conn

        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-token"

        response = self.client.post(
            "/findings/1/update",
            data={
                "csrf_token": "test-token",
                "repo_url": REPO,
                "assignee": "권은빈",
                "status": "open",
            },
        )

        self.assertEqual(response.status_code, 303)

        sql, values = cursor.execute.call_args.args

        self.assertIn("UPDATE findings", sql)
        self.assertEqual(
            values,
            ("권은빈", "open", 1, REPO),
        )

        conn.commit.assert_called_once()
        conn.close.assert_called_once()

    @patch("pymysql.connect")
    def test_invalid_csrf(self, mock_connect):
        """위조 방지 토큰이 없으면 저장 차단"""
        response = self.client.post(
            "/findings/1/update",
            data={
                "repo_url": REPO,
                "assignee": "권은빈",
                "status": "open",
            },
        )

        self.assertEqual(response.status_code, 403)
        mock_connect.assert_not_called()

    @patch("pymysql.connect")
    def test_invalid_status(self, mock_connect):
        """허용되지 않은 처리 상태 저장 차단"""
        with self.client.session_transaction() as session:
            session["csrf_token"] = "test-token"

        response = self.client.post(
            "/findings/1/update",
            data={
                "csrf_token": "test-token",
                "repo_url": REPO,
                "assignee": "권은빈",
                "status": "invalid",
            },
        )

        self.assertEqual(response.status_code, 400)
        mock_connect.assert_not_called()


if __name__ == "__main__":
    unittest.main()
