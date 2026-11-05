
import json
import unittest
from unittest.mock import patch

from app import app, QUEUE_NAME


class WebInputTests(unittest.TestCase):

    def setUp(self):
        app.config["TESTING"] = True
        self.client = app.test_client()

    def test_home_page(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"CommitGuard", response.data)

    @patch("app.queue.rpush")
    def test_valid_github_url(self, mock_rpush):
        response = self.client.post(
            "/scan",
            data={
                "repo_url": "https://github.com/kwon051/CommitGuard"
            },
        )

        self.assertEqual(response.status_code, 202)
        mock_rpush.assert_called_once()

        queue_name, payload = mock_rpush.call_args.args
        job = json.loads(payload)

        self.assertEqual(queue_name, QUEUE_NAME)
        self.assertEqual(
            job["repo_url"],
            "https://github.com/kwon051/CommitGuard",
        )
        self.assertEqual(job["status"], "queued")
        self.assertTrue(job["job_id"])

    @patch("app.queue.rpush")
    def test_invalid_github_url(self, mock_rpush):
        invalid_urls = [
            "https://gitlab.com/example/project",
            "https://github.com/kwon051",
            "https://fakegithub.com/example/project",
        ]

        for url in invalid_urls:
            with self.subTest(url=url):
                response = self.client.post(
                    "/scan",
                    data={"repo_url": url},
                )
                self.assertEqual(response.status_code, 400)

        mock_rpush.assert_not_called()


if __name__ == "__main__":
    unittest.main()
