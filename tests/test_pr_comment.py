"""PR 자동 댓글(worker/pr_comment.py) 테스트

실행: python tests/test_pr_comment.py -v
"""

import contextlib
import io
import os
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "worker"))

import aggregator  # noqa: E402
import pr_comment  # noqa: E402


def finding(severity, fingerprint, title="t", file="a.py", line=1, fix="f"):
    return {
        "tool": "gitleaks",
        "rule_id": "r",
        "severity": severity,
        "file": file,
        "line": line,
        "title": title,
        "why": "w",
        "fix": fix,
        "status": "open",
        "fingerprint": fingerprint,
    }


class FakeGitHub:
    def __init__(self, existing):
        self.existing = existing
        self.calls = []

    def __call__(self, method, url, token, data=None):
        self.calls.append((method, url, data))
        return self.existing if method == "GET" else {}


class PrCommentTest(unittest.TestCase):
    def test_no_findings(self):
        body = pr_comment.build_comment([])
        self.assertIn(pr_comment.MARKER, body)
        self.assertIn("발견된 보안 문제가 없습니다", body)

    def test_summary_counts_and_order(self):
        merged = aggregator.merge(
            [
                finding("LOW", "fp-1", title="낮은 문제"),
                finding("CRITICAL", "fp-2", title="키 노출"),
            ]
        )
        body = pr_comment.build_comment(merged)
        self.assertIn("**2건**", body)
        self.assertIn("| 🔴 CRITICAL (매우 위험) | 1 |", body)
        self.assertLess(body.index("키 노출"), body.index("낮은 문제"))

    def test_limits_items(self):
        merged = aggregator.merge(
            [finding("HIGH", f"fp-{i}") for i in range(5)]
        )
        body = pr_comment.build_comment(merged, max_items=2)
        self.assertIn("외 3건", body)

    def test_cell_escapes_table_characters(self):
        merged = aggregator.merge(
            [finding("HIGH", "fp-1", title="a|b\nc", line=None)]
        )
        body = pr_comment.build_comment(merged)
        self.assertIn("a\\|b c", body)
        self.assertIn("`a.py`", body)

    def test_post_creates_new_comment(self):
        fake = FakeGitHub(existing=[{"id": 1, "body": "다른 댓글"}])
        result = pr_comment.post_comment("o/r", 7, "내용", "tok", request=fake)
        self.assertEqual(result, "created")
        self.assertEqual(fake.calls[-1][0], "POST")
        self.assertTrue(
            fake.calls[-1][1].endswith("/repos/o/r/issues/7/comments")
        )

    def test_post_updates_existing_comment(self):
        fake = FakeGitHub(
            existing=[{"id": 42, "body": pr_comment.MARKER + " 이전 결과"}]
        )
        result = pr_comment.post_comment(
            "o/r", 7, "새 내용", "tok", request=fake
        )
        self.assertEqual(result, "updated")
        method, url, data = fake.calls[-1]
        self.assertEqual(method, "PATCH")
        self.assertTrue(url.endswith("/issues/comments/42"))
        self.assertEqual(data, {"body": "새 내용"})

    @unittest.skipUnless(
        os.path.exists(
            os.path.join(ROOT, "samples", "gitleaks-findings.json")
        ),
        "샘플 파일 없음",
    )
    def test_real_samples_dry_run(self):
        paths = [
            os.path.join(ROOT, "samples", n)
            for n in ("gitleaks-findings.json", "trivy-findings.json")
        ]
        with contextlib.redirect_stdout(io.StringIO()):
            body = pr_comment.main(paths + ["--dry-run"])
        self.assertIn("CommitGuard 보안 검사 결과", body)


if __name__ == "__main__":
    unittest.main()