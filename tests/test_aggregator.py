"""결과 수집기(worker/aggregator.py) 테스트

실행: python -m unittest discover -s tests -p "test_aggregator.py" -v
"""
import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "worker"))

import aggregator  # noqa: E402


def finding(tool, rule_id, severity, fingerprint, **extra):
    item = {
        "tool": tool, "rule_id": rule_id, "severity": severity,
        "file": "a.py", "line": 1, "title": "t", "why": "w", "fix": "f",
        "status": "open", "fingerprint": fingerprint,
    }
    item.update(extra)
    return item


class FakeCursor:
    def __init__(self):
        self.calls = []
        self.rowcount = 0

    def executemany(self, sql, rows):
        self.calls.append(("executemany", sql, list(rows)))

    def execute(self, sql, params):
        self.calls.append(("execute", sql, list(params)))
        self.rowcount = 2

    def close(self):
        pass


class FakeConnection:
    def __init__(self):
        self.cur = FakeCursor()
        self.committed = False

    def cursor(self):
        return self.cur

    def commit(self):
        self.committed = True


class AggregatorTest(unittest.TestCase):
    def test_merge_removes_duplicate_fingerprint(self):
        items = [
            finding("gitleaks", "aws", "HIGH", "fp-1"),
            finding("gitleaks", "aws", "CRITICAL", "fp-1"),
            finding("trivy", "CVE-1", "LOW", "fp-2"),
        ]
        merged = aggregator.merge(items)
        self.assertEqual(len(merged), 2)
        # 같은 fingerprint는 더 위험한 쪽을 남긴다
        self.assertEqual(merged[0]["severity"], "CRITICAL")

    def test_sorted_by_severity(self):
        items = [
            finding("trivy", "c", "LOW", "fp-low"),
            finding("trivy", "a", "CRITICAL", "fp-crit"),
            finding("trivy", "b", "MEDIUM", "fp-mid"),
            finding("trivy", "d", "HIGH", "fp-high"),
        ]
        severities = [f["severity"] for f in aggregator.merge(items)]
        self.assertEqual(severities, ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_missing_fields_get_defaults(self):
        item = {"tool": "trivy", "rule_id": "CVE-9", "file": "requirements.txt",
                "line": None, "severity": "weird"}
        f = aggregator.merge([item])[0]
        self.assertEqual(f["status"], "open")
        self.assertEqual(f["severity"], "UNKNOWN")
        self.assertEqual(f["fingerprint"], "trivy:CVE-9:requirements.txt:None")
        self.assertEqual(sorted(f.keys()), sorted(aggregator.FIELDS))

    def test_load_findings_skips_missing_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "g.json")
            with open(path, "w", encoding="utf-8") as fp:
                json.dump([finding("gitleaks", "aws", "HIGH", "fp-1")], fp)
            loaded = aggregator.load_findings([path, os.path.join(tmp, "none.json")])
        self.assertEqual(len(loaded), 1)

    def test_load_findings_rejects_non_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "bad.json")
            with open(path, "w", encoding="utf-8") as fp:
                json.dump({"tool": "gitleaks"}, fp)
            with self.assertRaises(ValueError):
                aggregator.load_findings([path])

    def test_save_to_db_upserts_and_marks_fixed(self):
        conn = FakeConnection()
        merged = aggregator.merge([
            finding("gitleaks", "aws", "CRITICAL", "fp-1"),
            finding("trivy", "CVE-1", "HIGH", "fp-2"),
        ])
        result = aggregator.save_to_db(conn, "https://github.com/x/y", merged)
        kind, sql, rows = conn.cur.calls[0]
        self.assertEqual(kind, "executemany")
        self.assertIn("ON DUPLICATE KEY UPDATE", sql)
        self.assertEqual(len(rows), 2)
        kind, sql, params = conn.cur.calls[1]
        self.assertIn("status = 'fixed'", sql)
        self.assertEqual(params, ["https://github.com/x/y", "fp-1", "fp-2"])
        self.assertTrue(conn.committed)
        self.assertEqual(result, {"saved": 2, "fixed": 2})

    @unittest.skipUnless(
        os.path.exists(os.path.join(ROOT, "samples", "gitleaks-findings.json")),
        "샘플 파일 없음",
    )
    def test_real_samples(self):
        paths = [os.path.join(ROOT, "samples", name)
                 for name in ("gitleaks-findings.json", "trivy-findings.json")]
        merged = aggregator.merge(aggregator.load_findings(paths))
        self.assertGreater(len(merged), 0)
        order = [aggregator.SEVERITY_ORDER[f["severity"]] for f in merged]
        self.assertEqual(order, sorted(order))
        for f in merged:
            self.assertTrue(f["fingerprint"])


if __name__ == "__main__":
    unittest.main()