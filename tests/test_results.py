
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as web


class TestResultsPage(unittest.TestCase):

    def setUp(self):
        """각 테스트에서 사용할 임시 JSON 파일 준비"""

        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)

        self.sample_dir = Path(self.temp_dir.name)

        # 실제 samples 폴더 대신 임시 폴더 사용
        patcher = patch.object(
            web, "SAMPLE_DIR", self.sample_dir
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        gitleaks_data = [
            {
                "tool": "gitleaks",
                "rule_id": "test-secret",
                "fingerprint": "test-secret-1",
                "severity": "CRITICAL",
                "file": "config.py",
                "line": 10,
                "title": "테스트용 키 노출",
                "why": "키가 노출되면 위험합니다.",
                "fix": "키를 폐기하고 새로 발급하세요.",
                "status": "open"
            }
        ]

        trivy_data = [
            {
                "tool": "trivy",
                "rule_id": "TEST-CVE-001",
                "fingerprint": "test-trivy-1",
                "severity": "HIGH",
                "file": "requirements.txt",
                "line": None,
                "title": "테스트용 패키지 취약점",
                "why": "취약한 버전입니다.",
                "fix": "패키지 버전을 올리세요.",
                "status": "open"
            }
        ]

        # 임시 샘플 파일 2개 생성
        for filename, data in [
            ("gitleaks-findings.json", gitleaks_data),
            ("trivy-findings.json", trivy_data),
        ]:
            file_path = self.sample_dir / filename
            file_path.write_text(
                json.dumps(data, ensure_ascii=False),
                encoding="utf-8"
            )

    def test_sample_count(self):
        """테스트 JSON 결과 2건 확인"""
        findings = web.load_sample_findings()
        self.assertEqual(len(findings), 2)

    def test_severity_order(self):
        """위험도 내림차순 정렬 확인"""
        findings = web.load_sample_findings()

        severities = [
            item["severity"] for item in findings
        ]

        self.assertEqual(
            severities,
            ["CRITICAL", "HIGH"]
        )

    def test_results_page(self):
        """결과 화면 정상 출력 확인"""
        client = web.app.test_client()
        response = client.get("/results")

        self.assertEqual(response.status_code, 200)

        html = response.get_data(as_text=True)

        self.assertIn("보안 검사 결과", html)
        self.assertIn("2건", html)
        self.assertIn("테스트용 키 노출", html)
        self.assertIn("시연용 샘플 데이터", html)

    def test_missing_json(self):
        """JSON 파일이 없을 때 안내 화면 확인"""

        # 임시 Trivy 파일만 삭제
        missing_file = (
            self.sample_dir / "trivy-findings.json"
        )
        missing_file.unlink()

        client = web.app.test_client()
        response = client.get("/results")

        self.assertEqual(response.status_code, 503)

        html = response.get_data(as_text=True)

        self.assertIn("샘플 데이터 준비 중", html)
        self.assertIn("trivy-findings.json", html)


if __name__ == "__main__":
    unittest.main()
