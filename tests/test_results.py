
import unittest

from app import app, load_sample_findings, SEVERITY_ORDER


class TestResultsPage(unittest.TestCase):

    def test_sample_count(self):
        """샘플 결과가 36건인지 확인"""
        findings = load_sample_findings()

        self.assertEqual(len(findings), 36)

    def test_severity_order(self):
        """위험도가 높은 순서대로 정렬되는지 확인"""
        findings = load_sample_findings()

        levels = [
            SEVERITY_ORDER.get(
                str(item.get("severity", "UNKNOWN")).upper(),
                4
            )
            for item in findings
        ]

        self.assertEqual(levels, sorted(levels))

    def test_results_page(self):
        """Flask 결과 화면이 정상적으로 열리는지 확인"""
        client = app.test_client()

        response = client.get("/results")

        self.assertEqual(response.status_code, 200)

        html = response.get_data(as_text=True)

        self.assertIn("보안 검사 결과", html)
        self.assertIn("36건", html)
        self.assertIn("시연용 샘플 데이터", html)


if __name__ == "__main__":
    unittest.main()
