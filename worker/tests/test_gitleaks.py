"""기능 1 Gitleaks 모듈 테스트.

- 변환 테스트: samples/gitleaks-raw.json만 있으면 돌아간다 (gitleaks 설치 불필요)
- 통합 테스트: gitleaks가 설치된 환경(worker 이미지, Actions)에서만 실행
실행: 저장소 루트에서  python -m pytest worker/tests -q
"""

import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "worker"))

from scanners import gitleaks  # noqa: E402

RAW = json.loads((ROOT / "samples" / "gitleaks-raw.json").read_text(encoding="utf-8"))
FIELDS = {"tool", "rule_id", "fingerprint", "severity", "file", "line", "title", "why", "fix", "status"}
EXPECTED = {
    ("aws-access-token", "config/settings.py"),
    ("generic-api-key", "config/settings.py"),
    ("generic-api-key", ".env"),
    ("github-pat", ".env"),
    ("slack-bot-token", "notify/slack.py"),
    ("private-key", "deploy/id_rsa"),
}


def test_findings_follow_format_v1():
    findings = gitleaks.to_findings(RAW)
    assert len(findings) == 6
    for f in findings:
        assert set(f) == FIELDS
        assert f["tool"] == "gitleaks"
        assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert f["status"] == "open"
        assert f["line"] is None or isinstance(f["line"], int)
        assert f["title"] and f["why"] and f["fix"]


def test_expected_rules_and_files():
    findings = gitleaks.to_findings(RAW)
    assert {(f["rule_id"], f["file"]) for f in findings} == EXPECTED


def test_fingerprint_preserved_from_gitleaks():
    findings = gitleaks.to_findings(RAW)
    assert {f["fingerprint"] for f in findings} == {item["Fingerprint"] for item in RAW}
    assert all(isinstance(f["fingerprint"], str) and f["fingerprint"] for f in findings)


def test_sorted_by_severity():
    order = [gitleaks.SEVERITY_ORDER[f["severity"]] for f in gitleaks.to_findings(RAW)]
    assert order == sorted(order)


def test_secret_masked_to_first_four():
    findings = gitleaks.to_findings(RAW)
    aws = next(f for f in findings if f["rule_id"] == "aws-access-token")
    assert aws["title"] == "AWS 접근 키 노출 (AKIA****)"
    for f in findings:
        # 가린 값 외에 키처럼 보이는 긴 문자열이 없어야 한다
        assert not re.search(r"[A-Za-z0-9/+]{12,}", f["title"].split(":")[-1])


def test_mask_secret():
    assert gitleaks.mask_secret("AKIA...", "aws-access-token") == "AKIA****"
    assert gitleaks.mask_secret("ghp_abcdefghijklmnop", "github-pat") == "ghp_****"
    assert gitleaks.mask_secret("-----BEGIN RSA PRIVATE KEY-----\nabc", "private-key") == "****"


def test_raw_sample_has_no_secret_values():
    for item in RAW:
        assert item["Secret"].endswith("****")
        assert "PRIVATE KEY-----" not in item["Match"]


def test_generic_rule_shows_variable_name():
    titles = [f["title"] for f in gitleaks.to_findings(RAW) if f["rule_id"] == "generic-api-key"]
    assert any("DB_PASSWORD" in t for t in titles)


def test_env_file_gets_gitignore_step():
    env = [f for f in gitleaks.to_findings(RAW) if f["file"] == ".env"]
    assert env and all(".gitignore" in f["fix"] for f in env)


def test_unknown_rule_uses_default():
    f = gitleaks.to_finding({"RuleID": "kakao-rest-api-key", "File": "a.py",
                             "StartLine": 3, "Secret": "abcd1234...", "Match": "x",
                             "Fingerprint": "commit:a.py:kakao-rest-api-key:3"})
    assert f["severity"] == "HIGH"
    assert "kakao-rest-api-key" in f["title"] and "abcd****" in f["title"]


def test_duplicates_merged():
    assert len(gitleaks.to_findings(RAW + RAW)) == 6


def test_same_location_with_distinct_fingerprint_is_preserved():
    another_commit = {**RAW[0], "Fingerprint": "another-commit:.env:github-pat:4"}
    assert len(gitleaks.to_findings(RAW + [another_commit])) == 7


@pytest.mark.skipif(shutil.which(gitleaks.GITLEAKS_BIN) is None, reason="gitleaks 미설치")
def test_scan_sample_repo(tmp_path):
    repo = tmp_path / "leaky-repo"
    subprocess.run([sys.executable, str(ROOT / "scripts" / "make_sample_repo.py"), str(repo)], check=True)
    findings = gitleaks.scan(repo)
    assert {(f["rule_id"], f["file"]) for f in findings} == EXPECTED
    assert all(f["fingerprint"] for f in findings)
    # AWS 문서 예시 키는 오탐으로 잡히면 안 된다
    assert all(f["file"] != "docs/aws-example.md" for f in findings)


def test_not_a_repo(tmp_path):
    with pytest.raises(gitleaks.GitleaksError):
        gitleaks.run_gitleaks(tmp_path)
