"""기능 2 Trivy 모듈 테스트.

- 변환 테스트: samples/trivy-raw.json만 있으면 돌아간다 (trivy 설치 불필요)
- 통합 테스트: trivy가 설치된 환경(worker 이미지, Actions)에서만 실행
실행: 저장소 루트에서 python -m pytest worker/tests -q

"""

import json
import re
import sys
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "worker"))

from scanners import trivy  # noqa: E402

RAW = json.loads((ROOT / "samples" / "trivy-raw.json").read_text(encoding="utf-8"))
MAKE_VULN_REPO = ROOT / "scripts" / "make_vuln_repo.py"
FIELDS = {"tool", "rule_id", "fingerprint", "severity", "file", "line", "title", "why", "fix", "status"}
FINGERPRINT_RE = re.compile(r"^trivy:[A-Z]+-[\w-]+:[A-Za-z0-9._-]+:.+$")


def _raw_vulns():
    """원본에 들어 있는 (파일, 취약점) 쌍 목록."""
    return [(r["Target"], v) for r in RAW.get("Results") or [] for v in r.get("Vulnerabilities") or []]


def test_findings_follow_format_v1():
    findings = trivy.to_findings(RAW)
    assert findings
    for f in findings:
        assert set(f) == FIELDS
        assert f["tool"] == "trivy"
        assert f["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        assert f["status"] == "open"
        assert f["line"] is None
        assert f["title"] and f["why"] and f["fix"]


def test_every_vulnerability_converted():
    # 원본의 취약점이 하나도 빠지지 않고 변환된다 (중복만 합쳐짐)
    expected = {(v["VulnerabilityID"], v["PkgName"], file) for file, v in _raw_vulns()}
    findings = trivy.to_findings(RAW)
    assert len(findings) == len(expected)
    assert {(f["rule_id"], f["fingerprint"].split(":")[2], f["file"]) for f in findings} == expected


def test_fingerprint_format():
    for f in trivy.to_findings(RAW):
        assert FINGERPRINT_RE.match(f["fingerprint"])
        pkg = f["fingerprint"].split(":")[2]
        assert f["fingerprint"] == f"trivy:{f['rule_id']}:{pkg}:{f['file']}"


def test_file_is_repo_relative():
    # vuln-repo를 저장소 최상위로 보고 검사했으므로 경로가 requirements.txt로 잡혀야 한다
    assert {f["file"] for f in trivy.to_findings(RAW)} == {"requirements.txt"}


def test_sorted_by_severity():
    order = [trivy.SEVERITY_ORDER[f["severity"]] for f in trivy.to_findings(RAW)]
    assert order == sorted(order)


def test_duplicates_merged():
    doubled = {"Results": (RAW.get("Results") or []) * 2}
    assert len(trivy.to_findings(doubled)) == len(trivy.to_findings(RAW))


def test_same_cve_in_another_file_is_kept():
    file, vuln = _raw_vulns()[0]
    extra = {"Results": (RAW.get("Results") or []) + [{"Target": "backend/requirements.txt", "Vulnerabilities": [vuln]}]}
    assert len(trivy.to_findings(extra)) == len(trivy.to_findings(RAW)) + 1


def test_pick_fixed_version():
    assert trivy.pick_fixed_version("2.20.0") == "2.20.0"
    # 여러 개면 가장 높은 버전 (2.2.5 이상이라고 하면 2.3.0, 2.3.1이 빠져나감)
    assert trivy.pick_fixed_version("2.3.2, 2.2.5") == "2.3.2"
    assert trivy.pick_fixed_version("1.26.19, 2.2.2") == "2.2.2"
    assert trivy.pick_fixed_version("") is None


def test_version_compared_as_numbers():
    # 문자열로 비교하면 '2.10' < '2.9'가 되므로 숫자로 비교해야 한다
    assert trivy._version_key("2.10") > trivy._version_key("2.9")


def test_no_fixed_version_message():
    f = trivy.to_finding({"VulnerabilityID": "CVE-2099-0001", "PkgName": "foo",
                          "InstalledVersion": "1.0", "Severity": "MEDIUM"}, "requirements.txt")
    assert "고쳐진 버전이 없습니다" in f["fix"]


def test_fix_message_has_version():
    f = trivy.to_finding({"VulnerabilityID": "CVE-2018-18074", "PkgName": "requests",
                          "InstalledVersion": "2.19.0", "FixedVersion": "2.20.0",
                          "Severity": "HIGH"}, "requirements.txt")
    assert f["fix"] == "requirements.txt에서 requests 버전을 2.20.0 이상으로 올리세요."
    assert f["fingerprint"] == "trivy:CVE-2018-18074:requests:requirements.txt"


def test_empty_results():
    assert trivy.to_findings({}) == []
    assert trivy.to_findings({"Results": None}) == []
    assert trivy.to_findings({"Results": [{"Target": "go.mod", "Vulnerabilities": None}]}) == []


def test_not_a_directory(tmp_path):
    with pytest.raises(trivy.TrivyError):
        trivy.run_trivy(tmp_path / "없는폴더")


def _make_vuln_repo(dest):
    """scripts/make_vuln_repo.py로 검사 대상 저장소를 만든다."""
    subprocess.run([sys.executable, str(MAKE_VULN_REPO), str(dest)], check=True)
    return dest


def test_make_vuln_repo(tmp_path):
    repo = _make_vuln_repo(tmp_path / "vuln-repo")
    text = (repo / "requirements.txt").read_text(encoding="utf-8")
    assert "flask==0.12.2" in text


def test_raw_sample_matches_script(tmp_path):
    # 커밋된 trivy-raw.json이 스크립트의 패키지 목록으로 만든 결과인지 확인
    repo = _make_vuln_repo(tmp_path / "vuln-repo")
    lines = (repo / "requirements.txt").read_text(encoding="utf-8").split()
    script_pkgs = {line.split("==")[0] for line in lines}
    raw_pkgs = {v["PkgName"] for _, v in _raw_vulns()}
    assert raw_pkgs == script_pkgs


@pytest.mark.skipif(shutil.which(trivy.TRIVY_BIN) is None, reason="trivy 미설치")
def test_scan_sample_repo(tmp_path):
    findings = trivy.scan(_make_vuln_repo(tmp_path / "vuln-repo"))
    assert findings
    assert all(f["file"] == "requirements.txt" for f in findings)
    assert all(FINGERPRINT_RE.match(f["fingerprint"]) for f in findings)