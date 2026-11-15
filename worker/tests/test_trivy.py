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

# ---------- 업그레이드 정리 (summarize_upgrades) ----------

UPGRADE_FIELDS = {"package", "current_version", "recommended_version", "fixed_count", "max_severity",
                  "file", "cves", "unfixed_count", "unfixed_cves", "major_upgrade", "prerelease", "summary"}


def _vuln(cve, pkg="foo", installed="1.0", fixed="", severity="MEDIUM"):
    """테스트용 가짜 취약점 1건."""
    return {"VulnerabilityID": cve, "PkgName": pkg, "InstalledVersion": installed,
            "FixedVersion": fixed, "Severity": severity}


def test_upgrades_grouped_by_package():
    # 샘플의 취약점 30건이 패키지 5개로 묶이고, 해결 수 합계가 원본 건수와 같음
    upgrades = trivy.summarize_upgrades(RAW)
    assert len(upgrades) == len({v["PkgName"] for _, v in _raw_vulns()})
    assert sum(u["fixed_count"] + u["unfixed_count"] for u in upgrades) == len(trivy.to_findings(RAW))
    for u in upgrades:
        assert set(u) == UPGRADE_FIELDS


def test_upgrade_recommends_highest_fixed_version():
    # 고친 버전이 2.0, 2.5, 1.9면 2.5까지 올려야 셋 다 해결
    raw = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        _vuln("CVE-1", fixed="2.0", severity="LOW"),
        _vuln("CVE-2", fixed="2.5, 2.4.9", severity="CRITICAL"),
        _vuln("CVE-3", fixed="1.9", severity="HIGH"),
    ]}]}
    [u] = trivy.summarize_upgrades(raw)
    assert u["recommended_version"] == "2.5"
    assert u["fixed_count"] == 3
    assert u["max_severity"] == "CRITICAL"
    assert u["major_upgrade"] is True          # 1.0 -> 2.5
    assert u["summary"] == "foo을(를) 2.5 버전으로 올리면 3개 해결"


def test_upgrade_excludes_unfixed():
    # 고쳐진 버전이 없는 취약점은 해결 수에서 빠지고, 요약에 무엇이 남는지 적힌다
    raw = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        _vuln("CVE-1", fixed="1.2"),
        _vuln("CVE-2"),
    ]}]}
    [u] = trivy.summarize_upgrades(raw)
    assert (u["fixed_count"], u["unfixed_count"]) == (1, 1)
    assert u["cves"] == ["CVE-1"]
    assert u["unfixed_cves"] == ["CVE-2"]
    assert u["summary"] == "foo을(를) 1.2 버전으로 올리면 1개 해결, 고쳐진 버전이 없는 1개는 남음 - CVE-2(MEDIUM)"

    # 하나도 안 고쳐졌으면 추천 버전은 None
    [u] = trivy.summarize_upgrades({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [_vuln("CVE-2")]}]})
    assert u["recommended_version"] is None
    assert u["summary"] == "foo: 아직 고쳐진 버전이 없음 - CVE-2(MEDIUM)"


def test_upgrades_sorted_by_severity_then_count():
    # 위험도 높은 순 -> 해결 수 많은 순으로 정렬됐는지, 빈 결과면 빈 목록인지
    order = [(trivy.SEVERITY_ORDER[u["max_severity"]], -u["fixed_count"]) for u in trivy.summarize_upgrades(RAW)]
    assert order == sorted(order)
    assert trivy.summarize_upgrades({}) == []

def test_prerelease_lower_than_final():
    # 출시 후보(rc)·베타·알파는 같은 숫자의 정식 버전보다 낮다
    assert trivy._version_key("1.2.0rc1") < trivy._version_key("1.2.0")
    assert trivy._version_key("1.2.0-rc.1") < trivy._version_key("1.2.0")       # npm 형식
    assert (trivy._version_key("1.2.0.dev1") < trivy._version_key("1.2.0a1")
            < trivy._version_key("1.2.0b1") < trivy._version_key("1.2.0rc1")
            < trivy._version_key("1.2.0") < trivy._version_key("1.2.0.post1"))
    assert trivy._version_key("1.2.0rc2") > trivy._version_key("1.2.0rc1")
    assert trivy._version_key("1.2.1rc1") > trivy._version_key("1.2.0")          # 숫자가 먼저
    assert trivy._version_key("2.0") == trivy._version_key("2.0.0")
    assert trivy._version_key("1.2.0+cpu") == trivy._version_key("1.2.0")       # 꼬리표는 정식 버전


def test_pick_fixed_version_prefers_final():
    assert trivy.pick_fixed_version("1.2.0rc1, 1.2.0") == "1.2.0"
    assert trivy.pick_fixed_version("1.2.0, 1.2.0rc1") == "1.2.0"
    assert trivy.pick_fixed_version("2.0.0rc1") == "2.0.0rc1"     # rc밖에 없으면 rc


def test_upgrade_does_not_recommend_rc_over_final():
    # 리뷰 피드백: 1.2.0rc1과 1.2.0이 있으면 정식 1.2.0을 추천
    raw = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        _vuln("CVE-1", fixed="1.2.0rc1"),
        _vuln("CVE-2", fixed="1.2.0"),
    ]}]}
    [u] = trivy.summarize_upgrades(raw)
    assert u["recommended_version"] == "1.2.0"
    assert u["major_upgrade"] is False      # 1.0 -> 1.2.0

def test_upgrade_flags_prerelease_recommendation():
    # 고친 버전이 rc밖에 없으면 추천은 하되, 출시 전 버전이라고 알려 준다
    raw = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [_vuln("CVE-1", fixed="2.0.0rc1")]}]}
    [u] = trivy.summarize_upgrades(raw)
    assert u["recommended_version"] == "2.0.0rc1"
    assert u["prerelease"] is True
    assert "출시 전 버전" in u["summary"]
    # 샘플은 전부 정식 버전 추천
    assert all(u["prerelease"] is False for u in trivy.summarize_upgrades(RAW))


def test_upgrade_summary_names_remaining_cves():
    # 남는 CVE는 위험도 높은 순으로 이름과 위험도를 보여 주고, 3개가 넘으면 '외 N개'로 줄인다
    raw = {"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        _vuln("CVE-1", fixed="1.1", severity="LOW"),
        _vuln("CVE-9", severity="LOW"),
        _vuln("CVE-8", severity="CRITICAL"),
        _vuln("CVE-7", severity="MEDIUM"),
        _vuln("CVE-6", severity="HIGH"),
        _vuln("CVE-5", severity="HIGH"),
    ]}]}
    [u] = trivy.summarize_upgrades(raw)
    assert u["unfixed_cves"] == ["CVE-8", "CVE-5", "CVE-6", "CVE-7", "CVE-9"]
    assert u["max_severity"] == "CRITICAL"
    assert u["summary"] == ("foo을(를) 1.1 버전으로 올리면 1개 해결, 고쳐진 버전이 없는 5개는 남음 - "
                            "CVE-8(CRITICAL), CVE-5(HIGH), CVE-6(HIGH) 외 2개")

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