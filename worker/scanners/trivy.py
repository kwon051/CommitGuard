"""Trivy 실행과 결과 변환 (기능 2).

흐름: Trivy 실행 -> 원본 JSON -> 공통 형식(Finding) 변환
공통 형식은 docs/finding-format.md(v1)를 따른다.

fingerprint 규칙 (finding-format.md):
    trivy:CVE번호:패키지명:파일
    파일은 검사한 저장소 최상위 기준 경로 (예: requirements.txt, backend/requirements.txt)

명령줄 사용 (worker 폴더에서):
    python -m scanners.trivy <저장소경로> --raw raw.json --out findings.json
    python -m scanners.trivy --from-raw raw.json --out findings.json   (Trivy 없이 변환만)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

TRIVY_BIN = os.environ.get("TRIVY_BIN", "trivy")
# 취약점 DB 위치. compose의 trivy-cache 볼륨을 이 경로에 붙인다.
TRIVY_CACHE_DIR = os.environ.get("TRIVY_CACHE_DIR", "/root/.cache/trivy")
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}


class TrivyError(RuntimeError):
    """Trivy 실행 자체가 실패했을 때 (취약점 발견은 오류가 아니다)."""


def run_trivy(repo_path: str | Path, timeout: int = 600) -> dict[str, Any]:
    """저장소 폴더를 검사하고 Trivy 원본 결과(dict)를 돌려준다."""
    repo = Path(repo_path)
    if not repo.is_dir():
        raise TrivyError(f"검사할 폴더가 없음: {repo}")

    cmd = [
        TRIVY_BIN, "fs", str(repo),
        "--scanners", "vuln",          # 취약점만 (비밀키는 Gitleaks 담당)
        "--format", "json",            # 결과를 JSON으로
        "--quiet",                     # 진행 로그 끄기 -> stdout에 JSON만 나옴
        "--cache-dir", TRIVY_CACHE_DIR,
        "--exit-code", "0",            # 취약점이 있어도 0, 실행 오류만 0이 아님
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              encoding="utf-8", timeout=timeout)
    except FileNotFoundError as e:
        raise TrivyError(f"trivy가 설치되어 있지 않음 ({TRIVY_BIN})") from e
    except subprocess.TimeoutExpired as e:
        raise TrivyError(f"trivy 검사가 {timeout}초 안에 끝나지 않음") from e
    if proc.returncode != 0:
        raise TrivyError(proc.stderr.strip() or f"trivy 실패 (exit {proc.returncode})")
    return json.loads(proc.stdout) if proc.stdout.strip() else {"Results": []}


def make_fingerprint(cve: str, pkg: str, file: str) -> str:
    """공통 형식 규칙: trivy:CVE번호:패키지명:파일"""
    return f"trivy:{cve}:{pkg}:{file}"


def _version_key(version: str) -> tuple[int, ...]:
    """'2.10.1' -> (2, 10, 1). 문자열 비교로는 '2.10' < '2.9'가 되어서 숫자로 바꾼다."""
    return tuple(int(n) for n in re.findall(r"\d+", version))


def pick_fixed_version(fixed: str) -> str | None:
    """'2.3.2, 2.2.5'처럼 여러 개면 가장 높은 버전을 고른다.
    버전 줄기마다 따로 패치된 경우라서, 낮은 쪽(2.2.5)을 '이상'으로 안내하면
    그 사이 버전(2.3.0, 2.3.1)은 여전히 취약하다. 가장 높은 버전이어야 '이상'이 맞다."""
    candidates = [v.strip() for v in fixed.split(",") if v.strip()]
    if not candidates:
        return None
    return max(candidates, key=_version_key)


def to_finding(vuln: dict[str, Any], file: str) -> dict[str, Any]:
    """Trivy 취약점 1건을 공통 형식 v1 dict로 바꾼다."""
    cve = vuln.get("VulnerabilityID", "unknown")
    pkg = vuln.get("PkgName", "unknown")
    installed = vuln.get("InstalledVersion", "")
    fixed = pick_fixed_version(vuln.get("FixedVersion", ""))
    severity = vuln.get("Severity", "UNKNOWN").upper()

    # 한국어 안내는 임시 문장. 11/22에 기능 3(김기령)의 템플릿으로 바뀔 수 있다.
    title = f"{pkg} {installed} 버전에 알려진 취약점 ({cve})"
    why = f"이 버전에는 공개된 취약점이 있어 공격에 악용될 수 있습니다. (원문: {vuln.get('Title', '설명 없음')})"
    if fixed:
        fix = f"{file}에서 {pkg} 버전을 {fixed} 이상으로 올리세요."
    else:
        fix = f"아직 고쳐진 버전이 없습니다. {pkg} 대신 쓸 수 있는 패키지를 검토하세요."

    return {
        "tool": "trivy",
        "rule_id": cve,
        "fingerprint": make_fingerprint(cve, pkg, file),
        "severity": severity if severity in SEVERITY_ORDER else "UNKNOWN",
        "file": file,
        "line": None,                  # Trivy 취약점 결과에는 줄 번호가 없다
        "title": title,
        "why": why,
        "fix": fix,
        "status": "open",
    }


def to_findings(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """원본 전체를 변환하고, 같은 fingerprint의 중복을 합친 뒤 위험도 순으로 정렬한다."""
    seen: set[str] = set()
    findings = []
    # Results: 검사한 파일마다 1개. 취약점이 없으면 Vulnerabilities가 없거나 null이다.
    for result in raw.get("Results") or []:
        file = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            f = to_finding(vuln, file)
            if f["fingerprint"] in seen:
                continue
            seen.add(f["fingerprint"])
            findings.append(f)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["rule_id"]))
    return findings


def scan(repo_path: str | Path) -> list[dict[str, Any]]:
    """worker가 호출하는 진입점: 저장소 경로 -> 공통 형식 목록."""
    return to_findings(run_trivy(repo_path))


def _main() -> None:
    p = argparse.ArgumentParser(description="Trivy 검사 결과를 공통 형식으로 변환")
    p.add_argument("repo", nargs="?", help="검사할 저장소 폴더")
    p.add_argument("--from-raw", help="Trivy 없이 기존 원본 JSON을 변환")
    p.add_argument("--raw", help="원본 JSON 저장 경로")
    p.add_argument("--out", help="공통 형식 JSON 저장 경로 (생략하면 화면에 출력)")
    args = p.parse_args()

    if args.from_raw:
        raw = json.loads(Path(args.from_raw).read_text(encoding="utf-8"))
    elif args.repo:
        raw = run_trivy(args.repo)
    else:
        p.error("저장소 폴더나 --from-raw를 지정하세요")

    findings = to_findings(raw)
    if args.raw:
        Path(args.raw).write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    text = json.dumps(findings, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    total = sum(len(r.get("Vulnerabilities") or []) for r in raw.get("Results") or [])
    print(f"[trivy] 원본 {total}건 -> 공통 형식 {len(findings)}건", file=sys.stderr)


if __name__ == "__main__":
    _main()