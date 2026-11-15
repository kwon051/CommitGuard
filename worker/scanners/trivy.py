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


# 같은 숫자 버전 안에서의 순서: dev < alpha < beta < rc < 정식 < post
# 예) 1.2.0.dev1 < 1.2.0a1 < 1.2.0b1 < 1.2.0rc1 < 1.2.0 < 1.2.0.post1
_PRE_STAGE = {"dev": 0, "alpha": 1, "a": 1, "beta": 2, "b": 2,
              "preview": 3, "pre": 3, "rc": 3, "c": 3}
_FINAL_STAGE = 4
_POST_STAGE = 5
# alpha가 a보다, preview가 pre보다 먼저 와야 긴 이름이 통째로 잡힌다
_STAGE_RE = re.compile(r"[.-]?(dev|alpha|beta|preview|pre|rc|post|a|b|c)[.-]?(\d*)")


def _version_key(version: str) -> tuple[tuple[int, ...], int, int]:
    """버전 문자열을 비교용 값으로 바꾼다.

    '2.10'      -> ((2, 10), 4, 0)     문자열 비교로는 '2.10' < '2.9'가 되어서 숫자로 바꾼다
    '1.2.0rc1'  -> ((1, 2), 3, 1)      출시 후보(rc)는 정식 1.2.0보다 낮다
    '1.2.0-rc.1'-> ((1, 2), 3, 1)      npm 형식도 같은 값
    '1.2.0'     -> ((1, 2), 4, 0)
    끝의 0은 지운다: '2.0'과 '2.0.0'은 같은 버전이다.
    """
    v = version.strip().lower().lstrip("v")
    m = re.match(r"(\d+(?:\.\d+)*)(.*)", v)
    if not m:
        return ((), _FINAL_STAGE, 0)
    release = tuple(int(n) for n in m.group(1).split("."))
    while len(release) > 1 and release[-1] == 0:
        release = release[:-1]

    # 숫자 바로 뒤에 붙은 rc1, -beta.2, .post1 등만 본다 ('+cpu' 같은 꼬리표의 c를 rc로 오해하지 않게)
    tag = _STAGE_RE.match(m.group(2))
    if not tag:
        return (release, _FINAL_STAGE, 0)
    stage = _POST_STAGE if tag.group(1) == "post" else _PRE_STAGE[tag.group(1)]
    return (release, stage, int(tag.group(2) or 0))


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

def _is_major_upgrade(current: str, recommended: str) -> bool:
    """첫 번째 숫자(메이저 버전)가 바뀌면 True. 예: 0.12.2 -> 3.1.3
    메이저가 바뀌면 사용법이 달라져 코드가 깨질 수 있어서 따로 표시"""
    cur, rec = _version_key(current)[0], _version_key(recommended)[0]
    return bool(cur and rec) and cur[0] != rec[0]

UNFIXED_SHOW_MAX = 3   # 요약 문장에 남는 CVE를 몇 개까지 이름으로 보여줄지


def _upgrade_summary(pkg: str, recommended: str | None, fixed: int,
                     unfixed: list[tuple[str, str]], prerelease: bool) -> str:
    """화면에 바로 쓸 한 줄 요약.

    올려도 남는 취약점이 있으면 무엇인지(CVE와 위험도)까지 같이 적는다.
    안 그러면 '올리면 해결'만 보고 전부 안전해진 줄 안다.
    unfixed: [(CVE, 위험도), ...] 위험도 높은 순으로 정렬된 목록
    """
    left = ""
    if unfixed:
        names = ", ".join(f"{cve}({sev})" for cve, sev in unfixed[:UNFIXED_SHOW_MAX])
        more = f" 외 {len(unfixed) - UNFIXED_SHOW_MAX}개" if len(unfixed) > UNFIXED_SHOW_MAX else ""
        left = f"{names}{more}"

    if not recommended:
        return f"{pkg}: 아직 고쳐진 버전이 없음 - {left}"
    text = f"{pkg}을(를) {recommended} 버전으로 올리면 {fixed}개 해결"
    if prerelease:
        text += " (출시 전 버전이라 정식 버전이 나오면 그 버전 권장)"
    if unfixed:
        text += f", 고쳐진 버전이 없는 {len(unfixed)}개는 남음 - {left}"
    return text

def summarize_upgrades(raw: dict[str, Any]) -> list[dict[str, Any]]:
    """같은 패키지의 취약점을 묶어 'X를 Y 버전으로 올리면 N개 해결' 목록을 만든다.

    묶는 기준: (파일, 패키지명, 현재 버전)
    추천 버전: 묶인 취약점들의 고친 버전 중 가장 높은 것 (그래야 전부 해결된다)
    고쳐진 버전이 없는 취약점은 해결 수에서 빼고 unfixed_count로 따로 센다.
    """
    groups: dict[tuple[str, str, str], dict[str, Any]] = {}
    for result in raw.get("Results") or []:
        file = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            pkg = vuln.get("PkgName", "unknown")
            installed = vuln.get("InstalledVersion", "")
            g = groups.setdefault((file, pkg, installed), {
                "fixed": [],          # 고친 버전 목록
                "cves": [],           # 고친 버전이 있는 CVE (중복 제거용)
                "unfixed": {},        # 고친 버전이 없는 CVE -> 위험도
                "severities": [],
            })
            cve = vuln.get("VulnerabilityID", "unknown")
            if cve in g["cves"] or cve in g["unfixed"]:
                continue              # 같은 CVE가 두 번 나오면 한 번만 센다
            sev = vuln.get("Severity", "UNKNOWN").upper()
            sev = sev if sev in SEVERITY_ORDER else "UNKNOWN"
            g["severities"].append(sev)
            fixed = pick_fixed_version(vuln.get("FixedVersion", ""))
            if fixed:
                g["fixed"].append(fixed)
                g["cves"].append(cve)
            else:
                g["unfixed"][cve] = sev

    upgrades = []
    for (file, pkg, installed), g in groups.items():
        recommended = max(g["fixed"], key=_version_key) if g["fixed"] else None
        prerelease = bool(recommended) and _version_key(recommended)[1] < _FINAL_STAGE
        # 남는 CVE를 위험도 높은 순으로 (같으면 CVE 번호 순)
        unfixed = sorted(g["unfixed"].items(), key=lambda kv: (SEVERITY_ORDER[kv[1]], kv[0]))
        upgrades.append({
            # --- 명세 필수 항목 5개 ---
            "package": pkg,
            "current_version": installed,
            "recommended_version": recommended,           # 고친 버전이 하나도 없으면 null
            "fixed_count": len(g["cves"]),                # 올리면 해결되는 취약점 수
            "max_severity": min(g["severities"], key=SEVERITY_ORDER.get),   # 해결 안 되는 것 포함
            # --- 추가 항목 ---
            "file": file,
            "cves": sorted(g["cves"]),                    # 올리면 해결되는 CVE
            "unfixed_count": len(g["unfixed"]),
            "unfixed_cves": [cve for cve, _ in unfixed],  # 올려도 남는 CVE (위험도 높은 순)
            "major_upgrade": bool(recommended) and _is_major_upgrade(installed, recommended),
            "prerelease": prerelease,                     # 추천 버전이 rc·beta 같은 출시 전 버전
            "summary": _upgrade_summary(pkg, recommended, len(g["cves"]), unfixed, prerelease),
        })
    # 위험도 높은 순 -> 해결 수 많은 순 -> 패키지 이름 순
    upgrades.sort(key=lambda u: (SEVERITY_ORDER[u["max_severity"]], -u["fixed_count"], u["package"]))
    return upgrades

def scan(repo_path: str | Path) -> list[dict[str, Any]]:
    """worker가 호출하는 진입점: 저장소 경로 -> 공통 형식 목록."""
    return to_findings(run_trivy(repo_path))


def _main() -> None:
    p = argparse.ArgumentParser(description="Trivy 검사 결과를 공통 형식으로 변환")
    p.add_argument("repo", nargs="?", help="검사할 저장소 폴더")
    p.add_argument("--from-raw", help="Trivy 없이 기존 원본 JSON을 변환")
    p.add_argument("--raw", help="원본 JSON 저장 경로")
    p.add_argument("--out", help="공통 형식 JSON 저장 경로 (생략하면 화면에 출력)")
    p.add_argument("--upgrades", help="업그레이드 정리 JSON 저장 경로") 
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

    # 업그레이드 정리 결과 저장
    if args.upgrades:
        upgrades = summarize_upgrades(raw)
        Path(args.upgrades).write_text(json.dumps(upgrades, ensure_ascii=False, indent=2) + "\n",
                                       encoding="utf-8")
        print(f"[trivy] 업그레이드 정리 {len(upgrades)}개 패키지", file=sys.stderr)


if __name__ == "__main__":
    _main()