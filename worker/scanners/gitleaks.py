"""Gitleaks 실행과 결과 변환 (기능 1).

흐름: Gitleaks 실행 -> 원본 JSON(키 값 가림) -> 공통 형식(Finding) 변환
공통 형식은 docs/finding-format.md(v1)를 따른다.

키 값 보호:
  1. Gitleaks를 --redact=80으로 실행해 키 전체가 임시 파일에도 남지 않게 한다.
  2. sanitize_raw()가 Secret·Match를 다시 '앞 4자리 + ****'로 바꾼다.
     원본 JSON을 저장하거나 다른 사람에게 넘길 때는 이 결과만 쓴다.

명령줄 사용 (worker 폴더에서):
    python -m scanners.gitleaks <저장소경로> --raw raw.json --out findings.json
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

GITLEAKS_BIN = os.environ.get("GITLEAKS_BIN", "gitleaks")
REDACT_PERCENT = 80          # Gitleaks가 키의 앞 20%만 남기고 가린다
MASK_VISIBLE = 4             # 공통 형식: 앞 4자리만 남긴다
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# 규칙별 한국어 안내. rule_id는 Gitleaks 기본 규칙 이름 그대로 쓴다.
# (한국형 규칙은 11/15 작업에서 이 표에 추가한다)
_REVOKE_GENERIC = "1) 발급한 곳에서 키 폐기 2) 새 키를 발급해 .env에 저장 3) Git 기록에서 삭제"
RULES: dict[str, dict[str, str]] = {
    "aws-access-token": {
        "severity": "CRITICAL",
        "title": "AWS 접근 키 노출",
        "why": "저장소를 볼 수 있는 사람은 누구나 이 키로 AWS 계정을 사용할 수 있습니다. 서버를 몰래 띄워 요금이 청구될 수 있습니다.",
        "fix": "1) AWS 콘솔 IAM에서 키 비활성화·삭제 2) 새 키 발급 후 .env에 저장 3) Git 기록에서 삭제",
    },
    "github-pat": {
        "severity": "CRITICAL",
        "title": "GitHub 개인 접근 토큰 노출",
        "why": "이 토큰으로 내 GitHub 계정의 저장소를 읽거나 수정할 수 있습니다.",
        "fix": "1) GitHub Settings > Developer settings > Tokens에서 토큰 삭제 2) 필요한 권한만 준 새 토큰 발급 후 .env에 저장 3) Git 기록에서 삭제",
    },
    "github-fine-grained-pat": {
        "severity": "CRITICAL",
        "title": "GitHub 세분화 접근 토큰 노출",
        "why": "토큰에 허용된 저장소를 읽거나 수정할 수 있습니다.",
        "fix": "1) GitHub Settings > Developer settings > Tokens에서 토큰 삭제 2) 새 토큰 발급 후 .env에 저장 3) Git 기록에서 삭제",
    },
    "github-oauth": {
        "severity": "HIGH",
        "title": "GitHub OAuth 토큰 노출",
        "why": "토큰 주인의 권한으로 GitHub API를 호출할 수 있습니다.",
        "fix": _REVOKE_GENERIC,
    },
    "github-app-token": {
        "severity": "HIGH",
        "title": "GitHub App 토큰 노출",
        "why": "앱에 허용된 권한으로 저장소에 접근할 수 있습니다.",
        "fix": _REVOKE_GENERIC,
    },
    "gcp-api-key": {
        "severity": "HIGH",
        "title": "Google Cloud API 키 노출",
        "why": "다른 사람이 이 키로 Google API를 호출해 할당량을 쓰거나 요금이 청구될 수 있습니다.",
        "fix": "1) Google Cloud 콘솔 > 사용자 인증 정보에서 키 삭제 2) 새 키 발급 후 사용 API·도메인 제한 설정 3) Git 기록에서 삭제",
    },
    "openai-api-key": {
        "severity": "CRITICAL",
        "title": "OpenAI API 키 노출",
        "why": "다른 사람이 이 키로 모델을 호출하면 사용 요금이 내 계정에 청구됩니다.",
        "fix": "1) OpenAI 대시보드에서 키 삭제 2) 새 키 발급 후 .env에 저장 3) Git 기록에서 삭제",
    },
    "anthropic-api-key": {
        "severity": "CRITICAL",
        "title": "Anthropic API 키 노출",
        "why": "다른 사람이 이 키로 모델을 호출하면 사용 요금이 내 계정에 청구됩니다.",
        "fix": "1) Anthropic 콘솔에서 키 삭제 2) 새 키 발급 후 .env에 저장 3) Git 기록에서 삭제",
    },
    "slack-bot-token": {
        "severity": "HIGH",
        "title": "Slack 봇 토큰 노출",
        "why": "이 토큰으로 워크스페이스에 메시지를 보내거나 대화 내용을 읽을 수 있습니다.",
        "fix": "1) Slack 앱 설정에서 토큰 재발급(기존 토큰 폐기) 2) 새 토큰을 .env에 저장 3) Git 기록에서 삭제",
    },
    "slack-user-token": {
        "severity": "HIGH",
        "title": "Slack 사용자 토큰 노출",
        "why": "토큰 주인처럼 워크스페이스의 메시지를 읽고 보낼 수 있습니다.",
        "fix": _REVOKE_GENERIC,
    },
    "slack-webhook-url": {
        "severity": "MEDIUM",
        "title": "Slack 웹훅 주소 노출",
        "why": "누구나 이 주소로 채널에 메시지를 보낼 수 있습니다(스팸·피싱).",
        "fix": "1) Slack 앱 설정에서 웹훅 삭제 후 새로 만들기 2) 주소를 .env에 저장 3) Git 기록에서 삭제",
    },
    "discord-api-token": {
        "severity": "HIGH",
        "title": "Discord 봇 토큰 노출",
        "why": "다른 사람이 봇을 조종해 서버에 메시지를 보내거나 관리 작업을 할 수 있습니다.",
        "fix": "1) Discord 개발자 포털에서 토큰 Reset 2) 새 토큰을 .env에 저장 3) Git 기록에서 삭제",
    },
    "telegram-bot-api-token": {
        "severity": "HIGH",
        "title": "Telegram 봇 토큰 노출",
        "why": "다른 사람이 봇을 조종해 메시지를 보내거나 받을 수 있습니다.",
        "fix": "1) BotFather에서 /revoke로 토큰 재발급 2) 새 토큰을 .env에 저장 3) Git 기록에서 삭제",
    },
    "stripe-access-token": {
        "severity": "CRITICAL",
        "title": "Stripe 결제 키 노출",
        "why": "결제 정보 조회나 환불 같은 결제 작업에 쓰일 수 있습니다.",
        "fix": "1) Stripe 대시보드에서 키 Roll(재발급) 2) 새 키를 .env에 저장 3) Git 기록에서 삭제",
    },
    "private-key": {
        "severity": "CRITICAL",
        "title": "개인 키 파일 노출",
        "why": "이 키로 서버에 접속하거나 서명·암호화를 흉내 낼 수 있습니다. 개인 키는 절대 저장소에 두면 안 됩니다.",
        "fix": "1) 이 키를 쓰는 서버·서비스에서 공개 키 등록 해제 2) 새 키 쌍을 만들어 저장소 밖에 보관 3) Git 기록에서 삭제",
    },
    "jwt": {
        "severity": "MEDIUM",
        "title": "JWT 토큰 노출",
        "why": "만료되지 않은 토큰이라면 토큰 주인으로 로그인한 것처럼 요청할 수 있습니다.",
        "fix": "1) 서명 키를 교체해 기존 토큰 무효화 2) 코드에서 토큰 제거 3) Git 기록에서 삭제",
    },
    "generic-api-key": {
        "severity": "HIGH",
        "title": "비밀번호·API 키 값 노출",
        "why": "비밀번호나 키로 보이는 값이 코드에 그대로 적혀 있어, 저장소를 보는 사람 누구나 쓸 수 있습니다.",
        "fix": "1) 해당 비밀번호·키 변경 2) 코드 대신 .env에 저장하고 os.environ으로 읽기 3) Git 기록에서 삭제",
    },
}

DEFAULT_RULE = {
    "severity": "HIGH",
    "title": "비밀정보 노출",
    "why": "API 키나 토큰으로 보이는 값이 저장소에 들어 있습니다. 저장소를 보는 사람 누구나 쓸 수 있습니다.",
    "fix": _REVOKE_GENERIC,
}

ENV_FILE_FIX = " 4) .gitignore에 .env 추가"
_IDENT_RE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_.-]*)\s*[:=]")


class GitleaksError(RuntimeError):
    """Gitleaks 실행 자체가 실패했을 때 (누출 발견은 오류가 아니다)."""


def run_gitleaks(repo_path: str | Path, config_path: str | Path | None = None,
                 timeout: int = 300) -> list[dict[str, Any]]:
    """저장소의 Git 이력 전체를 검사하고 Gitleaks 원본 결과 목록을 돌려준다."""
    repo = Path(repo_path)
    if not (repo / ".git").exists():
        raise GitleaksError(f"Git 저장소가 아닙니다: {repo}")

    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "report.json"
        cmd = [
            GITLEAKS_BIN, "git", str(repo),
            "--no-banner",
            f"--redact={REDACT_PERCENT}",
            "--report-format", "json",
            "--report-path", str(report),
            "--exit-code", "0",          # 누출이 있어도 0, 실행 오류만 0이 아님
            "--log-level", "error",
        ]
        if config_path:
            cmd += ["--config", str(config_path)]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as e:
            raise GitleaksError(f"gitleaks 실행 파일을 찾을 수 없습니다: {GITLEAKS_BIN}") from e
        except subprocess.TimeoutExpired as e:
            raise GitleaksError(f"gitleaks 검사 시간 초과({timeout}초)") from e
        if proc.returncode != 0:
            raise GitleaksError(proc.stderr.strip() or f"gitleaks 종료 코드 {proc.returncode}")
        text = report.read_text(encoding="utf-8").strip() if report.exists() else ""
        raw = json.loads(text) if text else []
    return sanitize_raw(raw)


def mask_secret(secret: str, rule_id: str) -> str:
    """공통 형식 규칙: 앞 4자리만 남기고 가린다. 개인 키는 전부 가린다."""
    if rule_id == "private-key" or "PRIVATE KEY" in secret:
        return "****"
    visible = secret.split("...")[0][:MASK_VISIBLE]   # Gitleaks 가림 표시(...) 제거
    return f"{visible}****"


def sanitize_raw(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """원본 결과의 Secret·Match에서 키 값을 가린다. 나머지 필드는 그대로 둔다."""
    clean = []
    for item in raw:
        item = dict(item)
        secret = str(item.get("Secret", ""))
        masked = mask_secret(secret, item.get("RuleID", ""))
        match = str(item.get("Match", ""))
        if item.get("RuleID") == "private-key" or "PRIVATE KEY" in match:
            item["Match"] = "[PRIVATE KEY REDACTED]"
        elif secret and secret in match:
            item["Match"] = match.replace(secret, masked)
        else:
            item["Match"] = masked
        item["Secret"] = masked
        clean.append(item)
    return clean


def _identifier(match: str) -> str | None:
    """'DB_PASSWORD=...' 같은 Match에서 변수 이름을 뽑는다."""
    m = _IDENT_RE.match(match)
    return m.group(1) if m else None


def to_finding(item: dict[str, Any]) -> dict[str, Any]:
    """Gitleaks 결과 1건을 공통 형식 v1 dict로 바꾼다."""
    rule_id = item.get("RuleID", "unknown")
    info = RULES.get(rule_id, DEFAULT_RULE)
    file = item.get("File", "")
    masked = mask_secret(str(item.get("Secret", "")), rule_id)

    title = info["title"]
    if rule_id not in RULES:
        title = f"{title} ({rule_id})"
    if rule_id == "generic-api-key":
        name = _identifier(str(item.get("Match", "")))
        if name:
            title = f"{title}: {name}"
    if rule_id != "private-key":
        title = f"{title} ({masked})"

    fix = info["fix"]
    if Path(file).name == ".env" or Path(file).name.startswith(".env."):
        fix += ENV_FILE_FIX

    line = item.get("StartLine")
    return {
        "tool": "gitleaks",
        "rule_id": rule_id,
        "fingerprint": item["Fingerprint"],
        "severity": info["severity"],
        "file": file,
        "line": line if isinstance(line, int) and line > 0 else None,
        "title": title,
        "why": info["why"],
        "fix": fix,
        "status": "open",
    }


def to_findings(raw: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """원본 목록 전체를 변환하고, 같은 fingerprint의 중복을 합친 뒤 위험도 순으로 정렬한다."""
    seen: set[str] = set()
    findings = []
    for item in sanitize_raw(raw):
        f = to_finding(item)
        key = f["fingerprint"]
        if key in seen:
            continue
        seen.add(key)
        findings.append(f)
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["file"], f["line"] or 0))
    return findings


def scan(repo_path: str | Path, config_path: str | Path | None = None) -> list[dict[str, Any]]:
    """worker가 호출하는 진입점: 저장소 경로 -> 공통 형식 목록."""
    return to_findings(run_gitleaks(repo_path, config_path))


def _main() -> None:
    p = argparse.ArgumentParser(description="Gitleaks 검사 후 공통 형식으로 변환")
    p.add_argument("repo", help="검사할 Git 저장소 경로")
    p.add_argument("--config", help="Gitleaks 설정 파일(.gitleaks.toml)")
    p.add_argument("--raw", help="가린 원본 JSON을 저장할 경로")
    p.add_argument("--out", help="공통 형식 JSON을 저장할 경로 (없으면 화면 출력)")
    args = p.parse_args()

    raw = run_gitleaks(args.repo, args.config)
    findings = to_findings(raw)
    if args.raw:
        Path(args.raw).write_text(json.dumps(raw, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    text = json.dumps(findings, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    print(f"[gitleaks] 원본 {len(raw)}건 -> 공통 형식 {len(findings)}건", file=sys.stderr)


if __name__ == "__main__":
    _main()
