"""Gitleaks 실행과 결과 변환 (기능 1).

흐름: Gitleaks 실행 -> 원본 JSON(키 값 가림) -> 공통 형식(Finding) 변환
공통 형식은 docs/finding-format.md(v1)를 따른다.

키 값 보호:
  1. Gitleaks를 --redact=80으로 실행해 키 전체가 임시 파일에도 남지 않게 한다.
  2. sanitize_raw()가 Secret·Match를 다시 '앞 4자리 + ****'로 바꾼다.
     원본 JSON을 저장하거나 다른 사람에게 넘길 때는 이 결과만 쓴다.

명령줄 사용 (worker 폴더에서):
    python -m scanners.gitleaks <저장소경로> --raw raw.json --out findings.json
    python -m scanners.gitleaks <저장소경로> --readiness readiness.json
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
DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "gitleaks.toml"
REDACT_PERCENT = 80          # Gitleaks가 키의 앞 20%만 남기고 가린다
MASK_VISIBLE = 4             # 공통 형식: 앞 4자리만 남긴다
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# 규칙별 한국어 안내. rule_id는 Gitleaks 기본 규칙 이름 그대로 쓴다.
# 국내 규칙은 worker/gitleaks.toml에 정의한다.
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
    "kr-rrn": {
        "severity": "CRITICAL",
        "title": "주민등록번호 노출",
        "why": "주민등록번호가 공개되면 개인 식별이나 명의 도용에 악용될 수 있습니다.",
        "fix": "1) 실제 번호라면 즉시 삭제하고 당사자에게 알리기 2) 테스트에는 '******-*******'처럼 가린 값 사용 3) Git 기록에서 삭제",
    },
    "kr-mobile": {
        "severity": "HIGH",
        "title": "휴대폰 번호 노출",
        "why": "저장소를 보는 사람 누구나 이 번호로 연락하거나 스팸·피싱에 쓸 수 있습니다.",
        "fix": "1) 실제 번호라면 삭제 2) 테스트에는 010-0000-0000 같은 가짜 번호 사용 3) Git 기록에서 삭제",
    },
    "kr-student-id": {
        "severity": "MEDIUM",
        "title": "학번 노출",
        "why": "학번은 이름·학과와 함께 쓰이면 특정 학생을 식별할 수 있는 정보입니다.",
        "fix": "1) 실제 학번이라면 삭제 2) 테스트에는 2000XXXX 같은 가짜 값 사용 3) Git 기록에서 삭제",
    },
    "kr-service-api-key": {
        "severity": "HIGH",
        "title": "국내 서비스 API 키 노출",
        "why": "카카오·네이버·공공데이터포털 같은 국내 서비스 키입니다. 다른 사람이 이 키로 지도·검색·공공데이터 API를 호출해 할당량을 소진하거나 요금이 청구될 수 있습니다.",
        "fix": "1) 카카오 개발자센터·네이버 개발자센터·공공데이터포털에서 키 재발급 2) 새 키를 .env에 저장 3) Git 기록에서 삭제",
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
        # 검사 대상 저장소의 설정이 worker 규칙을 대체하지 않도록 명시한다.
        config = Path(config_path) if config_path is not None else DEFAULT_CONFIG
        if not config.is_file():
            raise GitleaksError(f"Gitleaks 설정 파일이 없습니다: {config}")
        cmd += ["--config", str(config.resolve())]
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except FileNotFoundError as e:
            raise GitleaksError(f"gitleaks 실행 파일을 찾을 수 없습니다: {GITLEAKS_BIN}") from e
        except subprocess.TimeoutExpired as e:
            raise GitleaksError(f"gitleaks 검사 시간 초과({timeout}초)") from e
        if proc.returncode != 0:
            raise GitleaksError(proc.stderr.strip() or f"gitleaks 종료 코드 {proc.returncode}")
        try:
            raw = json.loads(report.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise GitleaksError("Gitleaks JSON 검사 결과를 읽을 수 없습니다.") from e
        if not isinstance(raw, list):
            raise GitleaksError("Gitleaks JSON 검사 결과는 목록이어야 합니다.")
    return sanitize_raw(raw)


PII_MASK = {"kr-rrn": "******-*******", "kr-mobile": "010-****-****", "kr-student-id": "20******"}


def mask_secret(secret: str, rule_id: str) -> str:
    """공통 형식 규칙: 앞 4자리만 남기고 가린다. 개인 키와 국내 개인정보는 식별 숫자를 남기지 않는다."""
    if rule_id == "private-key" or "PRIVATE KEY" in secret:
        return "****"
    if rule_id in PII_MASK:
        return PII_MASK[rule_id]
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


def assess_public_readiness(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """완료된 Gitleaks 검사 1회의 결과로 공개 판정과 차단 사유를 만든다."""
    reasons = [
        {key: finding[key] for key in ("rule_id", "severity", "file", "line")}
        for finding in findings
    ]
    return {"can_publish": not reasons, "reasons": reasons}


def _main() -> None:
    p = argparse.ArgumentParser(description="Gitleaks 검사 후 공통 형식으로 변환")
    p.add_argument("repo", help="검사할 Git 저장소 경로")
    p.add_argument("--config", help="Gitleaks 설정 파일(.gitleaks.toml)")
    p.add_argument("--raw", help="가린 원본 JSON을 저장할 경로")
    p.add_argument("--out", help="공통 형식 JSON을 저장할 경로 (없으면 화면 출력)")
    p.add_argument("--readiness", help="공개 전환 판정 JSON을 저장할 경로")
    args = p.parse_args()

    if args.readiness:
        try:
            history = subprocess.run(
                ["git", "-C", args.repo, "rev-parse", "--is-shallow-repository"],
                check=True, capture_output=True, text=True, timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            p.error("공개 전환을 판정할 Git 저장소의 이력을 확인할 수 없습니다.")
        if history.stdout.strip() != "false":
            p.error("공개 전환 판정에는 전체 이력을 포함하는 Git 저장소가 필요합니다.")

    raw = run_gitleaks(args.repo, args.config)
    findings = to_findings(raw)
    if args.readiness:
        decision = json.dumps(assess_public_readiness(findings), ensure_ascii=False, indent=2)
        Path(args.readiness).write_text(decision + "\n", encoding="utf-8")
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
