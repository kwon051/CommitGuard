"""PR 자동 댓글 (기능 3)

공통 형식 검사 결과를 요약해서 GitHub Pull Request에 댓글로 단다.
같은 PR에 다시 실행하면 새 댓글을 달지 않고, 이전 CommitGuard 댓글을 고친다.

사용 예)
  # 댓글 내용만 화면에 출력 (토큰 없이 확인용)
  python worker/pr_comment.py samples/gitleaks-findings.json \
      samples/trivy-findings.json --dry-run

  # 실제로 PR에 댓글 달기 (GITHUB_TOKEN 환경변수 필요)
  python worker/pr_comment.py gitleaks.json trivy.json \
      --repo kwon051/CommitGuard --pr 12
"""

import argparse
import json
import os
import urllib.request

import aggregator

MARKER = "<!-- commitguard-report -->"
API = "https://api.github.com"

SEVERITY_LABEL = {
    "CRITICAL": "🔴 CRITICAL (매우 위험)",
    "HIGH": "🟠 HIGH (높음)",
    "MEDIUM": "🟡 MEDIUM (보통)",
    "LOW": "🟢 LOW (낮음)",
    "UNKNOWN": "⚪ UNKNOWN (미분류)",
}


def cell(value):
    """표 칸에 넣을 글자: 줄바꿈과 | 를 정리한다."""
    text = "" if value is None else str(value)
    return text.replace("\n", " ").replace("|", "\\|")


def build_comment(findings, max_items=10):
    """검사 결과(merge 된 목록)로 PR 댓글 내용(마크다운)을 만든다."""
    lines = [MARKER, "## 🔒 CommitGuard 보안 검사 결과", ""]
    if not findings:
        lines.append("✅ 발견된 보안 문제가 없습니다.")
        return "\n".join(lines)

    counts = aggregator.summarize(findings)
    lines += [
        f"발견된 보안 항목: **{len(findings)}건**",
        "",
        "| 위험도 | 건수 |",
        "|---|---|",
    ]
    for severity, count in counts.items():
        if count:
            lines.append(f"| {SEVERITY_LABEL[severity]} | {count} |")

    shown = min(max_items, len(findings))
    lines += [
        "",
        f"### 먼저 고칠 항목 (위험도 순 {shown}건)",
        "",
        "| 위험도 | 내용 | 위치 | 해결 방법 |",
        "|---|---|---|---|",
    ]
    for f in findings[:max_items]:
        where = (
            f["file"]
            if f["line"] in (None, "")
            else f"{f['file']}:{f['line']}"
        )
        row = [cell(f["severity"]), cell(f["title"]),
               f"`{cell(where)}`", cell(f["fix"])]
        lines.append("| " + " | ".join(row) + " |")
    if len(findings) > max_items:
        lines += [
            "",
            f"외 {len(findings) - max_items}건은 CommitGuard 결과 화면에서 확인하세요.",
        ]

    lines += ["", "> 키 값은 앞 4자리만 남기고 가려서 표시합니다."]
    return "\n".join(lines)


def github_request(method, url, token, data=None):
    """GitHub API를 호출하고 JSON 응답을 돌려준다."""
    body = json.dumps(data).encode("utf-8") if data is not None else None
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8") or "null")


def post_comment(repo, pr_number, body, token, request=github_request):
    """PR에 댓글을 단다. 이전 CommitGuard 댓글이 있으면 그 댓글을 고친다."""
    url = f"{API}/repos/{repo}/issues/{pr_number}/comments"
    existing = request("GET", url + "?per_page=100", token) or []
    for comment in existing:
        if MARKER in (comment.get("body") or ""):
            request(
                "PATCH",
                f"{API}/repos/{repo}/issues/comments/{comment['id']}",
                token,
                {"body": body},
            )
            return "updated"
    request("POST", url, token, {"body": body})
    return "created"


def main(argv=None):
    parser = argparse.ArgumentParser(description="CommitGuard PR 자동 댓글")
    parser.add_argument("files", nargs="+", help="공통 형식 JSON 파일들")
    parser.add_argument("--repo", help="저장소 (예: kwon051/CommitGuard)")
    parser.add_argument("--pr", type=int, help="PR 번호")
    parser.add_argument(
        "--max-items", type=int, default=10, help="표에 보여 줄 최대 건수"
    )
    parser.add_argument(
        "--dry-run", action="store_true", help="댓글을 달지 않고 내용만 출력"
    )
    args = parser.parse_args(argv)

    findings = aggregator.merge(aggregator.load_findings(args.files))
    body = build_comment(findings, args.max_items)

    if args.dry_run:
        print(body)
        return body

    token = os.environ.get("GITHUB_TOKEN")
    if not (args.repo and args.pr and token):
        parser.error(
            "--repo, --pr 와 GITHUB_TOKEN 환경변수가 필요합니다 (확인만 하려면 --dry-run)"
        )
    result = post_comment(args.repo, args.pr, body, token)
    action = "수정" if result == "updated" else "작성"
    print(f"[pr_comment] PR #{args.pr} 댓글 {action} 완료")
    return body


if __name__ == "__main__":
    main()