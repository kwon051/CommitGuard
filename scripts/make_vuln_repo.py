"""Trivy 테스트용 취약 패키지 저장소를 만든다.

알려진 취약점이 있는 오래된 버전을 적은 requirements.txt를 samples/vuln-repo에 만든다.
만들어진 폴더는 .gitignore에 넣어 커밋하지 않는다.
(커밋하면 우리 저장소를 검사할 때 이 파일의 취약점이 우리 문제처럼 잡히고,
 GitHub 의존성 알림에도 걸린다)

사용법:
    python scripts/make_vuln_repo.py            # samples/vuln-repo 생성
    python scripts/make_vuln_repo.py <경로>     # 원하는 위치에 생성
"""

from __future__ import annotations

import sys
from pathlib import Path

DEFAULT_DEST = Path(__file__).resolve().parent.parent / "samples" / "vuln-repo"

# 알려진 취약점이 있는 오래된 버전 (실제 프로젝트 의존성 아님)
OLD_PACKAGES = {
    "requests": "2.19.0",
    "flask": "0.12.2",
    "jinja2": "2.10",
    "pyyaml": "5.3",
    "urllib3": "1.24.1",
}


def make_vuln_repo(dest: Path = DEFAULT_DEST) -> Path:
    """dest 폴더에 오래된 버전의 requirements.txt를 만든다."""
    dest.mkdir(parents=True, exist_ok=True)
    lines = [f"{name}=={version}" for name, version in OLD_PACKAGES.items()]
    (dest / "requirements.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest


def main() -> None:
    dest = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_DEST
    path = make_vuln_repo(dest)
    print(f"샘플 저장소 생성: {path}")


if __name__ == "__main__":
    main()