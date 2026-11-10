"""가짜 비밀정보가 들어 있는 테스트용 Git 저장소를 만든다.

가짜 키는 실행할 때 생성한다. 이 파일 안에는 키 문자열이 없으므로,
우리 저장소의 secret-scan(Gitleaks)이나 GitHub push protection에 걸리지 않는다.
만들어진 저장소(samples/leaky-repo)는 .gitignore에 넣어 커밋하지 않는다.

사용법:
    python scripts/make_sample_repo.py            # samples/leaky-repo 생성
    python scripts/make_sample_repo.py <경로>     # 원하는 위치에 생성

시드를 고정해 두었으므로 누가 실행해도 같은 키, 같은 커밋이 만들어진다.
"""

from __future__ import annotations

import os
import random
import shutil
import string
import subprocess
import sys
from pathlib import Path

SEED = 20261111  # 결과를 재현하기 위해 고정 (실제 키가 아니다)
DEFAULT_DEST = Path(__file__).resolve().parent.parent / "samples" / "leaky-repo"

AUTHOR = {"name": "Sample Dev", "email": "sample-dev@example.com"}

rng = random.Random(SEED)


def rand(chars: str, n: int) -> str:
    return "".join(rng.choice(chars) for _ in range(n))


ALNUM = string.ascii_letters + string.digits
UPPER_B32 = string.ascii_uppercase + "234567"
B64 = string.ascii_letters + string.digits + "+/"

# 실행 시점에 조립하는 가짜 키 (접두어도 쪼개 두어 이 파일이 탐지되지 않게 한다)
FAKE = {
    "aws_key_id": "AK" + "IA" + rand(UPPER_B32, 16),
    "aws_secret": rand(ALNUM + "/+", 40),
    "github_pat": "gh" + "p_" + rand(ALNUM, 36),
    "slack_bot": "xo" + "xb-" + rand(string.digits, 12) + "-" + rand(string.digits, 12) + "-" + rand(ALNUM, 24),
    "db_password": rand(ALNUM, 24),
    "private_key_body": "\n".join(rand(B64, 64) for _ in range(12)),
}

# (커밋 메시지, 날짜, {파일경로: 내용 또는 None(삭제)})
COMMITS = [
    (
        "프로젝트 초기 설정",
        "2026-11-02T10:00:00+09:00",
        {
            "README.md": "# leaky-repo\n\nCommitGuard 기능 1 테스트용 저장소 (가짜 키만 들어 있음)\n",
            "app.py": (
                "import os\n\n"
                "# 올바른 방법: 환경 변수에서 읽기 (탐지되면 안 됨)\n"
                'API_KEY = os.environ.get("API_KEY")\n'
            ),
            "docs/aws-example.md": (
                "AWS 문서의 예시 키는 탐지 대상이 아니다 (오탐 확인용)\n\n"
                "aws_access_key_id = " + "AK" + "IAIOSFODNN7" + "EXAMPLE\n"
            ),
        },
    ),
    (
        "AWS 설정 추가",
        "2026-11-03T14:20:00+09:00",
        {
            "config/settings.py": (
                "# 학생이 흔히 하는 실수: 키를 코드에 직접 작성\n"
                f'AWS_ACCESS_KEY_ID = "{FAKE["aws_key_id"]}"\n'
                f'AWS_SECRET_ACCESS_KEY = "{FAKE["aws_secret"]}"\n'
                'AWS_REGION = "ap-northeast-2"\n'
            ),
        },
    ),
    (
        "슬랙 알림 봇과 DB 설정 추가",
        "2026-11-04T21:05:00+09:00",
        {
            "notify/slack.py": f'SLACK_BOT_TOKEN = "{FAKE["slack_bot"]}"\n',
            ".env": (
                "DB_HOST=localhost\n"
                "DB_USER=root\n"
                f"DB_PASSWORD={FAKE['db_password']}\n"
                f"GITHUB_TOKEN={FAKE['github_pat']}\n"
            ),
        },
    ),
    (
        "키를 환경 변수로 옮김",  # 파일에서는 사라지지만 Git 이력에는 남는다
        "2026-11-05T09:30:00+09:00",
        {
            "config/settings.py": (
                "import os\n\n"
                'AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]\n'
                'AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]\n'
                'AWS_REGION = "ap-northeast-2"\n'
            ),
        },
    ),
    (
        "배포용 키 추가",
        "2026-11-06T16:45:00+09:00",
        {
            "deploy/id_rsa": (
                "-----BEGIN " + "RSA PRIVATE KEY-----\n"
                + FAKE["private_key_body"]
                + "\n-----END " + "RSA PRIVATE KEY-----\n"
            ),
        },
    ),
]


def git(repo: Path, *args: str, date: str | None = None) -> None:
    env = os.environ.copy()
    env.update(
        GIT_AUTHOR_NAME=AUTHOR["name"],
        GIT_AUTHOR_EMAIL=AUTHOR["email"],
        GIT_COMMITTER_NAME=AUTHOR["name"],
        GIT_COMMITTER_EMAIL=AUTHOR["email"],
    )
    if date:
        env.update(GIT_AUTHOR_DATE=date, GIT_COMMITTER_DATE=date)
    subprocess.run(["git", "-C", str(repo), *args], check=True, env=env,
                   stdout=subprocess.DEVNULL)


def main() -> None:
    dest = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else DEFAULT_DEST
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)

    git(dest, "init", "-q", "-b", "main")
    git(dest, "config", "commit.gpgsign", "false")

    for message, date, files in COMMITS:
        for rel, content in files.items():
            path = dest / rel
            if content is None:
                path.unlink(missing_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8", newline="\n")
        git(dest, "add", "-A")
        git(dest, "commit", "-q", "-m", message, date=date)

    print(f"샘플 저장소 생성: {dest} (커밋 {len(COMMITS)}개)")


if __name__ == "__main__":
    main()
