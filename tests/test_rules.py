"""국내 탐지 규칙 4종 테스트 (worker/gitleaks.toml).

규칙마다 '잡혀야 하는 가짜 예시' 5건과 '잡히면 안 되는 예시' 5건을 파일로 만들어
기본 규칙 샘플과 같은 Git 저장소에서 Gitleaks를 한 번 돌리고,
파일별로 해당 규칙이 잡혔는지 확인한다.

실행: 저장소 루트에서  python -m pytest tests/test_rules.py -v
  - --gitleaks-report-dir samples 옵션으로 기본·국내 규칙의 통합 결과를 저장한다.
  - gitleaks가 없으면 건너뛴다. CI에서는 REQUIRE_GITLEAKS=1로 건너뛰지 않고 실패하게 한다.

가짜 값 처리:
  잡혀야 하는 예시는 '§' 표시를 넣어 적어 두고 실행할 때 지운다.
  API 키는 실행할 때 무작위로 만든다. 그래서 이 파일 자체는
  우리 저장소의 secret-scan(같은 규칙)에 걸리지 않는다. 실제 개인정보는 쓰지 않는다.
"""

import json
import os
import random
import re
import shutil
import string
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from scripts.make_sample_repo import git as sample_git  # noqa: E402
from worker.scanners.gitleaks import run_gitleaks, to_findings  # noqa: E402

CONFIG = ROOT / "worker" / "gitleaks.toml"
GITLEAKS = os.environ.get("GITLEAKS_BIN", "gitleaks")
KR_RULES = ["kr-rrn", "kr-mobile", "kr-student-id", "kr-service-api-key"]

if shutil.which(GITLEAKS) is None:
    if os.environ.get("REQUIRE_GITLEAKS"):
        raise RuntimeError("gitleaks가 설치되어 있지 않습니다")
    pytest.skip("gitleaks 미설치", allow_module_level=True)

# 검사 cwd가 임시 폴더로 바뀌어도 상대 경로의 GITLEAKS_BIN이 동작하게 한다.
GITLEAKS = str(Path(shutil.which(GITLEAKS)).resolve())


def unmark(text: str) -> str:
    return text.replace("§", "")


# --- API 키용 가짜 값 (실행할 때 생성, 시드 고정) -------------------------------
_rng = random.Random(20261115)
_HEX = "0123456789abcdef"
_ALNUM = string.ascii_letters + string.digits
_B64 = string.ascii_letters + string.digits
FAKE_KAKAO = "".join(_rng.choice(_HEX) for _ in range(32))
FAKE_KAKAO_ADMIN = "".join(_rng.choice(_HEX) for _ in range(32))
FAKE_NAVER_SECRET = "".join(_rng.sample(_ALNUM, 10))
FAKE_NAVER_ID = "".join(_rng.choice(_ALNUM) for _ in range(20))
FAKE_DATA_GO_KR = "".join(_rng.choice(_B64) for _ in range(60)) + "%2B" + \
    "".join(_rng.choice(_B64) for _ in range(24)) + "%3D%3D"

# --- 규칙별 예시 ---------------------------------------------------------------
CASES = {
    "kr-rrn": {
        "hit": [
            'rrn = "950817-§1739204"',
            "INSERT INTO users VALUES ('홍길동', '880229-§2481936');",
            "김철수,030405-§3926718,서울",
            '{"jumin": "071231-§4058271"}',
            "# 테스트용 주민번호 991001-§1640392",
        ],
        "miss": [
            'rrn = "951317-1739204"',            # 13월: 없는 날짜
            'rrn = "950832-2481936"',            # 32일: 없는 날짜
            'rrn = "800101-1234567"',            # 교재용 가짜 번호
            'rrn = "950817-1******"',            # 이미 가린 값
            "주문번호 20250817-1739204",          # 8자리 날짜형 주문번호
        ],
    },
    "kr-mobile": {
        "hit": [
            'phone = "010-§4827-3591"',
            "PHONE=010§58213947",
            "tel: 010.§7362.1048",
            "연락처: 010 §9182 3746",
            'contact = "+82 10-§6273-8410"',
        ],
        "miss": [
            'phone = "010-1234-5678"',           # 가운데 1xxx: 배정되지 않는 번호(예시용)
            'phone = "010-5555-5555"',           # 같은 숫자 반복
            'office = "02-3456-7890"',           # 유선 전화
            "order_no = 0104827359123",          # 더 긴 숫자열의 일부
            'phone = "010-****-3591"',           # 이미 가린 값
        ],
    },
    "kr-student-id": {
        "hit": [
            '학번 = "2023§1234"',
            '{"student_id": "2021§123456"}',
            "STUDENT_NO=2019§5678",
            "학번: 2024§0871",
            "hakbun = 2022§314159",
        ],
        "miss": [
            "year_code = 20231234",              # 학번이라는 이름이 없음
            "학번 = 2023",                        # 자릿수 부족
            '학번 = "2023XXXX"',                  # 자리표시자
            'student_id = request.form["student_id"]',
            "학번은 8자리 숫자입니다",
        ],
    },
    "kr-service-api-key": {
        "hit": [
            f'KAKAO_REST_API_KEY = "{FAKE_KAKAO}"',
            f'NAVER_CLIENT_SECRET = "{FAKE_NAVER_SECRET}"',
            f"url = 'https://apis.data.go.kr/1360000/VilageFcstInfoService_2.0/getVilageFcst?serviceKey={FAKE_DATA_GO_KR}&numOfRows=10'",
            f"KAKAO_ADMIN_KEY={FAKE_KAKAO_ADMIN}",
            f'const naverClientId = "{FAKE_NAVER_ID}";',
        ],
        "miss": [
            'KAKAO_REST_API_KEY = os.environ["KAKAO_REST_API_KEY"]',
            'NAVER_CLIENT_SECRET = "your_naver_secret"',
            'KAKAO_MAP_URL = "https://dapi.kakao.com/v2/local"',
            "url = f'https://apis.data.go.kr/x?serviceKey=${DATA_GO_KR_KEY}'",
            "NAVER_SEARCH_LIMIT = 100",
        ],
    },
}

PARAMS = [
    (rule, kind, i)
    for rule in KR_RULES
    for kind in ("hit", "miss")
    for i in range(len(CASES[rule][kind]))
]


def _name(rule: str, kind: str, i: int) -> str:
    return f"{rule}_{kind}_{i + 1}.txt"


@pytest.fixture(scope="module")
def detected(tmp_path_factory, request):
    """기본·국내 예시를 함께 검사하고 {(파일명, 규칙)} 집합을 돌려준다."""
    work = tmp_path_factory.mktemp("rule-cases")
    repo = work / "leaky-repo"
    subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "make_sample_repo.py"), str(repo)],
        check=True, capture_output=True, text=True, timeout=30,
    )
    src = repo / "kr"
    src.mkdir()
    for rule, kind, i in PARAMS:
        (src / _name(rule, kind, i)).write_text(unmark(CASES[rule][kind][i]) + "\n", encoding="utf-8")
    sample_git(repo, "add", "kr")
    sample_git(repo, "commit", "-q", "-m", "국내 규칙 가짜 탐지·비탐지 예시 추가",
               date="2026-11-15T10:00:00+09:00")

    results = run_gitleaks(repo, CONFIG)
    results.sort(key=lambda r: (r["Fingerprint"], r["Match"], r["Secret"]))
    report_dir = request.config.getoption("--gitleaks-report-dir")
    if report_dir:
        dest = Path(report_dir)
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "gitleaks-raw.json").write_text(
            json.dumps(results, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        (dest / "gitleaks-findings.json").write_text(
            json.dumps(to_findings(results), ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
    return {(Path(r["File"]).name, r["RuleID"]) for r in results}


def test_each_rule_has_five_hit_and_five_miss_cases():
    for rule in KR_RULES:
        assert len(CASES[rule]["hit"]) == 5
        assert len(CASES[rule]["miss"]) == 5


@pytest.mark.parametrize("rule,kind,i", PARAMS,
                         ids=[f"{r}-{k}-{i + 1}" for r, k, i in PARAMS])
def test_rule_case(detected, rule, kind, i):
    found = (_name(rule, kind, i), rule) in detected
    example = unmark(CASES[rule][kind][i])
    if kind == "hit":
        assert found, f"잡혀야 하는데 안 잡힘: {example}"
    else:
        assert not found, f"잡히면 안 되는데 잡힘: {example}"


def test_default_rules_still_active(tmp_path):
    """[extend] useDefault = true 확인: 기본 규칙(AWS 키)도 함께 동작해야 한다."""
    rng = random.Random(1)
    key = "AK" + "IA" + "".join(rng.choice(string.ascii_uppercase + "234567") for _ in range(16))
    (tmp_path / "settings.py").write_text(f'AWS_ACCESS_KEY_ID = "{key}"\n', encoding="utf-8")
    report = tmp_path / "r.json"
    subprocess.run([GITLEAKS, "dir", str(tmp_path / "settings.py"), "--config", str(CONFIG),
                    "--no-banner", "--redact", "-f", "json", "-r", str(report),
                    "--exit-code", "0", "--log-level", "error"], check=True, timeout=30)
    rules = {r["RuleID"] for r in json.loads(report.read_text(encoding="utf-8"))}
    assert "aws-access-token" in rules


# 초안의 5/5 예시 외 경계 조건. 가짜 값은 스캔 시에만 조립한다.
EDGE_CASES = [
    ("kr-rrn", 'rrn = "990231-§1739204"', False),
    ("kr-rrn", 'rrn = "990431-§1739204"', False),
    ("kr-rrn", 'rrn = "010229-§3739204"', False),
    ("kr-rrn", 'rrn = "000229-§1739204"', False),  # 1900년은 평년
    ("kr-rrn", 'rrn = "000229-§3739204"', True),   # 2000년은 윤년
    ("kr-rrn", 'rrn = "960229-§1739204"', True),
    ("kr-rrn", 'rrn = "950817-§1234567"', True),  # 뒷자리만 같다고 제외하지 않음
    ("kr-mobile", 'phone = "010-§4827-0000"', True),
    ("kr-student-id", 'STUID = "2023§1234"', True),
    ("kr-student-id", 'STUNO = "2023§1234"', True),
    ("kr-service-api-key", f'NCP_ACCESS_KEY = "{FAKE_NAVER_ID}"', True),
    ("kr-service-api-key", f'NCLOUD_SECRET_KEY = "{FAKE_KAKAO}"', True),
]


@pytest.mark.parametrize("rule,text,expected", EDGE_CASES,
                         ids=[f"edge-{r}-{i}" for i, (r, _, _) in enumerate(EDGE_CASES)])
def test_rule_edge_case(tmp_path, rule, text, expected):
    src = tmp_path / "case.txt"
    src.write_text(unmark(text) + "\n", encoding="utf-8")
    report = tmp_path / "report.json"
    proc = subprocess.run(
        [GITLEAKS, "dir", str(src), "--config", str(CONFIG), "--no-banner",
         "--redact", "-f", "json", "-r", str(report), "--exit-code", "0",
         "--log-level", "error"], capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 0, proc.stderr
    results = json.loads(report.read_text(encoding="utf-8"))
    assert any(r["RuleID"] == rule for r in results) == expected


@pytest.mark.parametrize("rule,miss_index", [
    ("kr-rrn", 2), ("kr-mobile", 1), ("kr-service-api-key", 1),
])
def test_allowlists_actually_exclude_examples(tmp_path, detected, rule, miss_index):
    assert (_name(rule, "miss", miss_index), rule) not in detected
    config = tmp_path / "without-allowlists.toml"
    config.write_text(re.sub(
        r"(?ms)^  \[\[rules\.allowlists\]\].*?(?=^# -|\Z)", "", CONFIG.read_text(encoding="utf-8")
    ), encoding="utf-8")
    src = tmp_path / "case.txt"
    src.write_text(unmark(CASES[rule]["miss"][miss_index]) + "\n", encoding="utf-8")
    report = tmp_path / "report.json"
    subprocess.run(
        [GITLEAKS, "dir", str(src), "--config", str(config), "--no-banner", "--redact",
         "-f", "json", "-r", str(report), "--exit-code", "0", "--log-level", "error"],
        check=True, capture_output=True, text=True, timeout=30,
    )
    assert rule in {r["RuleID"] for r in json.loads(report.read_text(encoding="utf-8"))}
