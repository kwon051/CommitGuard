"""기능 2 유사 이름(타이포스쿼팅) 패키지 탐지 테스트.

인터넷 없이 돈다. 판정 규칙은 작은 가짜 유명 목록(TOY)으로, 실제 동작은 저장소의 typosquat_top.json으로 확인한다.
실행: 저장소 루트에서 python -m pytest worker/tests/test_typosquat.py -v

A. 명세 (reqeusts 같은 이름을 잡고, 정상 이름은 안 잡음)
B. 철자 거리와 길이별 허용 기준
C. 빠른 색인이 빠짐없이 찾는지 (전부 비교한 결과와 대조)
D. 이름 판정 규칙 (정규화, 예외 목록, npm 조직)
E. 파일 검사 (파싱 연동, 중복, 줄 번호, 검사 한도)
F. 결과 형식 (공통 형식 v1, fingerprint, DB 길이, aggregator·fake_package와 함께)
G. 유명 목록 파일 (깨진 파일은 조용히 넘어가지 않음)
H. 저장소 탐색 (대상 파일, 심볼릭 링크, 인코딩, 큰 파일)
I. 실제 목록으로 오탐 확인, 속도
J. 명령줄, worker 연결, 목록 생성 스크립트
"""

import importlib.util
import json
import random
import string
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "worker"))

import aggregator  # noqa: E402
from scanners import fake_package as fp  # noqa: E402
from scanners import similar_package as ts  # noqa: E402

FIELDS = {"tool", "rule_id", "fingerprint", "severity", "file", "line", "title", "why", "fix", "status"}

# 가짜 유명 목록 (인기순). 실제 목록이 갱신돼도 규칙 테스트 결과가 바뀌지 않게 따로 둔다.
TOY = ts.build_indexes(
    pypi=["requests", "numpy", "django", "flask", "tqdm", "six", "beautifulsoup4", "python-dateutil",
          "scipy", "attrs", "pytest-timeout"],
    npm=["react", "lodash", "express", "cross-env", "socket.io", "jest", "colors", "color"],
    scopes=["types", "babel", "testing-library"],
)


def scan_text(text, file="requirements.txt", indexes=TOY):
    return ts.TyposquatScanner(indexes).scan_text(file, text)


def hit(ecosystem, name, indexes=TOY):
    return ts.check_name(indexes, ecosystem, name)


@pytest.fixture(scope="module")
def real():
    return ts.default_indexes()


# ───────────────────── A. 명세 ─────────────────────

def test_typo_of_famous_package_is_reported():
    findings = scan_text("requests==2.31.0\nreqeusts==2.31.0\n")       # 2번째 줄이 오타
    assert len(findings) == 1
    f = findings[0]
    assert set(f) == FIELDS
    assert (f["tool"], f["rule_id"], f["severity"], f["line"], f["status"]) == \
        ("similar-package", "similar-package", "MEDIUM", 2, "open")
    assert f["title"] == "[유사 이름 의심] reqeusts (PyPI) - 비슷한 유명 패키지: requests"
    assert "1글자" in f["why"] and "'requests' 패키지를 쓰려던" in f["fix"]
    assert f["fingerprint"] == "similar-package:PyPI:reqeusts:requirements.txt"


def test_real_list_catches_spec_example(real):
    assert ts.check_name(real, "PyPI", "reqeusts") == ("package", "requests", 1)
    assert ts.check_name(real, "PyPI", "requests") is None


def test_famous_and_unrelated_names_are_not_reported():
    assert scan_text("requests\nnumpy\nDjango>=4\nmy-team-utils\nhttpx\n") == []


# ───────────────────── B. 철자 거리와 허용 기준 ─────────────────────

@pytest.mark.parametrize("a, b, expected", [
    ("requests", "requests", 0),
    ("requests", "reqeusts", 1),     # 옆 글자 순서 바꿈
    ("requests", "requets", 1),      # 빼기
    ("requests", "requestss", 1),    # 넣기
    ("requests", "requezts", 1),     # 바꾸기
    ("requests", "erquests", 1),     # 맨 앞 순서 바꿈
    ("requests", "requesst", 1),     # 맨 끝 순서 바꿈
    ("requests", "rqeuests", 1),
    ("abcd", "badc", 2),             # 순서 바꿈 2번
    ("ca", "abc", 3),                # OSA 방식: 바꾼 글자를 다시 고치지 않음 (진짜 Damerau는 2)
    ("", "abc", 3),
    ("abc", "", 3),
    ("", "", 0),
])
def test_distance(a, b, expected):
    assert ts.distance(a, b, 10) == expected
    assert ts.distance(b, a, 10) == expected            # 순서를 바꿔도 같음


@pytest.mark.parametrize("a, b, limit", [
    ("requests", "numpy", 1),        # 길이 차이만으로 초과
    ("abcdefgh", "zyxwvuts", 2),     # 중간에 계산을 멈춤
    ("beautifulsoup4", "bea", 2),
])
def test_distance_stops_over_limit(a, b, limit):
    assert ts.distance(a, b, limit) == limit + 1


@pytest.mark.parametrize("a, b, expected", [
    ("six", "sx", 0), ("six", "sixx", 0),               # 짧은 쪽 3글자 이하는 비교 안 함
    ("tqdm", "tqmd", 1),                                # 4글자: 옆 순서 바꿈만
    ("tqdm", "tqdn", 0), ("tqdm", "tqdmm", 0), ("tqdm", "tdmq", 0), ("tqdm", "tqd", 0),
    ("flask", "flasks", 1), ("flask", "flsk", 0),       # flsk는 4글자인데 순서 바꿈이 아님
    ("abcdefghijk", "abcdefghijx", 1),                  # 11글자: 1
    ("abcdefghijkl", "abcdefghijxx", 2),                # 12글자: 2
    ("abcdefghijkl", "abcdefghijk", 1),                 # 짧은 쪽이 11글자라 1
])
def test_limit_by_length(a, b, expected):
    assert ts._limit(a, b) == expected


def test_length_boundaries_end_to_end():
    assert hit("PyPI", "tqmd") == ("package", "tqdm", 1)
    assert hit("PyPI", "tdqm") == ("package", "tqdm", 1)
    assert hit("PyPI", "tqdn") is None                  # 4글자 바꾸기는 안 잡음 (정상 이름이 너무 많음)
    assert hit("PyPI", "sixx") is None and hit("PyPI", "sx") is None
    assert hit("PyPI", "nunpy") == ("package", "numpy", 1)
    assert hit("PyPI", "nunpi") is None                 # 5~11글자는 2글자 차이면 안 잡음
    assert hit("PyPI", "beatifulsoup") == ("package", "beautifulsoup4", 2)   # 12글자 이상은 2글자까지
    assert hit("PyPI", "beatifulsop") is None                                # 3글자 차이


# ───────────────────── C. 빠른 색인 = 전부 비교 ─────────────────────

def _brute_force(index, name):
    """색인 없이 유명 목록 전체와 하나씩 비교 (정답)"""
    if name in index.rank:
        return None
    best = None
    for t in index.names:
        limit = ts._limit(name, t)
        if limit == 0:
            continue
        d = ts.distance(name, t, limit)
        if d <= limit and (best is None or (d, index.rank[t]) < (best[1], index.rank[best[0]])):
            best = (t, d)
    return best


def _mutate(rng, word):
    for _ in range(rng.choice([1, 1, 2, 3])):
        i = rng.randrange(len(word) + 1)
        op = rng.choice("ids t")
        c = rng.choice(string.ascii_lowercase + "-0")
        if op == "i":
            word = word[:i] + c + word[i:]
        elif op == "d" and i < len(word):
            word = word[:i] + word[i + 1:]
        elif op == "s" and i < len(word):
            word = word[:i] + c + word[i + 1:]
        elif op == "t" and i + 1 < len(word):
            word = word[:i] + word[i + 1] + word[i] + word[i + 2:]
    return word


def test_index_finds_same_as_brute_force(real):
    rng = random.Random(20261125)          # 고정 시드 -> 매번 같은 3000개
    index = real["PyPI"]
    found = 0
    for _ in range(3000):
        name = _mutate(rng, rng.choice(index.names[:300]))
        expected = _brute_force(index, name) if 4 <= len(name) <= index.max_len + 2 else None
        assert index.closest(name) == expected, name
        found += expected is not None
    assert found > 1000                    # 실제로 많이 잡히는 입력으로 시험했는지


# ───────────────────── D. 이름 판정 규칙 ─────────────────────

@pytest.mark.parametrize("name", ["Requests", "REQUESTS", "python_dateutil", "Python.DateUtil", "beautifulSoup4"])
def test_pypi_normalized_name_is_the_famous_package(name):
    assert hit("PyPI", name) is None


def test_pypi_separator_typo_is_reported():
    assert hit("PyPI", "pythondateutil") == ("package", "python-dateutil", 1)


def test_npm_rules():
    assert hit("npm", "React") is None                     # 대소문자만 다르면 같은 이름
    assert hit("npm", "reactt") == ("package", "react", 1)
    assert hit("npm", "crossenv") == ("package", "cross-env", 1)    # 2017년 실제 npm 악성 패키지
    assert hit("npm", "socket-io") == ("package", "socket.io", 1)
    assert hit("npm", "loadsh") == ("package", "lodash", 1)


def test_similar_famous_names_are_both_fine():
    assert hit("npm", "colors") is None and hit("npm", "color") is None   # 둘 다 유명 목록에 있음


def test_known_distinct_packages_are_not_reported():
    assert "scapy" in ts.KNOWN_DISTINCT["PyPI"] and hit("PyPI", "scapy") is None
    assert hit("PyPI", "cattrs") is None                   # attrs와 1글자 차이지만 다른 정상 패키지
    assert hit("npm", "preact") is None                    # react와 1글자 차이지만 다른 정상 패키지
    assert hit("PyPI", "pytest-timeouts") == ("package", "pytest-timeout", 1)   # 확실하지 않은 건 예외에 안 넣음


def test_npm_scope_rules():
    assert hit("npm", "@typse/node") == ("scope", "@types", 1)          # 유명 조직 흉내
    assert hit("npm", "@bable/core") == ("scope", "@babel", 1)
    assert hit("npm", "@testing-libary/react") == ("scope", "@testing-library", 1)
    assert hit("npm", "@types/nodee") is None             # 유명 조직 안: 조직 주인만 올릴 수 있음
    assert hit("npm", "@Types/node") is None
    assert hit("npm", "@my-team/react") is None           # 상관없는 조직
    assert hit("npm", "@aws-cdk/core", indexes=ts.build_indexes([], [], ["aws-sdk"])) is None  # 예외 목록


def test_closest_prefers_smaller_distance_then_more_popular():
    idx = ts.build_indexes(pypi=["aaaab", "aaaac", "zzzzzzzzzzzz"], npm=["x"], scopes=["y"])
    assert hit("PyPI", "aaaad", idx) == ("package", "aaaab", 1)    # 같은 거리면 앞(더 유명)
    idx = ts.build_indexes(pypi=["abcdefghijkl", "abcdefghijkm"], npm=["x"], scopes=["y"])
    assert hit("PyPI", "abcdefghijkx", idx) == ("package", "abcdefghijkl", 1)
    assert hit("PyPI", "abcdefghijmk", idx) == ("package", "abcdefghijkm", 1)   # 1 < 2 우선


# ───────────────────── E. 파일 검사 ─────────────────────

def test_requirements_parsing_is_shared_with_fake_package():
    text = """
# reqeusts 주석은 무시
-r reqeusts.txt
reqeusts[security]>=2 ; python_version >= "3.8"   # 오타
./numpi
git+https://github.com/x/flaskk.git#egg=flaskk
nunpy==1.0 \\
    --hash=sha256:abc
djnago @ https://example.com/djnago.whl
"""
    findings = scan_text(text)
    assert [(f["title"].split()[3], f["line"]) for f in findings] == [("reqeusts", 4), ("nunpy", 7)]


def test_package_json_sections_and_alias():
    pkg = """{
  "scripts": {"reactt": "x"},
  "dependencies": {"react": "^18", "reactt": "^1", "my-lodash": "npm:loadsh@^4", "local": "file:./expresss"},
  "devDependencies": {"jset": "^29", "@typse/node": "^20"}
}"""
    findings = scan_text(pkg, file="web/package.json")
    titles = [f["title"] for f in findings]
    assert titles == [
        "[유사 이름 의심] reactt (npm) - 비슷한 유명 패키지: react",
        "[유사 이름 의심] loadsh (npm) - 비슷한 유명 패키지: lodash",     # npm: 별칭 뒤에 숨은 오타
        "[유사 이름 의심] jset (npm) - 비슷한 유명 패키지: jest",
        "[유사 이름 의심] @typse/node (npm) - 비슷한 유명 조직: @types",
    ]
    assert findings[0]["line"] == 3                       # scripts의 "reactt"가 아니라 dependencies 줄
    assert "공식 조직처럼" in findings[3]["why"]


def test_same_package_twice_in_file_is_one_finding():
    findings = scan_text("Reqeusts==1\nreqeusts==2\nREQEUSTS\n")
    assert len(findings) == 1 and findings[0]["line"] == 1


def test_same_package_in_two_files_gives_one_finding_each():
    scanner = ts.TyposquatScanner(TOY)
    a = scanner.scan_text("requirements.txt", "reqeusts\n")
    b = scanner.scan_text("backend/requirements.txt", "reqeusts\n")
    assert len(a) == len(b) == 1 and a[0]["fingerprint"] != b[0]["fingerprint"]
    assert len(scanner.cache) == 1                         # 계산은 1번


def test_broken_or_non_target_files_are_skipped():
    assert scan_text("{ 깨진 json", file="package.json") == []      # fake_package가 '확인 불가'로 알림
    assert scan_text('["reactt"]', file="package.json") == []
    assert scan_text("reqeusts\n", file="notes.txt") == []
    assert scan_text("reqeusts\n", file="package-lock.json") == []


def test_name_limit_reports_unknown_once(monkeypatch):
    monkeypatch.setattr(ts, "MAX_NAMES", 3)
    scanner = ts.TyposquatScanner(TOY)
    findings = scanner.scan_text("requirements.txt", "reqeusts\na1111\na2222\na3333\na4444\nnunpy\n")
    assert [f["severity"] for f in findings] == ["MEDIUM", "UNKNOWN"]   # 한도 넘은 줄은 버리지 않고 1번 알림
    assert "3개를 넘어" in findings[1]["title"] and findings[1]["line"] is None
    # 이미 계산한 이름은 한도와 상관없이 계속 잡는다
    again = scanner.scan_text("requirements-dev.txt", "reqeusts\n")
    assert len(again) == 1 and again[0]["severity"] == "MEDIUM"


# ───────────────────── F. 결과 형식 ─────────────────────

def test_fingerprint_does_not_depend_on_line_or_target():
    one = scan_text("reqeusts\n")[0]
    two = scan_text("numpy\n\n\nreqeusts\n")[0]
    assert one["line"] != two["line"] and one["fingerprint"] == two["fingerprint"]
    # 유명 목록이 바뀌어 가장 가까운 이름이 달라져도 같은 항목
    other = ts.build_indexes(pypi=["reqeust"], npm=["x"], scopes=["y"])
    assert scan_text("reqeusts\n", indexes=other)[0]["fingerprint"] == one["fingerprint"]


def test_fingerprint_matches_fake_package_naming():
    # 같은 이름이면 fake_package와 같은 정규화 규칙, 앞부분만 도구 이름으로 다르다
    ty = scan_text("Reqeusts_Lib\n", indexes=ts.build_indexes(["requests-lib"], ["x"], ["y"]))[0]
    fake = fp.FakePackageScanner(lambda url, method: (404, b"", "")).scan_text("requirements.txt", "Reqeusts_Lib\n")[0]
    assert ty["fingerprint"].split(":", 1)[1] == fake["fingerprint"].split(":", 1)[1]
    assert ty["fingerprint"] != fake["fingerprint"]


def test_long_values_fit_db_columns():
    def check(f):
        assert len(f["title"]) <= 255 and len(f["file"]) <= 255 and len(f["fingerprint"]) <= 255
        assert len(f["tool"]) <= 20 and len(f["rule_id"]) <= 100      # db/init.sql
        return f

    long_name = "a" * 200
    idx = ts.build_indexes(pypi=[long_name + "b"], npm=["n" * 213], scopes=["y"])
    f = check(scan_text(long_name + "c\n", indexes=idx)[0])
    assert f["title"].endswith("...")

    def deep(name):
        return check(scan_text('{"dependencies": {"%s": "1"}}' % name, file="deep/" * 60 + "package.json",
                               indexes=idx)[0])
    a, b = deep("n" * 214), deep("n" * 212 + "x")
    assert a["file"].endswith("package.json") and a["file"].startswith("...")
    assert a["fingerprint"].startswith("similar-package:sha256:") and a["fingerprint"] != b["fingerprint"]


def test_findings_pass_through_aggregator_with_fake_package():
    text = "reqeusts\n"
    typo = scan_text(text)
    fake = fp.FakePackageScanner(lambda url, method: (404, b"", "")).scan_text("requirements.txt", text)
    merged = aggregator.merge(fake + typo)
    assert [(f["tool"], f["severity"]) for f in merged] == [("fake-package", "HIGH"), ("similar-package", "MEDIUM")]
    assert all(set(f) == FIELDS for f in merged)


# ───────────────────── G. 유명 목록 파일 ─────────────────────

def test_real_data_file_is_valid(real):
    data = ts.load_data()
    assert len(data["pypi"]) >= 300 and len(data["npm"]) >= 300 and len(data["npm_scopes"]) >= 20
    for name in ("requests", "numpy", "django", "flask", "pytest", "boto3"):
        assert name in real["PyPI"].rank
    for name in ("react", "lodash", "express", "axios", "cross-env", "nodemon", "jest", "mongoose", "bcrypt"):
        assert name in real["npm"].rank
    assert "types" in real["scope"].rank and "babel" in real["scope"].rank


def test_missing_data_file_raises(tmp_path):
    with pytest.raises(ts.TyposquatDataError):
        ts.load_data(tmp_path / "nope.json")


@pytest.mark.parametrize("content", [
    "{ 깨진",
    "[]",
    '{"pypi": [], "npm": ["react"], "npm_scopes": ["types"]}',                # 빈 목록
    '{"npm": ["react"], "npm_scopes": ["types"]}',                            # 칸 없음
    '{"pypi": ["Requests"], "npm": ["react"], "npm_scopes": ["types"]}',      # 정규화 안 됨
    '{"pypi": ["a b"], "npm": ["react"], "npm_scopes": ["types"]}',
    '{"pypi": [1], "npm": ["react"], "npm_scopes": ["types"]}',
    '{"pypi": ["requests"], "npm": ["React"], "npm_scopes": ["types"]}',
    '{"pypi": ["requests"], "npm": ["@types/node"], "npm_scopes": ["types"]}',
    '{"pypi": ["requests"], "npm": ["react"], "npm_scopes": ["@types"]}',
    '{"pypi": ["requests"], "npm": ["react"], "npm_scopes": "types"}',
])
def test_broken_data_file_raises(tmp_path, content):
    path = tmp_path / "top.json"
    path.write_text(content, encoding="utf-8")
    with pytest.raises(ts.TyposquatDataError):
        ts.load_data(path)


def test_broken_data_fails_scan_instead_of_empty_result(tmp_path, monkeypatch):
    # 빈 결과로 넘어가면 DB의 지난 유사 이름 항목이 fixed로 잘못 바뀐다 -> 반드시 오류
    (tmp_path / "requirements.txt").write_text("reqeusts\n")
    monkeypatch.setattr(ts, "DATA_FILE", tmp_path / "nope.json")
    ts.default_indexes.cache_clear()
    try:
        with pytest.raises(ts.TyposquatDataError):
            ts.scan(str(tmp_path))
        with pytest.raises(ts.TyposquatDataError):     # 실패는 저장해 두지 않고 다음 검사에서 다시 시도
            ts.scan(str(tmp_path))
    finally:
        monkeypatch.undo()
        ts.default_indexes.cache_clear()
    assert len(ts.scan(str(tmp_path))) == 1             # 파일이 돌아오면 정상 동작


# ───────────────────── H. 저장소 탐색 ─────────────────────

def test_scan_repo(tmp_path, monkeypatch):
    import os
    (tmp_path / "requirements.txt").write_text("reqeusts\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("reqeusts\n", encoding="utf-8")                  # 대상 아님
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "dev.txt").write_text("nunpy\n", encoding="utf-8")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package.json").write_text('{"dependencies":{"reactt":"1"}}')
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "requirements.txt").write_text("reqeusts\n")
    outside = tmp_path.parent / "outside-requirements.txt"
    outside.write_text("djnago\n", encoding="utf-8")
    try:
        os.symlink(outside, tmp_path / "requirements-prod.txt")            # 저장소 밖 파일을 가리키는 링크
        os.symlink(tmp_path / "requirements", tmp_path / "linked-dir")
    except OSError:
        pass   # Windows는 권한이 없으면 링크를 못 만듦 (CI는 Linux라 검사함)
    (tmp_path / "requirements-win.txt").write_bytes("tqmd==1.0\r\n".encode("utf-16"))   # PowerShell pip freeze
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_bytes(b'\xef\xbb\xbf{"dependencies":{"loadsh":"1"}}')  # BOM
    monkeypatch.setattr(fp, "MAX_FILE_SIZE", 100)
    (tmp_path / "requirements-big.txt").write_text("reqeusts\n" * 20)    # 큰 파일은 fake_package가 알림

    findings = ts.scan(str(tmp_path), indexes=TOY)
    assert sorted((f["file"], f["title"].split()[3]) for f in findings) == [
        ("requirements-win.txt", "tqmd"),
        ("requirements.txt", "reqeusts"),
        ("requirements/dev.txt", "nunpy"),
        ("web/package.json", "loadsh"),
    ]


def test_empty_or_missing_repo():
    assert ts.scan("/nonexistent/path/for/test", indexes=TOY) == []


# ───────────────────── I. 실제 목록으로 오탐 확인, 속도 ─────────────────────

def test_every_famous_name_is_not_reported(real):
    for ecosystem in ("PyPI", "npm"):
        for name in real[ecosystem].names:
            assert ts.check_name(real, ecosystem, name) is None, name


def test_known_distinct_is_written_in_compare_form(real):
    # 팀원이 예외 목록에 대문자나 _로 적으면 비교가 안 돼서 소용없다
    for name in ts.KNOWN_DISTINCT["PyPI"]:
        assert name == fp._norm_pypi(name), name
        assert ts.check_name(real, "PyPI", name) is None
    for name in ts.KNOWN_DISTINCT["npm"]:
        assert name == name.lower() and not name.startswith("@"), name
        assert ts.check_name(real, "npm", name) is None
    for scope in ts.KNOWN_DISTINCT["scope"]:
        assert scope == scope.lower() and "@" not in scope, scope


@pytest.mark.parametrize("ecosystem, name, target", [
    ("PyPI", "reqeusts", "requests"), ("PyPI", "djnago", "django"), ("PyPI", "nunpy", "numpy"),
    ("PyPI", "tdqm", "tqdm"), ("PyPI", "pyyml", "pyyaml"), ("PyPI", "beatifulsoup", "beautifulsoup4"),
    ("npm", "crossenv", "cross-env"), ("npm", "expresss", "express"), ("npm", "mongose", "mongoose"),
    ("npm", "nodemn", "nodemon"), ("npm", "bcyrpt", "bcrypt"), ("npm", "loadsh", "lodash"),
    ("npm", "@typse/node", "@types"), ("npm", "@bable/core", "@babel"),
])
def test_real_list_catches_common_typos(real, ecosystem, name, target):
    result = ts.check_name(real, ecosystem, name)
    assert result is not None and result[1] == target


def test_speed_with_many_names(real):
    rng = random.Random(1)
    lines = ["".join(rng.choice(string.ascii_lowercase + "-") for _ in range(rng.randint(4, 40)))
             for _ in range(ts.MAX_NAMES)]
    lines.append("x" * 100_000)                          # 아주 긴 이름은 비교 없이 넘어감
    start = time.monotonic()
    ts.TyposquatScanner(real).scan_text("requirements.txt", "\n".join(lines))
    assert time.monotonic() - start < 5


# ───────────────────── J. 명령줄, worker, 목록 생성 스크립트 ─────────────────────

def test_command_line(tmp_path, monkeypatch, capsys):
    (tmp_path / "requirements.txt").write_text("reqeusts\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["typosquat", str(tmp_path)])
    ts._main()
    out = capsys.readouterr()
    assert '"[유사 이름 의심] reqeusts (PyPI) - 비슷한 유명 패키지: requests"' in out.out and "결과 1건" in out.err

    out_file = tmp_path / "findings.json"
    monkeypatch.setattr(sys, "argv", ["typosquat", str(tmp_path), "--out", str(out_file)])
    ts._main()
    assert json.loads(out_file.read_text(encoding="utf-8"))[0]["tool"] == "similar-package"


def _fake_db(saved):
    conn = type("C", (), {"close": lambda self: None})()
    return conn, (lambda c, repo, findings: saved.update(findings=findings) or {"saved": len(findings), "fixed": 0})


def test_worker_runs_typosquat_scan(monkeypatch):
    pytest.importorskip("valkey")
    import main

    saved = {}
    conn, save = _fake_db(saved)

    def fake_clone(url, target):
        Path(target).mkdir()
        (Path(target) / "requirements.txt").write_text("reqeusts\n")

    monkeypatch.setattr(main, "clone_repo", fake_clone)
    monkeypatch.setattr(main.gitleaks, "scan", lambda path: [])
    monkeypatch.setattr(main.trivy, "scan", lambda path: [])
    monkeypatch.setattr(main.fake_package, "scan", lambda path: [])
    monkeypatch.setattr(main.aggregator, "get_connection", lambda: conn)
    monkeypatch.setattr(main.aggregator, "save_to_db", save)

    main.process_job({"repo_url": "https://github.com/user/repo"})
    assert [(f["tool"], f["title"].split()[3]) for f in saved["findings"]] == [("similar-package", "reqeusts")]


def test_worker_does_not_save_when_typosquat_fails(monkeypatch):
    pytest.importorskip("valkey")
    import main

    saved = {}
    conn, save = _fake_db(saved)
    monkeypatch.setattr(main, "clone_repo", lambda url, target: None)
    monkeypatch.setattr(main.gitleaks, "scan", lambda path: [])
    monkeypatch.setattr(main.trivy, "scan", lambda path: [])
    monkeypatch.setattr(main.fake_package, "scan", lambda path: [])

    def broken(path):
        raise ts.TyposquatDataError("목록 파일 깨짐")
    monkeypatch.setattr(main.similar_package, "scan", broken)
    monkeypatch.setattr(main.aggregator, "save_to_db", save)
    monkeypatch.setattr(main.aggregator, "get_connection", lambda: conn)

    with pytest.raises(ts.TyposquatDataError):
        main.process_job({"repo_url": "https://github.com/user/repo"})
    assert saved == {}                                   # 일부 결과만 저장하지 않음


def _load_script():
    path = ROOT / "scripts" / "make_similar_package_data.py"
    spec = importlib.util.spec_from_file_location("make_similar_package_data", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_data_script_parsing_without_network():
    script = _load_script()
    pypi = {"rows": [{"project": "Requests"}, {"project": "requests"}, {"project": "Foo_Bar"},
                     {"project": "bad name"}, {"project": None}, "junk", {"project": "numpy"}]}
    assert script.pypi_names(pypi) == ["requests", "foo-bar", "numpy"]          # 정규화, 중복·이상한 값 제거
    npm = [{"name": "react"}, {"name": "@types/node"}, {"name": "@Types/react"}, {"name": "JSONStream"},
           {"name": "react"}, {"name": "bad name"}, {"name": "x" * 215}, {}, "junk", {"name": "@babel/core"}]
    assert script.npm_names(npm) == (["react", "jsonstream"], ["types", "babel"])
    data = {"pypi": script.pypi_names(pypi), "npm": ["react", "jsonstream"], "npm_scopes": ["types", "babel"]}
    ts.validate_data(data)                                # 스크립트 결과는 typosquat.py 검사를 통과해야 함