"""기능 2 가짜 패키지 탐지 테스트.

진짜 인터넷 대신 가짜 fetch 함수를 끼워서, 네트워크 상태와 상관없이 같은 결과가 나온다.
실행: 저장소 루트에서 python -m pytest worker/tests/test_fake_package.py -v

A. 명세 3건 (있음 / 없음 / 네트워크 오류)
B. 레지스트리 응답 경계 (PyPI·npm의 모든 응답 종류)
C. 파일 파싱 경계 (requirements.txt, package.json)
D. 조회 제어 (중복 조회, 한도, 시간 초과, 연속 실패)
E. 결과 형식 (공통 형식 v1, fingerprint, DB 길이, aggregator 연동)
F. 저장소 탐색 (대상 파일, 심볼릭 링크, 인코딩, 큰 파일)
G. 실제 HTTP 함수와 worker 연결
"""

import io
import os
import sys
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "worker"))

import aggregator  # noqa: E402
from scanners import fake_package as fp  # noqa: E402

FIELDS = {"tool", "rule_id", "fingerprint", "severity", "file", "line", "title", "why", "fix", "status"}
PYPI = "https://pypi.org/pypi/{}/json"
NPM = "https://registry.npmjs.org/-/package/{}/dist-tags"
OK_PYPI = (200, b"", "application/json")


def fake_fetch(routes):
    """url -> (상태, 본문, Content-Type) 또는 예외. 등록 안 된 url은 404. 호출한 url은 calls에 기록."""
    calls = []

    def fetch(url, method):
        calls.append(url)
        r = routes.get(url, (404, b"", ""))
        if isinstance(r, Exception):
            raise r
        return r
    fetch.calls = calls
    return fetch


def scan_req(text, routes=None, file="requirements.txt"):
    fetch = fake_fetch(routes or {})
    return fp.FakePackageScanner(fetch).scan_text(file, text), fetch


# ───────────────────── A. 명세 3건 ─────────────────────

def test_real_package_is_not_reported():
    findings, _ = scan_req("requests==2.31.0\n", {PYPI.format("requests"): OK_PYPI})
    assert findings == []


def test_missing_package_is_fake_suspect():
    text = "requests==2.31.0\nFlask_GPT.Helper==0.1.0\n"      # 2번째 줄이 지어낸 이름
    findings, fetch = scan_req(text, {PYPI.format("requests"): OK_PYPI})
    assert len(findings) == 1
    f = findings[0]
    assert set(f) == FIELDS
    assert f["title"].startswith("[가짜 의심] Flask_GPT.Helper (PyPI)")
    assert (f["tool"], f["rule_id"], f["severity"], f["line"], f["status"]) == \
        ("fake-package", "fake-package", "HIGH", 2, "open")
    assert PYPI.format("flask-gpt-helper") in fetch.calls          # 정규화된 이름으로 조회
    assert f["fingerprint"] == "fake-package:PyPI:flask-gpt-helper:requirements.txt"


def test_network_error_is_unknown_not_fake():
    findings, _ = scan_req("flask-gpt-helper\n", {PYPI.format("flask-gpt-helper"): TimeoutError()})
    assert len(findings) == 1
    f = findings[0]
    assert set(f) == FIELDS
    assert f["title"].startswith("[확인 불가]") and "가짜" not in f["title"]
    assert f["severity"] == "UNKNOWN"
    # 가짜 의심일 때와 같은 fingerprint -> 재검사 때 fixed로 잘못 바뀌지 않음
    assert f["fingerprint"] == "fake-package:PyPI:flask-gpt-helper:requirements.txt"


# ───────────────────── B. 레지스트리 응답 경계 ─────────────────────

@pytest.mark.parametrize("response, expected", [
    ((200, b"", "application/json"), fp.EXISTS),
    ((200, b"", "application/json; charset=utf-8"), fp.EXISTS),
    ((404, b"", ""), fp.NOT_FOUND),
    ((429, b"", ""), fp.UNKNOWN),                      # 요청 과다
    ((500, b"", ""), fp.UNKNOWN),                      # 서버 문제
    ((503, b"", ""), fp.UNKNOWN),
    ((200, b"", "text/html"), fp.UNKNOWN),             # 프록시 안내 페이지 등
    (ConnectionResetError(), fp.UNKNOWN),
    (urllib.error.URLError("dns"), fp.UNKNOWN),
])
def test_pypi_responses(response, expected):
    status, _ = fp.check_pypi("pkg", fake_fetch({PYPI.format("pkg"): response}))
    assert status == expected


@pytest.mark.parametrize("response, expected", [
    ((200, b'{"latest":"1.0.0"}', ""), fp.EXISTS),
    ((200, b'{"latest":"1.0.0-rc.1"}', ""), fp.EXISTS),           # rc만 있어도 설치는 됨
    ((404, b'"Not Found"', ""), fp.NOT_FOUND),
    ((200, b'{}', ""), fp.NOT_FOUND),                             # unpublish돼서 태그가 없음
    ((200, b'{"latest":""}', ""), fp.NOT_FOUND),
    ((200, b'{"latest":null}', ""), fp.NOT_FOUND),
    ((200, b'{"latest":"0.0.1-security"}', ""), fp.NOT_FOUND),   # npm이 지운 악성 이름
    ((429, b"", ""), fp.UNKNOWN),
    ((502, b"", ""), fp.UNKNOWN),
    ((200, b"{" * (fp.MAX_BODY + 1), ""), fp.UNKNOWN),            # 응답이 너무 큼
    ((200, b"<html>login</html>", ""), fp.UNKNOWN),               # JSON 아님
    ((200, b"\xff\xfe\x00", ""), fp.UNKNOWN),                     # 깨진 인코딩
    ((200, b'["latest"]', ""), fp.UNKNOWN),                       # dict가 아닌 JSON
    (TimeoutError(), fp.UNKNOWN),
])
def test_npm_responses(response, expected):
    status, _ = fp.check_npm("pkg", fake_fetch({NPM.format("pkg"): response}))
    assert status == expected


def test_npm_scoped_name_is_url_encoded():
    fetch = fake_fetch({NPM.format("@types%2Fnode"): (200, b'{"latest":"1.0.0"}', "")})
    assert fp.check_npm("@types/node", fetch)[0] == fp.EXISTS
    assert fetch.calls == [NPM.format("@types%2Fnode")]           # '/'가 %2F로 바뀌어야 함


# ───────────────────── C. 파일 파싱 경계 ─────────────────────

def test_requirements_parsing_edge_cases():
    req = """
# 주석 줄
-r base.txt
--index-url https://example.com/simple
-e .
git+https://github.com/x/y.git#egg=y
./local_pkg
/abs/path/pkg
Django[bcrypt]>=4.2 ; python_version >= "3.10"   # 인라인 주석
numpy==1.26.0 \\
    --hash=sha256:abc
oldstyle (>=1.0)
mypkg @ https://example.com/mypkg.whl
foo$bar==1.0
weird#not-comment==1.0
requests>=2,<3
a
"""
    parsed = fp.parse_requirements(req)
    assert [n for n, _ in parsed] == ["Django", "numpy", "oldstyle", "requests", "a"]
    assert dict(parsed)["numpy"] == 10            # 이어진 줄은 시작 줄 번호
    # '#' 앞에 공백이 없으면 주석이 아님 (pip 규칙) -> 'weird#...'는 잘못된 줄이라 제외


def test_requirements_windows_newlines_and_trailing_backslash():
    assert fp.parse_requirements("a==1\r\nb==2\r\n") == [("a", 1), ("b", 2)]
    assert fp.parse_requirements("a==1\nb==2 \\") == [("a", 1), ("b", 2)]   # 파일이 '\'로 끝남


def test_package_json_parsing_edge_cases():
    pkg = """{
  "name": "my-app",
  "scripts": {"build": "tsc"},
  "dependencies": {
    "react": "^18.2.0",
    "@types/node": "^20.0.0",
    "my-alias": "npm:lodash@^4.17.21",
    "scoped-alias": "npm:@babel/core",
    "local": "file:../local",
    "gh": "user/repo",
    "url": "https://example.com/x.tgz",
    "ws": "workspace:*",
    "JSONStream": "1.3.5",
    "num": 1,
    ".hidden": "1.0.0",
    "_under": "1.0.0",
    "empty-alias": "npm:",
    "build": "1.0.0"
  },
  "devDependencies": {"react": "^18.2.0", "left-pad-ai": "1.0.0"},
  "peerDependencies": [],
  "optionalDependencies": {"%s": "1.0.0"}
}""" % ("x" * 215)                                   # 215자: npm 최대 214자 초과
    parsed = fp.parse_package_json(pkg)
    assert [n for n, _ in parsed] == [
        "react", "@types/node", "lodash", "@babel/core", "JSONStream", "num", "build", "left-pad-ai"]
    lines = dict(parsed)
    assert lines["react"] == 5
    assert lines["build"] == 18        # scripts의 "build"(3번 줄)가 아니라 dependencies의 줄


def test_package_json_invalid_inputs():
    with pytest.raises(ValueError):
        fp.parse_package_json("{ 깨진 json")
    with pytest.raises(ValueError):
        fp.parse_package_json('["not", "object"]')
    assert fp.parse_package_json('{"name": "no-deps"}') == []
    # 키를 유니코드 이스케이프로 써서 원문에서 못 찾으면 줄 번호는 None
    assert fp.parse_package_json('{"dependencies": {"\\u0072eact": "1"}}') == [("react", None)]


def test_broken_package_json_becomes_unknown_finding():
    findings, fetch = scan_req("{ 깨진 json", file="web/package.json")
    assert len(findings) == 1 and fetch.calls == []
    f = findings[0]
    assert set(f) == FIELDS
    assert f["severity"] == "UNKNOWN" and f["line"] is None and f["file"] == "web/package.json"


# ───────────────────── D. 조회 제어 ─────────────────────

def test_same_package_is_queried_once():
    # 같은 파일 안 철자 다른 중복 + 다른 파일의 같은 패키지 -> 조회 1번, 결과는 파일마다 1개
    scanner = fp.FakePackageScanner(fake_fetch({}))
    a = scanner.scan_text("requirements.txt", "Flask_X==1\nflask-x==1\n")
    b = scanner.scan_text("requirements-dev.txt", "flask.x\n")
    assert len(scanner.fetch.calls) == 1
    assert len(a) == 1 and len(b) == 1


def test_stops_querying_when_registry_is_down():
    findings, fetch = scan_req("a\nb\nc\nd\ne\nf\n", {PYPI.format(n): OSError() for n in "abcdef"})
    assert len(fetch.calls) == fp.MAX_FAILS_IN_ROW
    assert len(findings) == 6 and all(f["severity"] == "UNKNOWN" for f in findings)
    assert "계속 실패" in findings[-1]["title"]


def test_failure_count_resets_after_success():
    routes = {PYPI.format(n): OSError() for n in "abde"}
    routes[PYPI.format("c")] = OK_PYPI                    # 실패 2번 -> 성공 -> 실패 2번
    _, fetch = scan_req("a\nb\nc\nd\ne\n", routes)
    assert len(fetch.calls) == 5                          # 중간에 멈추지 않음


def test_pypi_down_does_not_block_npm():
    fetch = fake_fetch({PYPI.format(n): OSError() for n in "abc"})
    scanner = fp.FakePackageScanner(fetch)
    scanner.scan_text("requirements.txt", "a\nb\nc\nd\n")
    npm = scanner.scan_text("package.json", '{"dependencies": {"ghost-npm": "1"}}')
    assert NPM.format("ghost-npm") in fetch.calls
    assert npm[0]["title"].startswith("[가짜 의심]")


def test_lookup_limit(monkeypatch):
    monkeypatch.setattr(fp, "MAX_LOOKUPS", 2)
    findings, fetch = scan_req("a\nb\nc\n", {PYPI.format(n): OK_PYPI for n in "abc"})
    assert len(fetch.calls) == 2
    assert len(findings) == 1 and "조회 한도" in findings[0]["title"]   # 버리지 않고 확인 불가로 보고


def test_time_budget():
    now = [1000.0]
    scanner = fp.FakePackageScanner(fake_fetch({PYPI.format(n): OK_PYPI for n in "ab"}), clock=lambda: now[0])
    assert scanner.scan_text("requirements.txt", "a\n") == []
    now[0] += fp.TIME_BUDGET + 1                          # 60초 넘게 지남
    findings = scanner.scan_text("requirements.txt", "b\n")
    assert len(scanner.fetch.calls) == 1
    assert "시간 초과" in findings[0]["title"]


# ───────────────────── E. 결과 형식 ─────────────────────

def test_fingerprint_does_not_depend_on_line():
    one, _ = scan_req("ghost\n")
    two, _ = scan_req("requests\nnumpy\nghost\n", {PYPI.format(n): OK_PYPI for n in ("requests", "numpy")})
    assert one[0]["line"] != two[0]["line"]
    assert one[0]["fingerprint"] == two[0]["fingerprint"]  # 줄이 밀려도 같은 결과로 인식


def test_long_values_fit_db_columns():
    def check(f):
        assert len(f["title"]) <= 255 and len(f["file"]) <= 255 and len(f["fingerprint"]) <= 255
        return f

    # PyPI 이름은 길이 제한이 없음 -> 300자 이름이면 title이 255자를 넘음
    f = check(scan_req("p" * 300 + "\n")[0][0])
    assert f["title"].endswith("...")

    # npm 최대 214자 + 가장 긴 사유(삭제된 패키지)면 title이 255자를 넘음
    unpublished = {NPM.format("n" * 214): (200, b"{}", "")}
    f = check(fp.FakePackageScanner(fake_fetch(unpublished)).scan_text(
        "package.json", '{"dependencies": {"%s": "1"}}' % ("n" * 214))[0])
    assert f["title"].endswith("...")

    # 깊은 경로: 앞을 자르고 파일 이름은 남김, fingerprint는 해시로 줄여도 서로 구분됨
    def deep(name):
        return check(fp.FakePackageScanner(fake_fetch({})).scan_text(
            "deep/" * 60 + "package.json", '{"dependencies": {"%s": "1.0.0"}}' % name)[0])
    a, b = deep("a" * 214), deep("b" * 214)
    assert a["file"].endswith("package.json")
    assert a["fingerprint"].startswith("fake-package:sha256:") and a["fingerprint"] != b["fingerprint"]


def test_findings_pass_through_aggregator():
    findings, _ = scan_req("ghost\nflaky\n", {PYPI.format("flaky"): OSError()})
    merged = aggregator.merge(findings)
    assert len(merged) == 2
    assert {f["fingerprint"] for f in merged} == {f["fingerprint"] for f in findings}
    assert [f["severity"] for f in merged] == ["HIGH", "UNKNOWN"]   # 위험도 순 정렬


# ───────────────────── F. 저장소 탐색 ─────────────────────

@pytest.mark.parametrize("path, ecosystem", [
    ("requirements.txt", "PyPI"),
    ("requirements-dev.txt", "PyPI"),
    ("Requirements.TXT", "PyPI"),
    ("backend/requirements.txt", "PyPI"),
    ("requirements/base.txt", "PyPI"),
    ("package.json", "npm"),
    ("web/Package.json", "npm"),
    ("package-lock.json", None),
    ("requirements.md", None),
    ("setup.py", None),
    ("reqs.txt", None),
    ("docs/notes.txt", None),
])
def test_target_files(path, ecosystem):
    kind = fp._ecosystem_of(path)
    assert (kind[0] if kind else None) == ecosystem


def test_non_target_file_is_ignored():
    findings, fetch = scan_req("ghost\n", file="notes.txt")
    assert findings == [] and fetch.calls == []


def test_scan_repo(tmp_path, monkeypatch):
    (tmp_path / "requirements.txt").write_text("ghost-pkg\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("ghost-readme\n", encoding="utf-8")    # 대상 아님
    (tmp_path / "requirements").mkdir()
    (tmp_path / "requirements" / "dev.txt").write_text("ghost-dev\n", encoding="utf-8")
    (tmp_path / "node_modules" / "x").mkdir(parents=True)
    (tmp_path / "node_modules" / "x" / "package.json").write_text('{"dependencies":{"zz":"1"}}')
    (tmp_path / ".git").mkdir()
    (tmp_path / ".git" / "requirements.txt").write_text("in-git\n")
    secret = tmp_path.parent / "secret.env"
    secret.write_text("DB_PASSWORD_hunter2\n", encoding="utf-8")
    try:
        os.symlink(secret, tmp_path / "requirements-prod.txt")          # 서버 파일을 가리키는 링크
        os.symlink(tmp_path / "requirements", tmp_path / "linked-dir")  # 링크 폴더도 안 따라감
    except OSError:
        pass   # Windows는 관리자 권한/개발자 모드가 없으면 링크를 못 만듦 -> 링크 검사만 생략 (CI는 Linux라 검사)
    # Windows PowerShell 'pip freeze >' 결과처럼 UTF-16, 메모장 저장처럼 UTF-8 BOM
    (tmp_path / "requirements-win.txt").write_bytes("ghost-win==1.0\r\n".encode("utf-16"))
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / "package.json").write_bytes(b'\xef\xbb\xbf{"dependencies":{"ghost-npm":"1"}}')
    # 큰 파일은 읽지 않고 '확인 불가'
    monkeypatch.setattr(fp, "MAX_FILE_SIZE", 100)
    (tmp_path / "requirements-big.txt").write_text("x\n" * 100)

    findings = fp.scan(str(tmp_path), fetch=fake_fetch({}))
    by_file = {f["file"]: f for f in findings}
    assert sorted(by_file) == ["requirements-big.txt", "requirements-win.txt", "requirements.txt",
                               "requirements/dev.txt", "web/package.json"]
    assert by_file["requirements-big.txt"]["severity"] == "UNKNOWN"
    assert by_file["web/package.json"]["title"].startswith("[가짜 의심] ghost-npm")
    assert not any("hunter2" in f["title"] for f in findings)


# ───────────────────── G. 실제 HTTP 함수와 worker 연결 ─────────────────────

class _Resp(io.BytesIO):
    """urlopen이 돌려주는 응답 흉내"""
    def __init__(self, status, body, ctype):
        super().__init__(body)
        self.status = status
        self.headers = {"Content-Type": ctype}


def test_http_fetch(monkeypatch):
    seen = []

    def fake_urlopen(req, timeout):
        seen.append((req.full_url, req.get_method(), timeout))
        if "ghost" in req.full_url:
            raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, io.BytesIO(b""))
        if "down" in req.full_url:
            raise urllib.error.URLError("no route")
        return _Resp(200, b'{"latest":"1.0.0"}', "application/json")

    monkeypatch.setattr(fp.urllib.request, "urlopen", fake_urlopen)
    assert fp._http_fetch("https://x/ok", "GET") == (200, b'{"latest":"1.0.0"}', "application/json")
    assert fp._http_fetch("https://x/ok", "HEAD") == (200, b"", "application/json")   # HEAD는 본문 안 읽음
    assert fp._http_fetch("https://x/ghost", "GET") == (404, b"", "")                  # 404는 예외가 아니라 응답
    with pytest.raises(urllib.error.URLError):
        fp._http_fetch("https://x/down", "GET")
    assert seen[1][1] == "HEAD" and all(t == fp.TIMEOUT for _, _, t in seen)

    # 기본 fetch(_http_fetch)로 끝까지: 404 -> 가짜 의심, 연결 실패 -> 확인 불가
    assert fp.check_pypi("ghost", fp._http_fetch)[0] == fp.NOT_FOUND
    assert fp.check_npm("down", fp._http_fetch)[0] == fp.UNKNOWN


def test_command_line(tmp_path, monkeypatch, capsys):
    # python -m scanners.fake_package <폴더> [--out 파일]
    (tmp_path / "requirements.txt").write_text("ghost\n", encoding="utf-8")
    real_scan = fp.scan
    monkeypatch.setattr(fp, "scan", lambda repo: real_scan(repo, fetch=fake_fetch({})))

    monkeypatch.setattr(sys, "argv", ["fake_package", str(tmp_path)])
    fp._main()
    out = capsys.readouterr()
    assert '"[가짜 의심] ghost (PyPI)' in out.out and "결과 1건" in out.err

    out_file = tmp_path / "findings.json"
    monkeypatch.setattr(sys, "argv", ["fake_package", str(tmp_path), "--out", str(out_file)])
    fp._main()
    assert '"fake-package:PyPI:ghost:requirements.txt"' in out_file.read_text(encoding="utf-8")


def test_worker_runs_fake_package_scan(monkeypatch):
    pytest.importorskip("valkey")
    import main

    saved = {}
    monkeypatch.setattr(main, "clone_repo", lambda url, target: None)
    monkeypatch.setattr(main.gitleaks, "scan", lambda path: [])
    monkeypatch.setattr(main.trivy, "scan", lambda path: [])
    monkeypatch.setattr(main.fake_package, "scan", lambda path: fp.FakePackageScanner(
        fake_fetch({})).scan_text("requirements.txt", "ghost\n"))
    monkeypatch.setattr(main.aggregator, "get_connection", lambda: type("C", (), {"close": lambda self: None})())
    monkeypatch.setattr(main.aggregator, "save_to_db",
                        lambda conn, repo, findings: saved.update(findings=findings) or {"saved": 1, "fixed": 0})

    result = main.process_job({"repo_url": "https://github.com/user/repo"})
    assert [f["tool"] for f in saved["findings"]] == ["fake-package"]
    assert result["public_readiness"] == {"can_publish": True, "reasons": []}
