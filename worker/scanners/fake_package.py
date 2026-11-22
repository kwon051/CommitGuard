"""AI가 지어낸 가짜 패키지 탐지 

흐름: 저장소에서 requirements*.txt·package.json 찾기 -> 패키지 이름 뽑기
      -> PyPI·npm에 실제로 있는지 조회 -> 공통 형식 v1(Finding) 변환

판정:
    있음                      -> 결과 없음
    없음(404)·삭제됨           -> '가짜 의심' (HIGH)
    조회 실패(네트워크·429·5xx) -> '확인 불가' (UNKNOWN)

fingerprint 규칙: fake-package:생태계:패키지명:파일
    '가짜 의심'과 '확인 불가'가 같은 fingerprint를 쓴다.
    -> 지난번에 가짜 의심이던 패키지가 이번엔 네트워크 오류로 확인 불가가 돼도
       fixed로 잘못 바뀌지 않고, 같은 항목의 내용만 갱신된다 (aggregator UPSERT).

명령줄 사용 (worker 폴더에서):
    python -m scanners.fake_package <저장소경로> --out findings.json
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import PurePosixPath
from typing import Any, Callable
from urllib.parse import quote

# PyPI: HEAD로 존재 여부만 본다 (GET 본문은 boto3가 3MB가 넘을 만큼 큼)
PYPI_URL = "https://pypi.org/pypi/{name}/json"
# npm: dist-tags만 받는다 (전체 정보는 react가 3MB, dist-tags는 수백 바이트)
NPM_URL = "https://registry.npmjs.org/-/package/{name}/dist-tags"

TIMEOUT = 5                 # 조회 1번 최대 대기(초)
MAX_LOOKUPS = 300           # 검사 1번당 최대 조회 수
MAX_FAILS_IN_ROW = 3        # 연속으로 이만큼 실패하면 레지스트리가 죽은 걸로 보고 나머지는 조회 X
TIME_BUDGET = 60            # 전체 조회에 쓸 최대 시간(초). worker가 한 검사에 묶여 있지 않게
MAX_FILE_SIZE = 1_000_000   # 1MB 넘는 의존성 파일은 읽지 않음
MAX_BODY = 64 * 1024        # npm dist-tags 응답 최대 크기
DB_TEXT_MAX = 255           # db/init.sql: file·title·fingerprint가 VARCHAR(255)
SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__"}

TOOL = "fake-package"
EXISTS, NOT_FOUND, UNKNOWN = "exists", "not_found", "unknown"


PYPI_NAME_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?")

NPM_NAME_RE = re.compile(r"^(?:@[a-z0-9~-][a-z0-9._~-]*/)?[a-z0-9~-][a-z0-9._~-]*$", re.IGNORECASE)
NPM_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")

Fetch = Callable[[str, str], "tuple[int, bytes, str]"]


#  파일 파싱 -> 패키지 이름만 뽑아냄
def _logical_lines(text: str):
    """줄 끝 '\\'로 이어진 줄을 한 줄로 합친다. (시작 줄 번호, 내용)"""
    buf, start = "", None
    for no, raw in enumerate(text.splitlines(), start=1):
        if start is None:
            start = no
        s = raw.rstrip()
        if s.endswith("\\"): 
            buf += s[:-1] + " "
            continue
        yield start, buf + raw
        buf, start = "", None
    if buf:     # 파일이 '\'로 끝나도 버리지 X
        yield start, buf


def parse_requirements(text: str) -> list[tuple[str, int]]:
    """requirements.txt -> [(패키지이름, 줄번호)]. PyPI에서 받지 않는 줄은 건너뜀."""
    found = []
    for line_no, line in _logical_lines(text):
        # '#'이 줄 맨 앞이거나 앞에 공백이 있을 때만 주석 (pip 규칙, URL의 #egg= 보호)
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line or line.startswith("-"):    
            continue
        m = PYPI_NAME_RE.match(line)              # ./local, /abs 같은 경로는 여기서 필터링
        if not m:
            continue
        rest = line[m.end():].lstrip()
        # 이름 뒤에 올 수 있는 것: 없음 [extras] (버전) 버전기호 ;마커 @URL
        if rest and rest[0] not in "[(<>=!~;@":
            continue
        if rest.startswith("@"):                  # "pkg @ https://..." 는 URL에서 받음
            continue
        found.append((m.group(0), line_no))
    return found


def _find_json_line(lines: list[str], section: str, key: str) -> int | None:
    """package.json에서 section("dependencies" 등) 줄부터 아래로 "key": 가 처음 나오는 줄 번호 (못 찾으면 None).
    scripts 같은 다른 칸에 같은 이름의 키("build" 등)가 먼저 나와도 엉뚱한 줄을 가리키지 X"""
    sec = re.compile(r'"' + re.escape(section) + r'"\s*:')
    pat = re.compile(r'"' + re.escape(key) + r'"\s*:')
    start = next((i for i, line in enumerate(lines) if sec.search(line)), 0)
    for i in range(start, len(lines)):
        if pat.search(lines[i]):
            return i + 1
    return None


def parse_package_json(text: str) -> list[tuple[str, int | None]]:
    """package.json -> [(패키지이름, 줄번호)]. JSON이 깨졌으면 ValueError."""
    data = json.loads(text)
    if not isinstance(data, dict):
        raise ValueError("package.json 최상위가 객체가 아님")
    lines = text.splitlines()
    found, seen = [], set()
    for section in NPM_SECTIONS:
        deps = data.get(section)
        if not isinstance(deps, dict):
            continue
        for key, spec in deps.items():
            name = key
            spec = spec if isinstance(spec, str) else ""
            if spec.startswith("npm:"):
                
                target = spec[4:]
                at = target.find("@", 1)       
                name = target if at == -1 else target[:at]
            elif ":" in spec or "/" in spec:
                # file: link: workspace: git+ github: https:// user/repo -> 레지스트리 아님
                continue
            if name in seen or not (0 < len(name) <= 214 and NPM_NAME_RE.match(name)):
                continue
            seen.add(name)
            found.append((name, _find_json_line(lines, section, key)))
    return found


# 레지스트리 조회 -> 진짜 해당 레지스트리가 존재하는지 확인
def _norm_pypi(name: str) -> str:
    """PEP 503 정규화: Foo_Bar, foo.bar, foo-bar는 같은 패키지 (PyPI는 정규화 안 하면 404)."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _http_fetch(url: str, method: str = "GET") -> tuple[int, bytes, str]:
    """실제 HTTP 요청. 네트워크 오류는 예외로 올려 보낸다.
    requests 대신 표준 라이브러리 urllib을 쓴다 (worker 이미지·CI에 requests가 없음)."""
    req = urllib.request.Request(url, method=method, headers={
        "Accept": "application/json", "User-Agent": "CommitGuard-fake-package"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read(MAX_BODY + 1) if method == "GET" else b""
            return resp.status, body, resp.headers.get("Content-Type", "")
    except urllib.error.HTTPError as e:   # 404·429·5xx는 '응답'이니 상태 코드로 돌려준다
        e.close()
        return e.code, b"", ""


def _request(fetch: Fetch, url: str, method: str):
    """fetch 실행. 타임아웃·DNS 실패·연결 끊김이면 (None, 사유)."""
    try:
        return fetch(url, method), ""
    except (OSError, http.client.HTTPException) as e:   # URLError·TimeoutError도 OSError
        return None, f"네트워크 오류({type(e).__name__})"


def check_pypi(name: str, fetch: Fetch) -> tuple[str, str]:
    resp, err = _request(fetch, PYPI_URL.format(name=quote(_norm_pypi(name), safe="")), "HEAD")
    if resp is None:
        return UNKNOWN, err
    status, _, ctype = resp
    if status == 404:
        return NOT_FOUND, "PyPI에 없는 패키지"
    if status != 200:
        return UNKNOWN, f"PyPI 응답 HTTP {status}"
    if "json" not in ctype.lower():               # 200인데 JSON이 아니면 프록시 안내 페이지 등
        return UNKNOWN, "예상과 다른 응답"
    return EXISTS, ""


def check_npm(name: str, fetch: Fetch) -> tuple[str, str]:
   
    resp, err = _request(fetch, NPM_URL.format(name=quote(name, safe="@")), "GET")
    if resp is None:
        return UNKNOWN, err
    status, body, _ = resp
    if status == 404:
        return NOT_FOUND, "npm에 없는 패키지"
    if status != 200:
        return UNKNOWN, f"npm 응답 HTTP {status}"
    if len(body) > MAX_BODY:
        return UNKNOWN, "응답이 너무 큼"
    try:
        tags = json.loads(body)
    except ValueError:                            # 깨진 JSON, 잘못된 인코딩 모두
        return UNKNOWN, "응답 해석 실패"
    if not isinstance(tags, dict):
        return UNKNOWN, "예상과 다른 응답"
    latest = tags.get("latest")
    if not isinstance(latest, str) or not latest:
        return NOT_FOUND, "설치할 수 있는 버전이 없음 (삭제된 패키지)"
    if latest.endswith("-security"):
        # npm이 악성 패키지를 지우고 0.0.1-security 빈 패키지로 이름만 막아 둔 경우 (예: crossenv)
        return NOT_FOUND, "npm이 악성 패키지로 삭제한 이름"
    return EXISTS, ""


# 공통 형식 v1 변환 
def _fit(text: str, limit: int = DB_TEXT_MAX) -> str:
    """VARCHAR(255)를 넘으면 MySQL 저장이 실패해 검사 전체가 날아가므로 자름 """
    return text if len(text) <= limit else text[:limit - 3] + "..."


def make_fingerprint(ecosystem: str, name: str, file: str) -> str:
    """fake-package:생태계:패키지명:파일. 255자를 넘으면 해시로 줄임"""
    fp = f"{TOOL}:{ecosystem}:{name}:{file}"
    if len(fp) > DB_TEXT_MAX:
        fp = f"{TOOL}:sha256:{hashlib.sha256(fp.encode('utf-8')).hexdigest()}"
    return fp


def to_finding(ecosystem: str, name: str, key: str, file: str, line: int | None,
               status: str, reason: str) -> dict[str, Any]:
   
    if status == NOT_FOUND:
        severity = "HIGH"
        title = f"[가짜 의심] {name} ({ecosystem}) - {reason}"
        why = (f"{ecosystem}에서 '{name}' 패키지를 설치할 수 없습니다. AI가 지어낸 이름일 수 있고, "
               "누군가 이 이름으로 악성 패키지를 올리면 그대로 설치됩니다.")
        fix = "이름 철자를 확인하고, 실제로 있는 패키지로 바꾸거나 이 줄을 지우세요."
    else:
        severity = "UNKNOWN"
        title = f"[확인 불가] {name} ({ecosystem}) - {reason}"
        why = "레지스트리 조회에 실패해서 실제로 있는 패키지인지 확인하지 못했습니다."
        fix = "잠시 후 다시 검사하세요."
    return {
        "tool": TOOL,
        "rule_id": TOOL,              # 두 판정 모두 같은 값 (UPSERT가 rule_id는 갱신하지 않음)
        "fingerprint": make_fingerprint(ecosystem, key, file),
        "severity": severity,
        "file": file,
        "line": line,
        "title": _fit(title),
        "why": why,
        "fix": fix,
        "status": "open",
    }


# 스캐너 -> 위의 함수들을 묶어서 실행
def _ecosystem_of(rel_path: str):
    """경로로 검사 대상인지 판단. requirements*.txt, requirements/*.txt, package.json"""
    p = PurePosixPath(rel_path)
    name = p.name.lower()
    if name == "package.json":
        return "npm", parse_package_json
    if name.endswith(".txt") and (name.startswith("requirements") or p.parent.name.lower() == "requirements"):
        return "PyPI", parse_requirements
    return None


def _read_text(path: str) -> str:
    with open(path, "rb") as f:
        raw = f.read()
    
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")     # 맨 앞 BOM 제거


class FakePackageScanner:
    def __init__(self, fetch: Fetch | None = None, clock: Callable[[], float] = time.monotonic):
        self.fetch = fetch or _http_fetch
        self.clock = clock
        self.cache: dict[tuple[str, str], tuple[str, str]] = {}   # 같은 패키지 재조회 방지
        self.lookups = 0
        self.fails_in_row = {"PyPI": 0, "npm": 0}   # PyPI가 죽어도 npm 조회는 계속하도록 따로 센다
        self.deadline: float | None = None

    def _lookup(self, ecosystem: str, key: str) -> tuple[str, str]:
        if (ecosystem, key) in self.cache:
            return self.cache[(ecosystem, key)]
        if self.deadline is None:
            self.deadline = self.clock() + TIME_BUDGET
        # 한도에 걸린 것도 조용히 버리지 않고 '확인 불가'로 보고한다
        if self.lookups >= MAX_LOOKUPS:
            return UNKNOWN, f"조회 한도({MAX_LOOKUPS}개) 초과로 확인 안 함"
        if self.fails_in_row[ecosystem] >= MAX_FAILS_IN_ROW:
            return UNKNOWN, "레지스트리 조회가 계속 실패해 확인 안 함"
        if self.clock() > self.deadline:
            return UNKNOWN, "시간 초과로 확인 안 함"

        self.lookups += 1
        checker = check_pypi if ecosystem == "PyPI" else check_npm
        result = checker(key, self.fetch)
        self.fails_in_row[ecosystem] = self.fails_in_row[ecosystem] + 1 if result[0] == UNKNOWN else 0
        self.cache[(ecosystem, key)] = result
        return result

    def scan_text(self, file: str, text: str) -> list[dict[str, Any]]:
        """파일 하나(경로, 내용) -> 공통 형식 목록."""
        kind = _ecosystem_of(file)
        if kind is None:
            return []
        ecosystem, parser = kind
        file = file if len(file) <= DB_TEXT_MAX else "..." + file[-(DB_TEXT_MAX - 3):]
        try:
            packages = parser(text)
        except ValueError:
            return [to_finding(ecosystem, "(파일 전체)", "*", file, None, UNKNOWN, "파일 형식 해석 실패")]

        findings, seen = [], set()
        for name, line in packages:
            key = _norm_pypi(name) if ecosystem == "PyPI" else name   # npm은 대소문자 구분
            status, reason = self._lookup(ecosystem, key)
            if status == EXISTS:
                continue
            f = to_finding(ecosystem, name, key, file, line, status, reason)
            if f["fingerprint"] not in seen:          # 같은 파일에 같은 패키지가 두 번 적힌 경우
                seen.add(f["fingerprint"])
                findings.append(f)
        return findings

    def scan_repo(self, repo_path: str) -> list[dict[str, Any]]:
        findings = []
        for root, dirs, files in os.walk(repo_path):          # 심볼릭 링크 폴더는 기본으로 따라가지 X
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            for fname in files:
                path = os.path.join(root, fname)
                rel = os.path.relpath(path, repo_path).replace(os.sep, "/")
                kind = _ecosystem_of(rel)
                if kind is None:
                    continue
                # 심볼릭 링크 무시: requirements.txt -> /app/.env 처럼 서버 파일을 가리키면
                # 그 내용이 '패키지 이름'으로 결과 화면에 새어 나갈 수 있다
                if os.path.islink(path):
                    continue
                if os.path.getsize(path) > MAX_FILE_SIZE:
                    findings.append(to_finding(kind[0], "(파일 전체)", "*", _fit(rel), None,
                                               UNKNOWN, "파일이 너무 커서 검사 하지 않음"))
                    continue
                findings.extend(self.scan_text(rel, _read_text(path)))
        return findings


def scan(repo_path: str, fetch: Fetch | None = None) -> list[dict[str, Any]]:
    """worker가 호출하는 진입점: 저장소 경로 -> 공통 형식 목록."""
    return FakePackageScanner(fetch).scan_repo(str(repo_path))


def _main() -> None:
    p = argparse.ArgumentParser(description="가짜 패키지 탐지 결과를 공통 형식으로 출력")
    p.add_argument("repo", help="검사할 저장소 폴더")
    p.add_argument("--out", help="공통 형식 JSON 저장 경로 (생략하면 화면에 출력)")
    args = p.parse_args()

    findings = scan(args.repo)
    text = json.dumps(findings, ensure_ascii=False, indent=2) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
    else:
        print(text, end="")
    print(f"[fake-package] 결과 {len(findings)}건", file=sys.stderr)


if __name__ == "__main__":
    _main()