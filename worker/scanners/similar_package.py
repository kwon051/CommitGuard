"""유사 이름 가짜 패키지 탐지 

흐름: requirements*.txt·package.json에서 패키지 이름 뽑기 (fake_package의 파서를 그대로 씀)
      -> 유명 패키지 목록(typosquat_top.json)과 철자 비교
      -> 한두 글자만 다르면 '유사 이름 의심' -> 공통 형식 v1(Finding) 변환

철자 거리: 글자 1개 바꾸기·넣기·빼기, 옆 글자끼리 순서 바꾸기를 각각 1로 센다.
    requests -> reqeusts (순서 바꿈 1), requets (빼기 1), requestss (넣기 1)

판정 기준 (두 이름 중 짧은 쪽 길이로 정한다)
    3글자 이하   : 비교하지 않음 (six·tox·ws처럼 짧은 정상 이름끼리 너무 많이 겹침)
    4글자        : 옆 글자 순서만 바뀐 경우만 (tqdm -> tqmd)
    5~11글자     : 1글자 차이
    12글자 이상  : 2글자 차이까지 (beautifulsoup4 -> beatifulsoup)

잡지 않는 경우
    - 유명 목록에 있는 이름 자신 (PyPI는 Foo_Bar = foo-bar, npm은 대소문자 무시)
    - KNOWN_DISTINCT: 이름은 비슷하지만 서로 다른 정상 패키지 (preact·react, scapy·scipy)
    - npm 유명 조직 안의 이름 (@types/nodee): 조직 주인만 올릴 수 있어서 남이 흉내 낼 수 없음
npm @조직/이름은 조직 이름을 유명 조직과 비교한다 (@typse/node -> @types 흉내).

명령줄 사용 (worker 폴더에서):
    python -m scanners.typosquat <저장소경로> --out findings.json
"""

from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Iterable

from . import fake_package as fp

DATA_FILE = Path(__file__).with_name("similar_package_top.json")
TOOL = "similar-package"
SEVERITY = "MEDIUM"      # 정상 패키지일 수도 있어서 HIGH는 아님 (레지스트리에 없으면 fake_package가 HIGH로 잡음)
MAX_NAMES = 2000         # 검사 1번당 비교할 최대 이름 수 (1MB짜리 파일로 worker를 오래 붙잡지 못하게)

# 이름은 비슷하지만 서로 다른 정상 패키지 (make_typosquat_data.py --report 결과 중 확실히 정상인 것만)
# 인기 목록에도 진짜 타이포스쿼팅 이름(tdqm, pyyml 등)이 섞여 있어서, 확실하지 않은 이름은 넣지 않았다.
# PyPI는 정규화된 이름(소문자, -_. -> -), npm은 소문자로 적는다.
KNOWN_DISTINCT = {
    "PyPI": frozenset({
        "aresponses", "bpython", "cattrs", "cchardet", "crick", "cronitor", "cssselect", "cwcwidth",
        "dataset", "fastai", "futures", "gitdb2", "grequests", "gsutil", "hjson", "hyper", "identity",
        "ipytest", "isolate", "jiwer", "jsonpath", "jsons", "langchain-cohere", "markdown-it-pyrs", "markdown2",
        "ncclient", "opentelemetry-instrumentation-wsgi", "parse", "parsy", "polars-runtime-64", "pyaml",
        "pyhdf", "pymssql", "pymupdfb", "pypdf2", "pypdf4", "pyshark", "pytest-csv", "scapy", "scipp", "scrypt",
        "simpy", "smmap2", "spython", "torchx", "ujson", "unicorn", "uri-template", "usort", "vyper", "willow",
        "wsgiref", "x-transformers",
    }),
    "npm": frozenset({
        "ansicolors", "aws-cdk", "buffers", "callsite", "clipboard", "colord", "colors", "cookies", "csv-parser",
        "dargs", "dom-serialize", "es-module-lexer", "eslint-plugin-es", "eslint-plugin-import-x",
        "eslint-plugin-jsonc", "eslint-plugin-tsdoc", "event-emitter", "eventemitter2", "foreach", "gaxios",
        "global", "ip-regex", "is-base64", "is-object", "is-regexp", "is-typedarray", "isomorphic-unfetch",
        "isstream", "jsdoc", "json-pointer", "jsonschema", "just-diff", "level", "lodash.set", "makeerror",
        "mem-fs", "merge", "mpath", "mquery", "mssql", "nprogress", "oas-resolver", "one-time", "optimism",
        "parse-url", "parseuri", "png-js", "postcss-less", "postcss-values-parser", "preact", "prompt",
        "rambda", "redent", "seed-random", "split", "stream", "stream-combiner2", "stylus-loader", "synckit",
        "trough", "urijs", "watch", "wordwrap", "xml-js", "xmlbuilder2", "yargs-unparser",
    }),
    "scope": frozenset({"aws-cdk"}),
}


class TyposquatDataError(ValueError):
    """유명 패키지 목록 파일이 없거나 깨짐. 조용히 넘어가지 않고 검사를 실패시킨다.
    (빈 결과로 저장하면 지난 검사의 유사 이름 항목이 fixed로 잘못 바뀐다)"""


# 철자 거리
def _limit(a: str, b: str) -> int:
    """두 이름 사이에 허용하는 최대 거리. 0이면 비교하지 않는다."""
    short = min(len(a), len(b))
    if short <= 3:
        return 0
    if short == 4:
        return 1 if _is_adjacent_swap(a, b) else 0
    return 1 if short < 12 else 2


def _is_adjacent_swap(a: str, b: str) -> bool:
    """옆 글자 두 개의 순서만 바뀌었는지 (tqdm <-> tqmd)"""
    if len(a) != len(b):
        return False
    diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]


def distance(a: str, b: str, limit: int) -> int:
    """철자 거리 (Damerau-Levenshtein의 OSA 방식). limit을 넘으면 계산을 멈추고 limit+1을 돌려준다."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > limit:        # 길이 차이만으로 이미 limit 초과
        return limit + 1
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i in range(1, len(a) + 1):
        cur = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            v = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost)     # 빼기, 넣기, 바꾸기
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                v = min(v, prev2[j - 2] + 1)                              # 옆 글자 순서 바꾸기
            cur[j] = v
        if min(cur) > limit:                 # 이 줄이 전부 limit을 넘으면 뒤는 더 작아질 수 없음
            return limit + 1
        prev2, prev = prev, cur
    return prev[-1] if prev[-1] <= limit else limit + 1


def _deletes(word: str, k: int) -> set[str]:
    """글자를 최대 k개 뺀 모든 변형 (자기 자신 포함)"""
    out, frontier = {word}, {word}
    for _ in range(k):
        frontier = {w[:i] + w[i + 1:] for w in frontier for i in range(len(w))}
        out |= frontier
    return out


def _depth(length: int) -> int:
    """이 길이의 이름이 가질 수 있는 최대 허용 거리 (_limit 기준)"""
    return 0 if length < 4 else 1 if length < 12 else 2


class PopularIndex:
    """유명 이름 목록 + 빠른 검색용 색인.

    이름마다 유명 목록 전체(1000개)와 거리를 재면 느리다. 대신 '글자를 빼서 같아지는 변형'으로 후보만 고른다.
    거리가 k 이하인 두 이름은 각각 글자를 최대 k개 빼면 반드시 같은 문자열이 나온다.
        requests -(e 빼기)-> requsts <-(e 빼기)- reqeusts
    """

    def __init__(self, names: Iterable[str]):
        self.names = list(dict.fromkeys(names))               # 인기순 유지, 중복 제거
        self.rank = {n: i for i, n in enumerate(self.names)}  # 같은 거리면 더 유명한 쪽을 고른다
        self.max_len = max((len(n) for n in self.names), default=0)
        self.by_variant: dict[str, list[str]] = {}
        for name in self.names:
            for v in _deletes(name, _depth(len(name))):
                self.by_variant.setdefault(v, []).append(name)

    def closest(self, name: str) -> tuple[str, int] | None:
        """가장 가까운 유명 이름 (이름, 거리). 유명 목록에 있는 이름 자신이거나 비슷한 게 없으면 None."""
        if name in self.rank or len(name) < 4 or len(name) > self.max_len + 2:
            return None
        best: tuple[int, int, str] | None = None
        candidates = {t for v in _deletes(name, _depth(len(name))) for t in self.by_variant.get(v, ())}
        for target in candidates:
            limit = _limit(name, target)
            if limit == 0:
                continue
            d = distance(name, target, limit)
            if d <= limit and (best is None or (d, self.rank[target]) < best[:2]):
                best = (d, self.rank[target], target)
        return (best[2], best[0]) if best else None


# 유명 목록 읽기
def validate_data(data: Any) -> None:
    """목록 파일 형식 검사. 이상하면 TyposquatDataError."""
    if not isinstance(data, dict):
        raise TyposquatDataError("최상위가 객체가 아님")
    for key in ("pypi", "npm", "npm_scopes"):
        names = data.get(key)
        if not isinstance(names, list) or not names:
            raise TyposquatDataError(f"'{key}' 목록이 없거나 비어 있음")
        for n in names:
            if not isinstance(n, str):
                raise TyposquatDataError(f"'{key}'에 문자열이 아닌 값: {n!r}")
            if key == "pypi":
                ok = bool(fp.PYPI_NAME_RE.fullmatch(n)) and fp._norm_pypi(n) == n
            elif key == "npm":
                ok = not n.startswith("@") and n == n.lower() and len(n) <= 214 and bool(fp.NPM_NAME_RE.match(n))
            else:
                ok = n == n.lower() and bool(fp.NPM_NAME_RE.match(f"@{n}/x"))
            if not ok:
                raise TyposquatDataError(f"'{key}'에 잘못된 이름: {n!r}")


def load_data(path: str | os.PathLike | None = None) -> dict[str, Any]:
    path = DATA_FILE if path is None else path
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError) as e:
        raise TyposquatDataError(f"유명 패키지 목록을 읽을 수 없음 ({path}): {e}") from e
    validate_data(data)
    return data


def build_indexes(pypi: Iterable[str], npm: Iterable[str], scopes: Iterable[str]) -> dict[str, PopularIndex]:
    return {"PyPI": PopularIndex(pypi), "npm": PopularIndex(npm), "scope": PopularIndex(scopes)}


@functools.lru_cache(maxsize=1)
def default_indexes() -> dict[str, PopularIndex]:
    """typosquat_top.json으로 만든 색인. worker가 켜져 있는 동안 한 번만 만든다 (실패하면 매번 다시 시도)."""
    data = load_data()
    return build_indexes(data["pypi"], data["npm"], data["npm_scopes"])


# 이름 1개 판정
def compare_key(ecosystem: str, name: str) -> str:
    """비교용 이름. PyPI: PEP 503 정규화, npm: 소문자 (npm은 새 패키지에 대문자를 못 씀)"""
    return fp._norm_pypi(name) if ecosystem == "PyPI" else name.lower()


def check_name(indexes: dict[str, PopularIndex], ecosystem: str, name: str) -> tuple[str, str, int] | None:
    """('package' 또는 'scope', 비슷한 유명 이름, 거리). 문제없으면 None."""
    key = compare_key(ecosystem, name)
    if ecosystem == "npm" and key.startswith("@"):
        scope = key[1:].split("/", 1)[0]
        if scope in KNOWN_DISTINCT["scope"]:
            return None
        hit = indexes["scope"].closest(scope)       # 유명 조직 자신이면 None (조직 주인만 올릴 수 있음)
        return ("scope", "@" + hit[0], hit[1]) if hit else None
    if key in KNOWN_DISTINCT[ecosystem]:
        return None
    hit = indexes[ecosystem].closest(key)
    return ("package", hit[0], hit[1]) if hit else None


# 공통 형식 v1 변환
def make_fingerprint(ecosystem: str, key: str, file: str) -> str:
    """typosquat:생태계:패키지명:파일. 255자를 넘으면 해시로 줄임"""
    fingerprint = f"{TOOL}:{ecosystem}:{key}:{file}"
    if len(fingerprint) > fp.DB_TEXT_MAX:
        fingerprint = f"{TOOL}:sha256:{hashlib.sha256(fingerprint.encode('utf-8')).hexdigest()}"
    return fingerprint


def to_finding(ecosystem: str, name: str, key: str, file: str, line: int | None,
               kind: str, target: str, dist: int) -> dict[str, Any]:
    if kind == "scope":
        title = f"[유사 이름 의심] {name} (npm) - 비슷한 유명 조직: {target}"
        why = (f"조직 이름이 유명 조직 '{target}'에서 {dist}글자만 다릅니다. "
               "공식 조직처럼 보이게 이름을 흉내 낸 악성 패키지일 수 있습니다.")
        fix = (f"'{target}' 조직의 패키지를 쓰려던 거라면 이름을 고치세요. "
               "일부러 쓴 패키지라면 npm 페이지에서 만든 사람을 확인한 뒤 '문제 아님'으로 표시하세요.")
    else:
        title = f"[유사 이름 의심] {name} ({ecosystem}) - 비슷한 유명 패키지: {target}"
        why = (f"유명 패키지 '{target}'에서 {dist}글자만 다른 이름입니다. 공격자는 이렇게 철자가 비슷한 이름으로 "
               "악성 패키지를 올려 두고 오타로 설치되기를 기다립니다.")
        fix = (f"'{target}' 패키지를 쓰려던 거라면 이름을 고치세요. "
               f"일부러 쓴 패키지라면 {ecosystem} 페이지에서 만든 사람과 다운로드 수를 확인한 뒤 '문제 아님'으로 표시하세요.")
    return {
        "tool": TOOL,
        "rule_id": TOOL,
        "fingerprint": make_fingerprint(ecosystem, key, file),
        "severity": SEVERITY,
        "file": file,
        "line": line,
        "title": fp._fit(title),
        "why": why,
        "fix": fix,
        "status": "open",
    }


def _too_many_finding(ecosystem: str, file: str) -> dict[str, Any]:
    """MAX_NAMES를 넘어 비교하지 못한 파일. 조용히 버리지 않고 '확인 불가'로 알린다."""
    return {
        "tool": TOOL,
        "rule_id": TOOL,
        "fingerprint": make_fingerprint(ecosystem, "*", file),
        "severity": "UNKNOWN",
        "file": file,
        "line": None,
        "title": fp._fit(f"[확인 불가] (파일 일부) ({ecosystem}) - 패키지가 {MAX_NAMES}개를 넘어 나머지는 비교 안 함"),
        "why": "패키지 이름이 너무 많아서 일부는 유명 패키지와 비교하지 못했습니다.",
        "fix": "의존성 파일이 정말 이렇게 큰지 확인하세요. 필요 없는 줄을 지우고 다시 검사하세요.",
        "status": "open",
    }


# 스캐너
class TyposquatScanner:
    def __init__(self, indexes: dict[str, PopularIndex] | None = None):
        self.indexes = indexes if indexes is not None else default_indexes()
        self.cache: dict[tuple[str, str], tuple[str, str, int] | None] = {}   # 같은 이름 재계산 방지

    def scan_text(self, file: str, text: str) -> list[dict[str, Any]]:
        """파일 하나(경로, 내용) -> 공통 형식 목록."""
        kind = fp._ecosystem_of(file)
        if kind is None:
            return []
        ecosystem, parser = kind
        file = file if len(file) <= fp.DB_TEXT_MAX else "..." + file[-(fp.DB_TEXT_MAX - 3):]
        try:
            packages = parser(text)
        except ValueError:
            return []        # 깨진 package.json은 fake_package가 '확인 불가'로 이미 알린다

        findings, seen = [], set()
        for name, line in packages:
            key = compare_key(ecosystem, name)
            fingerprint_key = fp._norm_pypi(name) if ecosystem == "PyPI" else name   # fake_package와 같은 규칙
            if (ecosystem, key) not in self.cache:
                if len(self.cache) >= MAX_NAMES:
                    f = _too_many_finding(ecosystem, file)
                    if f["fingerprint"] not in seen:
                        seen.add(f["fingerprint"])
                        findings.append(f)
                    continue
                self.cache[(ecosystem, key)] = check_name(self.indexes, ecosystem, name)
            hit = self.cache[(ecosystem, key)]
            if hit is None:
                continue
            f = to_finding(ecosystem, name, fingerprint_key, file, line, *hit)
            if f["fingerprint"] not in seen:          # 같은 파일에 같은 패키지가 두 번 적힌 경우
                seen.add(f["fingerprint"])
                findings.append(f)
        return findings

    def scan_repo(self, repo_path: str) -> list[dict[str, Any]]:
        findings = []
        for root, dirs, files in os.walk(repo_path):         # 심볼릭 링크 폴더는 따라가지 않음
            dirs[:] = [d for d in dirs if d not in fp.SKIP_DIRS]
            for fname in sorted(files):
                path = os.path.join(root, fname)
                rel = os.path.relpath(path, repo_path).replace(os.sep, "/")
                if fp._ecosystem_of(rel) is None or os.path.islink(path):
                    continue        # 링크는 서버 파일(/app/.env 등)을 가리킬 수 있어서 읽지 않음
                if os.path.getsize(path) > fp.MAX_FILE_SIZE:
                    continue        # 큰 파일은 fake_package가 '확인 불가'로 이미 알린다
                findings.extend(self.scan_text(rel, fp._read_text(path)))
        return findings


def scan(repo_path: str, indexes: dict[str, PopularIndex] | None = None) -> list[dict[str, Any]]:
    """worker가 호출하는 진입점: 저장소 경로 -> 공통 형식 목록. 목록 파일이 깨졌으면 TyposquatDataError."""
    return TyposquatScanner(indexes).scan_repo(str(repo_path))


def _main() -> None:
    p = argparse.ArgumentParser(description="유사 이름 패키지 탐지 결과를 공통 형식으로 출력")
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
    print(f"[typosquat] 결과 {len(findings)}건", file=sys.stderr)


if __name__ == "__main__":
    _main()