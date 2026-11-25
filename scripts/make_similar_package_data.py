"""유사 이름 탐지(typosquat)가 비교 기준으로 쓰는 '유명 패키지 목록'을 만든다 (기능 2).

출처 (둘 다 공개 데이터, 인기순으로 정렬돼 있음)
    PyPI: hugovk/top-pypi-packages - 최근 30일 다운로드 수 상위 15,000개
    npm : tristan-f-r/npm-rank      - 인기 상위 10,000개
-> 상위 N개씩 골라 worker/scanners/typosquat_top.json 으로 저장한다. 이 파일은 저장소에 커밋한다.
   (worker는 검사할 때 인터넷에서 목록을 받지 않는다. 목록 서버가 죽어도 검사는 그대로 돈다)

실행 (저장소 루트에서)
    python scripts/make_typosquat_data.py             # 목록 만들기/갱신
    python scripts/make_typosquat_data.py --report    # 정상 패키지 오탐 측정

기준 개수: PyPI 500개, npm 1,700개 (--top-pypi, --top-npm으로 바꿀 수 있음)
    npm 순위는 '다른 패키지가 얼마나 의존하는지' 기준이라 express(209위)·nodemon(616위)·bcrypt(1138위)·
    mysql(1523위)처럼 웹 서비스에서 바로 쓰는 패키지가 뒤에 있다. 그래서 npm은 더 많이 넣는다.

--report: 기준 목록 밖의 인기 패키지(PyPI 약 14,500개, npm 약 2,000개 + 조직 160개)를 검사해서
          '유사 이름 의심'으로 잡히는 개수와 목록을 보여 준다.
          여기 나온 이름 중 정상 패키지는 typosquat.py의 KNOWN_DISTINCT에 넣는다.
          (인기 목록에도 실제 타이포스쿼팅 패키지가 섞여 있으니 전부 넣으면 안 된다)
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "worker"))

from scanners import fake_package as fp  
from scanners import similar_package as ts  

PYPI_SOURCE = "https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json"
NPM_SOURCE = "https://github.com/tristan-f-r/npm-rank/releases/download/latest/raw.json"
MAX_DOWNLOAD = 30 * 1024 * 1024    # 30MB 넘게 오면 이상한 응답으로 보고 중단 (npm 목록이 약 6MB)
TOP_SCOPES = 100                   # npm 유명 조직(@types 등)은 상위 100개


def download_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "CommitGuard-typosquat-data"})
    with urllib.request.urlopen(req, timeout=60) as resp:
        body = resp.read(MAX_DOWNLOAD + 1)
    if len(body) > MAX_DOWNLOAD:
        raise ValueError(f"응답이 너무 큼: {url}")
    return json.loads(body)


def pypi_names(data) -> list[str]:
    """인기순 PyPI 이름 (PEP 503 정규화, 중복·이상한 이름 제거)"""
    names = []
    for row in data["rows"]:
        name = row.get("project") if isinstance(row, dict) else None
        if isinstance(name, str) and fp.PYPI_NAME_RE.fullmatch(name):
            names.append(fp._norm_pypi(name))
    return list(dict.fromkeys(names))          # 순서(인기순) 유지하면서 중복 제거


def npm_names(data) -> tuple[list[str], list[str]]:
    """인기순 npm (조직 없는 이름, 조직 이름) - 둘 다 소문자"""
    plain, scopes = [], []
    for pkg in data:
        name = pkg.get("name") if isinstance(pkg, dict) else None
        if not (isinstance(name, str) and 0 < len(name) <= 214 and fp.NPM_NAME_RE.match(name)):
            continue
        name = name.lower()
        if name.startswith("@"):
            scopes.append(name[1:].split("/", 1)[0])
        else:
            plain.append(name)
    return list(dict.fromkeys(plain)), list(dict.fromkeys(scopes))


def report(pypi_all: list[str], npm_all: list[str], scopes_all: list[str]) -> None:
    """기준 목록 밖의 인기 패키지 중 '유사 이름 의심'으로 잡히는 것 (오탐 후보)"""
    idx = ts.default_indexes()
    rows = [("PyPI", n, n) for n in pypi_all] + [("npm", n, n) for n in npm_all] + \
           [("npm", f"@{s}/x", f"@{s}") for s in scopes_all]
    stats: dict[str, list[int]] = {}
    for ecosystem, name, shown in rows:
        kind = "npm 조직" if shown.startswith("@") else ecosystem
        if kind == "npm 조직":
            in_top = name[1:].split("/", 1)[0] in idx["scope"].rank
        else:
            in_top = ts.compare_key(ecosystem, name) in idx[ecosystem].rank
        if in_top:                                   # 기준 목록에 있는 이름은 오탐 측정 대상 아님
            continue
        stat = stats.setdefault(kind, [0, 0])
        stat[0] += 1
        hit = ts.check_name(idx, ecosystem, name)
        if hit:
            stat[1] += 1
            print(f"  [{kind}] {shown}  ->  {hit[1]} (거리 {hit[2]})")
    for kind, (total, hits) in stats.items():
        print(f"[report] {kind}: 기준 밖 인기 이름 {total}개 중 {hits}개 잡힘 ({hits / total:.2%})")


def main() -> None:
    p = argparse.ArgumentParser(description="typosquat 유명 패키지 목록 생성")
    p.add_argument("--top-pypi", type=int, default=500, help="PyPI 기준 상위 개수 (기본 500)")
    p.add_argument("--top-npm", type=int, default=1700, help="npm 기준 상위 개수 (기본 1700)")
    p.add_argument("--out", default=str(ts.DATA_FILE), help="저장 경로")
    p.add_argument("--report", action="store_true", help="정상 인기 패키지로 오탐 측정")
    args = p.parse_args()
    if args.top_pypi < 1 or args.top_npm < 1:
        p.error("--top-pypi, --top-npm은 1 이상")

    pypi_raw, npm_raw = download_json(PYPI_SOURCE), download_json(NPM_SOURCE)
    pypi_all = pypi_names(pypi_raw)
    npm_all, scopes_all = npm_names(npm_raw)
    data = {
        "generated": date.today().isoformat(),
        "sources": {"pypi": PYPI_SOURCE, "pypi_updated": pypi_raw.get("last_update", ""), "npm": NPM_SOURCE},
        "pypi": pypi_all[:args.top_pypi],
        "npm": npm_all[:args.top_npm],
        "npm_scopes": scopes_all[:TOP_SCOPES],
    }
    ts.validate_data(data)                           # 저장 전에 typosquat.py와 같은 규칙으로 검사
    with open(args.out, "w", encoding="utf-8", newline="\n") as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
        f.write("\n")
    print(f"[typosquat-data] PyPI {len(data['pypi'])}개, npm {len(data['npm'])}개, "
          f"npm 조직 {len(data['npm_scopes'])}개 -> {args.out}")

    if args.report:
        ts.default_indexes.cache_clear()             # 방금 저장한 파일로 다시 읽기
        report(pypi_all, npm_all, scopes_all)


if __name__ == "__main__":
    main()