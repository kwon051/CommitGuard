#!/usr/bin/env bash
# image-scan: Trivy JSON 결과를 등급별 표(마크다운)로 바꾼다.
# Actions에서는 $GITHUB_STEP_SUMMARY에 붙여서 실행 화면 맨 앞(Summary)에 보이게 한다.
#
# 사용: bash scripts/trivy_summary.sh trivy.json web
# 1건 = 보안 구멍(CVE) 1개 × 그 구멍이 든 부품 1개 (같은 구멍이 부품 4개에 있으면 4건)
set -euo pipefail

json="$1"
name="$2"

# 등급별 건수: count <등급> [fixed]  (fixed면 고친 버전이 나와 있는 것만)
count() {
  local filter='select(.Severity == $sev)'
  if [ "${2:-}" = "fixed" ]; then
    filter="$filter | select((.FixedVersion // \"\") != \"\")"
  fi
  jq --arg sev "$1" "[.Results[]?.Vulnerabilities[]? | $filter] | length" "$json"
}

crit=$(count CRITICAL)
crit_fixed=$(count CRITICAL fixed)
high=$(count HIGH)
high_fixed=$(count HIGH fixed)

echo "### image-scan 결과 — ${name}"
echo ""
echo "| 등급 | 건수 | 버전 업데이트로 해결 가능 |"
echo "|---|---|---|"
echo "| CRITICAL | ${crit} | ${crit_fixed} |"
echo "| HIGH | ${high} | ${high_fixed} |"
echo ""
if [ "$crit" -gt 0 ]; then
  echo "❌ **실패**: 가장 위험한 등급(CRITICAL)의 취약점을 ${crit}건 발견했습니다."
  echo ""
  echo "- 버전 업데이트로 해결 가능: ${crit_fixed}건"
  echo "- 해결 방법이 없는 것은 기본 이미지를 바꾸거나 해당 부품을 빼는 방법을 팀과 정해 주세요."
else
  echo "✅ **통과**: 가장 위험한 등급(CRITICAL) 정도의 취약점을 발견하지 못했습니다."
  echo ""
  echo "HIGH 등급은 참고용으로 개수만 보여 줍니다."
fi
echo ""
echo "<details><summary>취약점이 발견된 위치 보기 (눌러서 펼치기)</summary>"
echo ""
echo "| 발견된 곳 | CRITICAL | HIGH | 버전 업데이트로 해결 가능 |"
echo "|---|---|---|---|"
jq -r '.Results[]? | select((.Vulnerabilities // []) | length > 0)
  | [ (if .Class == "os-pkgs"
       then "리눅스 기본 부품 (" + (.Target | sub(".*\\("; "") | sub("\\)$"; "")) + ")"
       elif .Type == "gobinary" then "프로그램 `" + (.Target | split("/") | last) + "`"
       else "라이브러리 `" + .Target + "`" end),
      ([.Vulnerabilities[] | select(.Severity == "CRITICAL")] | length),
      ([.Vulnerabilities[] | select(.Severity == "HIGH")] | length),
      ([.Vulnerabilities[] | select((.FixedVersion // "") != "")] | length) ]
  | "| \(.[0]) | \(.[1]) | \(.[2]) | \(.[3]) |"' "$json"
echo ""
echo "1건은 취약점(CVE) 1개가 부품 1개에서 발견된 것입니다. 같은 취약점이 부품 4개에 있으면 4건으로 셉니다. 자세한 목록은 'HIGH·CRITICAL 목록' 단계 로그에 있습니다."
echo ""
echo "</details>"
