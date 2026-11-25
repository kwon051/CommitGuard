#!/usr/bin/env bash
# compose-test: docker compose로 띄운 4개 컨테이너에서 검사 1건이
# web → queue → worker → db 까지 끝까지 도는지 확인한다.
#
# 미리 해 둘 것: cp .env.example .env && docker compose up -d --build --wait
# 사용:        bash scripts/compose_test.sh
#
# 통과: 상태가 done이고 DB 결과와 웹 공개 불가 판정이 확인되면 exit 0
# 실패: 상태가 failed이거나, 제한 시간 안에 끝나지 않으면 exit 1
set -euo pipefail

WEB_URL="${WEB_URL:-http://localhost:5001}"
# 공개 저장소여야 러너에서 clone할 수 있다. 우리 저장소는 테스트용 가짜 키가 있어 결과가 꼭 1건 이상 나온다.
REPO_URL="${REPO_URL:-https://github.com/kwon051/CommitGuard}"
# 안전망: 10분. 처음 검사는 worker의 Trivy가 취약점 DB를 받느라 약 3분 걸린다
# (러너는 매번 빈 캐시로 시작). 캐시가 있으면 5초 안팎.
TIMEOUT="${TIMEOUT:-600}"
INTERVAL="${INTERVAL:-5}"   # 확인 간격(초)

echo "① 검사 요청 보내기: $REPO_URL"
response=$(curl -sS -X POST "$WEB_URL/scan" --data-urlencode "repo_url=$REPO_URL" -w $'\n%{http_code}')
code=$(tail -n1 <<<"$response")
body=$(sed '$d' <<<"$response")
echo "   web 응답 ($code): $body"
if [ "$code" != "202" ]; then
  echo "❌ web이 요청을 받지 못했습니다 (202가 아님)"
  exit 1
fi

job_id=$(grep -oE '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}' <<<"$body" | head -n1 || true)
if [ -z "$job_id" ]; then
  echo "❌ 응답에서 작업 번호를 찾지 못했습니다"
  exit 1
fi
echo "   작업 번호: $job_id"

echo "② worker가 끝낼 때까지 ${INTERVAL}초마다 상태 확인 (최대 ${TIMEOUT}초)"
start=$(date +%s)
status=""
while true; do
  value=$(docker compose exec -T queue valkey-cli GET "commitguard:scan:status:$job_id" || true)
  status=$(grep -oE '"status": *"[a-z]+"' <<<"$value" | grep -oE '[a-z]+"$' | tr -d '"' || true)
  elapsed=$(( $(date +%s) - start ))
  echo "   ${elapsed}초: ${status:-아직 꺼내지 않음(queued)}"

  if [ "$status" = "done" ]; then
    echo "   상태: $value"
    break
  fi
  if [ "$status" = "failed" ]; then
    echo "❌ worker가 검사에 실패했습니다: $value"
    docker compose logs --tail 50 worker
    exit 1
  fi
  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "❌ ${TIMEOUT}초 안에 끝나지 않았습니다 (worker 응답 없음)"
    docker compose logs --tail 50 worker
    exit 1
  fi
  sleep "$INTERVAL"
done

echo "③ db에 결과가 저장됐는지 확인"
# 비밀번호는 db 컨테이너 안의 환경변수(.env에서 온 값)를 그대로 쓴다
count=$(docker compose exec -T -e REPO_URL="$REPO_URL" db sh -c \
  'MYSQL_PWD="$MYSQL_PASSWORD" mysql -N -u"$MYSQL_USER" "$MYSQL_DATABASE" \
     -e "SELECT COUNT(*) FROM findings WHERE repo_url = '"'"'$REPO_URL'"'"'"' | tr -d '[:space:]')
echo "   findings 테이블: ${count}건"
if [ "${count:-0}" -lt 1 ]; then
  echo "❌ 검사는 끝났지만 db에 결과가 없습니다"
  exit 1
fi

echo "④ 웹 결과에 Gitleaks 공개 불가 판정이 표시되는지 확인"
page=$(curl -fsS -G "$WEB_URL/results" \
  --data-urlencode "repo_url=$REPO_URL" --data-urlencode "job_id=$job_id")
if [[ "$page" != *"<strong>공개 불가</strong>"* ]]; then
  echo "❌ 이 작업의 공개 불가 판정을 웹에서 확인할 수 없습니다"
  exit 1
fi

echo "✅ web → queue → worker → db 검사 및 공개 전환 판정 통과 ($(( $(date +%s) - start ))초)"
