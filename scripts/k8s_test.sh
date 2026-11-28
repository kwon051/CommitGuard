#!/usr/bin/env bash
# k8s-test: Kubernetes(commitguard 네임스페이스)에 띄운 서비스에서 검사 1건이
# web → queue → worker → db 까지 끝까지 도는지 확인한다. (compose_test.sh의 Kubernetes판)
#
# 미리 해 둘 것: docs/k8s.md대로 배포해서 pod 6개가 Running
# 사용:        bash scripts/k8s_test.sh
#
# 통과: 상태가 done이고 DB에 결과가 있으면 exit 0
# 실패: 상태가 failed이거나, 제한 시간 안에 끝나지 않으면 exit 1
set -euo pipefail

NS="${NS:-commitguard}"
PORT="${PORT:-5001}"
WEB_URL="http://localhost:$PORT"
# 공개 저장소여야 clone할 수 있다. 우리 저장소는 테스트용 가짜 키가 있어 결과가 꼭 1건 이상 나온다.
REPO_URL="${REPO_URL:-https://github.com/kwon051/CommitGuard}"
# 안전망: 10분. 처음 검사는 worker의 Trivy가 취약점 DB를 받느라 약 3분 걸린다.
TIMEOUT="${TIMEOUT:-600}"
INTERVAL="${INTERVAL:-5}"

kube() { kubectl -n "$NS" "$@"; }

echo "⓪ web에 연결 (port-forward svc/web → localhost:$PORT)"
kube port-forward svc/web "$PORT:5000" >/dev/null 2>&1 &
pf_pid=$!
trap 'kill "$pf_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 30); do
  if curl -fs -o /dev/null "$WEB_URL/"; then break; fi   # port-forward가 열릴 때까지 조용히 재시도
  sleep 1
done
if ! curl -fsS -o /dev/null "$WEB_URL/"; then
  echo "❌ web 화면(/)에 접속하지 못했습니다"
  exit 1
fi
echo "   web 화면 응답 OK"

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
while true; do
  value=$(kube exec deploy/queue -- valkey-cli GET "commitguard:scan:status:$job_id" 2>/dev/null || true)
  status=$(grep -oE '"status": *"[a-z]+"' <<<"$value" | grep -oE '[a-z]+"$' | tr -d '"' || true)
  elapsed=$(( $(date +%s) - start ))
  echo "   ${elapsed}초: ${status:-아직 꺼내지 않음(queued)}"

  if [ "$status" = "done" ]; then
    echo "   상태: $value"
    break
  fi
  if [ "$status" = "failed" ]; then
    echo "❌ worker가 검사에 실패했습니다: $value"
    kube logs -l app=worker --tail=50 --prefix || true
    exit 1
  fi
  if [ "$elapsed" -ge "$TIMEOUT" ]; then
    echo "❌ ${TIMEOUT}초 안에 끝나지 않았습니다 (worker 응답 없음)"
    kube logs -l app=worker --tail=50 --prefix || true
    exit 1
  fi
  sleep "$INTERVAL"
done

echo "③ db에 결과가 저장됐는지 확인"
# 비밀번호는 db pod 안의 환경변수(Secret에서 온 값)를 그대로 쓴다
# -h 127.0.0.1: 소켓 대신 TCP로 접속 (kind에서 소켓 경로가 어긋나는 문제, k8s/db.yaml 주석 참고)
count=$(kube exec deploy/db -- env REPO_URL="$REPO_URL" sh -c \
  'MYSQL_PWD="$MYSQL_PASSWORD" mysql -h 127.0.0.1 -N -u"$MYSQL_USER" "$MYSQL_DATABASE" \
     -e "SELECT COUNT(*) FROM findings WHERE repo_url = '"'"'$REPO_URL'"'"'"' | tr -d '[:space:]')
echo "   findings 테이블: ${count}건"
if [ "${count:-0}" -lt 1 ]; then
  echo "❌ 검사는 끝났지만 db에 결과가 없습니다"
  exit 1
fi

echo "✅ Kubernetes에서 web → queue → worker → db 검사 통과 ($(( $(date +%s) - start ))초)"
