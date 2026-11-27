# Kubernetes 실행법

compose와 같은 4개 서비스(web·queue·worker·db)를 Kubernetes에 띄운다.
web·worker는 2개씩, queue·db는 1개씩 → **pod 6개**.
수업 실습 등 다른 것과 섞이지 않게 `commitguard` 네임스페이스(클러스터 안의 칸막이)에 띄운다.

## 준비물

- Docker Desktop + minikube (`brew install minikube`), kubectl
- 저장소 루트에 `.env` (compose와 같은 파일, `.env.example`을 복사해 비밀번호 채우기)

## 공통 Flask 세션 키 설정 (필수)

web Pod 2개가 같은 세션과 CSRF 토큰을 검증하도록 `.env`에 비어 있지 않은
`FLASK_SECRET_KEY`를 한 번 생성하여 설정한다. 기존 키가 있다면 유지한다.
다음 명령은 저장소 루트에서 실행하며, 키가 이미 설정되어 있으면 중단한다.

```bash
python -c "from pathlib import Path; import secrets; p=Path('.env'); s=p.read_text(encoding='utf-8'); assert not any(l.strip().startswith('FLASK_SECRET_KEY=') for l in s.splitlines()), 'FLASK_SECRET_KEY already exists'; p.write_text(s.rstrip('\n')+'\nFLASK_SECRET_KEY='+secrets.token_hex(32)+'\n', encoding='utf-8')"
```

macOS에서 `python` 명령이 없다면 `python3`을 사용한다. 빈 키가 이미 있다면
해당 빈 설정을 제거한 뒤 생성한다. `.env`와 실제 키는 커밋하거나 공유하지 않는다.

새 설치에서는 아래 `create secret` 명령이 키를 함께 등록한다. 기존 설치에서는
기존 DB 설정을 유지하면서 Secret의 해당 키를 안전하게 갱신하고 Web Deployment를
재시작한다. 키를 변경하면 기존 로그인/세션 쿠키가 무효화될 수 있다.
키 항목이 Secret에 없으면 Web Pod가 시작되지 않도록 명시적으로 참조한다.
빈 문자열은 사용하지 않는다.

## 실행 (저장소 루트에서)

```bash
minikube start
minikube image build -t commitguard-web:dev . && minikube image build -t commitguard-worker:dev worker
kubectl create namespace commitguard
kubectl -n commitguard create secret generic commitguard-secret --from-env-file=.env
kubectl -n commitguard create configmap db-init --from-file=db/init.sql
kubectl -n commitguard apply -f k8s/
```

확인과 접속:

```bash
kubectl -n commitguard get pods          # 6개가 모두 Running, READY 1/1이 될 때까지 1~2분
kubectl -n commitguard port-forward svc/web 5001:5000    # 브라우저에서 http://localhost:5001
```

## 파일 구성

| 파일 | 들어 있는 것 | compose에서는 |
|---|---|---|
| `k8s/configmap.yaml` | `VALKEY_HOST=queue`, `DB_HOST=db` 등 공개 설정 | `environment:` |
| `k8s/queue.yaml` | Valkey Deployment 1개 + Service `queue` | `queue` |
| `k8s/db.yaml` | PVC `db-data` + MySQL Deployment 1개 + Service `db`(클러스터 안에서만) | `db`, `db-data` 볼륨 |
| `k8s/web.yaml` | web Deployment 2개 + Service `web`(NodePort 30080) | `web`, `ports` |
| `k8s/worker.yaml` | worker Deployment 2개 (Service 없음) | `worker`, `trivy-cache` |

저장소에 올리지 않는 것 (명령으로 만든다):

- **Secret `commitguard-secret`**: `.env`에서 만든다. Secret yaml은 base64일 뿐 암호화가 아니라서 파일로 올리지 않는다.
- **ConfigMap `db-init`**: `db/init.sql`에서 만든다. SQL을 yaml에 복사해 두 군데서 관리하지 않으려고.

## 코드를 고친 뒤 다시 띄우기

```bash
minikube image build -t commitguard-web:dev .
kubectl -n commitguard rollout restart deployment/web     # worker면 deployment/worker
```

## 끄기

```bash
kubectl delete namespace commitguard     # 안의 pod·Service·Secret·PVC(DB 데이터)까지 전부 삭제
minikube stop
```

## 자주 나는 오류

| 증상 (`kubectl get pods`) | 원인 | 해결 |
|---|---|---|
| `ErrImageNeverPull`, `ImagePullBackOff` (web·worker) | minikube 안에 이미지가 없음. 내 Docker에서 `docker build` 한 이미지는 minikube가 못 본다 | `minikube image build` 다시 실행 |
| `CreateContainerConfigError` | Secret이나 ConfigMap `db-init`을 안 만듦 | 위 `kubectl create` 두 줄 실행 후 `kubectl -n commitguard delete pod --all` |
| web·worker가 처음에 `CrashLoopBackOff`, 1~2분 뒤 Running | db가 아직 준비 전이라 접속 실패 → K8s가 다시 띄움 (compose의 depends_on이 K8s엔 없음) | 기다리면 된다. 계속되면 `kubectl -n commitguard logs deploy/worker` |
| 테이블이 없음 (`findings` doesn't exist) | init.sql은 DB가 **처음** 만들어질 때만 실행됨 | `kubectl -n commitguard delete -f k8s/db.yaml` 후 다시 apply (데이터 삭제됨) |
| `localhost:30080` 접속 안 됨 | 맥의 minikube(docker 드라이버)는 NodePort를 바로 못 연다 | 위 port-forward 사용, 또는 `minikube service web -n commitguard` |
| `connection refused ... 127.0.0.1` (kubectl) | minikube가 꺼져 있음 | `minikube start` |
| `queue`가 `ImagePullBackOff` | minikube가 Docker Hub에서 이미지를 받다 시간 초과 (느린 와이파이) | 네트워크 확인 후 `kubectl -n commitguard delete pod -l app=queue` (다시 받음), 또는 `minikube image load valkey/valkey:8` |
| 다른 pod(guestbook 등)가 보임 | `-n commitguard` 없이 조회해서 default 네임스페이스를 봄 | 명령에 `-n commitguard` 붙이기 |
