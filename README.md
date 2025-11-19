# Compliance Mapping API

AWS 보안 컴플라이언스 요건과 감사/해결 방법을 조회하는 FastAPI 기반 REST API

## 빠른 시작
```bash
# 1. 가상환경 설정
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. CSV 데이터 로드
python -m scripts.load_csv \
  --requirements ./compliance-gorn.csv \
  --mappings ./mapping-standard.csv

# 3. API 서버 실행
python -m app.main
```

API 문서: http://localhost:8003/docs  
Redoc: http://localhost:8003/redoc

## 프로젝트 구조
```
.
├── app/
│   ├── core/
│   │   ├── db.py
│   │   └── __init__.py
│   ├── main.py              # FastAPI 앱
│   ├── models.py            # DB 모델
│   ├── schemas.py           # API 스키마
│   ├── routers/
│   │   ├── compliance.py
│   │   ├── health.py
│   │   └── __init__.py
│   └── services/
│       ├── compliance_service.py
│       └── __init__.py
├── scripts/
│   ├── load_csv.py          # CSV 로더
│   └── __init__.py
├── data/
│   └── app.db               # SQLite DB
├── requirements.txt
└── README.md
```

## 데이터베이스

- **위치**: `./data/app.db`
- **테이블**: `frameworks`, `requirements`, `mappings`, `requirement_mappings`

### DB 내용 확인
```bash
sqlite3 data/app.db ".tables"
sqlite3 data/app.db "SELECT code, name FROM frameworks;"
sqlite3 data/app.db "SELECT id, framework_code, item_code, title FROM requirements LIMIT 5;"
```

## API 엔드포인트

### Health Check
```bash
GET /health

curl -s http://localhost:8003/health
```

### 컴플라이언스별 요건 개수
```bash
GET /compliance/compliance/stats

curl -s http://localhost:8003/compliance/compliance/stats | jq
```

**응답 예시:**
```json
[
  {"framework": "GDPR", "count": 2},
  {"framework": "ISMS-P", "count": 6},
  {"framework": "iso-27001", "count": 2}
]
```

### 특정 컴플라이언스의 요건 목록
```bash
GET /compliance/compliance/{code}/requirements?offset=0&limit=50

curl -s "http://localhost:8003/compliance/compliance/ISMS-P/requirements?offset=0&limit=20" | jq
```

**응답 예시:**
```json
[
  {
    "id": 1,
    "item_code": "2.10.1.2",
    "title": "2.10.1.2",
    "mapping_status": "직접매핑"
  }
]
```

### 요건별 매핑(감사/해결법) 상세
```bash
GET /compliance/compliance/{code}/requirements/{req_id}/mappings

curl -s http://localhost:8003/compliance/compliance/ISMS-P/requirements/3/mappings | jq
```

**응답 예시:**
```json
{
  "framework": "ISMS-P",
  "requirement": {
    "id": 3,
    "item_code": "2.5.1.2",
    "title": "2.5.1.2",
    "mapping_status": "직접매핑"
  },
  "mappings": [
    {
      "code": "1.0-01",
      "category": "1 (접근제어/RBAC/IAM)",
      "service": "IAM Identity Center(SSO)",
      "console_path": "IAM Identity Center → Users/Groups → Assignments",
      "check_how": "SSO 권한셋 최소화, 계정 연결 확인",
      "cli_cmd": "aws sso-admin list-permission-sets --instance-arn ARN",
      "return_field": "PermissionSets",
      "compliant_value": "최소 권한만 존재",
      "non_compliant_value": "권한셋 누락 또는 과다",
      "console_fix": "IAM Identity Center → Permission sets → 과다 권한 제거",
      "cli_fix_cmd": "-"
    }
  ]
}
```

## CORS 설정

프론트엔드 연동 시 필요한 경우 `app/main.py`에 추가:
```python
from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

## .gitignore

프로젝트 루트에 `.gitignore` 파일을 생성하고 아래 내용을 추가하세요:
```
# Python
__pycache__/
*.py[cod]
*.pyo
*.pyd
*.so
*.egg-info/
dist/
build/

# Venv
.venv/
venv/

# OS & Editor
.DS_Store
Thumbs.db
.idea/
.vscode/

# Test/Cache
.pytest_cache/
.mypy_cache/
coverage/
htmlcov/

# Local data
data/*.db
data/**/*.db
.env
*.sqlite
*.sqlite3
```

## Git 푸시
```bash
# 변경 사항 확인
git status

# .gitignore 추가
git add .gitignore

# 전체 파일 추가
git add .

# 커밋
git commit -m "docs: README 추가 및 프로젝트 구조 정리"

# 원격 저장소 추가 (처음 한 번만)
git remote add origin https://github.com/BOB-DSPM/DSPM_Compliance-show.git

# 푸시
git push origin main
```

## 트러블슈팅

### ModuleNotFoundError 발생 시
프로젝트 루트에서 실행하세요:
```bash
python -m scripts.load_csv
python -m app.main
```

### DB가 비어있을 때
1. CSV 파일 경로 확인
2. 로더 실행 후 "✅ CSV 적재 완료" 로그 확인
3. `sqlite3 data/app.db "SELECT COUNT(*) FROM requirements;"`로 데이터 확인

### 포트 충돌 시
환경 변수로 포트 변경:
```bash
APP_PORT=8004 python -m app.main
```
또는 `app/main.py`에서 `uvicorn.run()` 포트 수정

## Docker 이미지 빌드 & 실행 (AWS Marketplace 대비)

프로젝트 루트에 있는 `Dockerfile`은 `python:3.12-slim` 기반이며, 비루트 사용자(`appuser`)로 FastAPI 앱을 실행하도록 구성되어 있습니다. `_entry.py`는 컨테이너 기동 시 SQLite DB(기본 `/app/app.db`)를 자동 시드합니다.

```bash
# 기본 빌드/실행
docker build -t compliance-api .
docker run --rm -p 8003:8003 compliance-api

# CSV를 다시 적재하려면 FORCE_SEED=1 지정
docker run --rm -e FORCE_SEED=1 -p 8003:8003 compliance-api

# AWS Marketplace 업로드 대비 멀티아키텍처 빌드 (ECR 예시)
aws ecr get-login-password --region <region> | \
  docker login --username AWS --password-stdin <account>.dkr.ecr.<region>.amazonaws.com

docker buildx build --platform linux/amd64,linux/arm64 \
  -t <account>.dkr.ecr.<region>.amazonaws.com/compliance-api:latest \
  --push .
```

컨테이너는 `/health` 엔드포인트로 헬스체크를 제공하며, 외부 의존성은 포함하지 않습니다. 사용 설명서에는 노출 포트(기본 `8003`), 요구 CPU/메모리, 필요한 환경 변수(`PORT`, `APP_HOST`, `REQUIREMENTS_CSV`, `MAPPINGS_CSV`, `FORCE_SEED`) 등을 명확하게 기재하세요.

## AWS Marketplace 컨테이너 가이드

AWS Marketplace에 제출할 때 확인해야 하는 핵심 요구 사항과 이 프로젝트의 대응 방향입니다.

- **보안 정책**: 루트가 아닌 사용자로 실행, 불필요한 패키지 제거, 이미지에 비밀번호·AWS 자격 증명·라이선스 키를 포함하지 않습니다. 빌드 파이프라인에 `trivy`나 `grype`로 취약성 스캔을 추가하세요.
- **고객 정보 요구 사항**: 앱은 입력 CSV/SQLite 외 고객 데이터를 외부로 전송하지 않습니다. BYOL 등 고객 데이터 수집이 필요한 경우 사용자 동의/자동화 절차를 문서화해야 합니다.
- **제품 사용 요구 사항**: README/Marketplace 가이드에 컨테이너 배포 단계(ECR 업로드 → EKS/ECS/Fargate 실행), 필요 IAM 권한, 외부 의존성(없음), 상태 점검 방법(`/health`)을 포함합니다.
- **아키텍처 요구 사항**: 컨테이너 이미지는 AWS가 제공하는 ECR 리포지터리에 푸시하고, Linux 기반이며 Amazon ECS/EKS/Fargate 배포 매니페스트를 제공해야 합니다. Helm 차트를 사용할 경우 이미지 참조는 `values.yaml` 변수로만 정의합니다.
- **Helm/추가 기능**: Amazon EKS Add-on으로 게시하려면 amd64/arm64 지원, `aws_mp_configuration_schema.json`·`aws_mp_addon_parameters.json` 구성, IRSA/Pod Identity 권한 정의, Helm Lint/Template 통과, CRD 처리 전략 등을 갖추세요.
- **외부 종속성/라이선스**: 배포 시 추가 결제 수단이 없어야 하며, 지속적 외부 서비스 호출이 필요하면 사용説明과 SLA를 명시합니다. PAYG/계약 모델을 선택한다면 AWS Marketplace Metering 또는 License Manager 통합이 필요합니다.

요구 사항은 정기적으로 업데이트되므로 제출 전 [AWS Marketplace Seller Guide](https://docs.aws.amazon.com/marketplace/latest/seller-guide/what-is-aws-marketplace.html)의 컨테이너 섹션을 다시 확인하고 체크리스트를 갱신하세요.
