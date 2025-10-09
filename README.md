Compliance Mapping API

간단한 컴플라이언스–>요건–>매핑(감사/해결법) 조회 API입니다.
CSV로 정리된 규제 요건과 매핑 정보를 SQLite DB에 적재한 뒤, FastAPI로 조회합니다.

✅ 빠른 시작
# 0) (처음 한 번) 가상환경 & 의존성
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 1) CSV 적재 (프로젝트 루트에서 실행)
python -m scripts.load_csv --requirements ../compliance-gorn.csv --mappings ../mapping-standard.csv
# => "✅ CSV 적재 완료" 확인

# 2) API 서버 실행
python -m app.main
# Uvicorn running on http://0.0.0.0:8003
```

API 문서: http://localhost:8003/docs

Redoc: http://localhost:8003/redoc

📦 폴더 구조
```tree
.
├── app
│   ├── core
│   │   ├── db.py
│   │   └── __init__.py
│   ├── __init__.py
│   ├── main.py
│   ├── models.py
│   ├── routers
│   │   ├── compliance.py
│   │   ├── health.py
│   │   └── __init__.py
│   ├── schemas.py
│   └── services
│       ├── compliance_service.py
│       └── __init__.py
├── README.md
├── requirements.txt
└── scripts
    ├── __init__.py
    └── load_csv.py
```
🗂️ 데이터베이스

```bash
SQLite 파일: ./data/app.db (상대 경로)

테이블: frameworks, requirements, mappings, requirement_mappings

DB 내용 확인 (선택):

sqlite3 data/app.db ".tables"
sqlite3 data/app.db "SELECT code, name FROM frameworks;"
sqlite3 data/app.db "SELECT id, framework_code, item_code, title FROM requirements LIMIT 5;"
```
🔌 엔드포인트
1) Health
GET /health


예시:

curl -s http://localhost:8003/health

2) 컴플라이언스별 항목 개수
GET /compliance/compliance/stats


응답 예:
```json
[
  {"framework": "GDPR", "count": 2},
  {"framework": "ISMS-P", "count": 6},
  {"framework": "iso-27001", "count": 2}
]
```

예시 호출:
```bash
curl -s http://localhost:8003/compliance/compliance/stats | jq
```
3) 특정 컴플라이언스의 요건 목록
GET /compliance/compliance/{code}/requirements


쿼리 파라미터: offset(기본 0), limit(기본 50)

예시:
```bash
curl -s "http://localhost:8003/compliance/compliance/ISMS-P/requirements?offset=0&limit=20" | jq

```
응답 예(요약):
```json
[
  {"id": 1, "item_code": "2.10.1.2", "title": "2.10.1.2", "mapping_status": "직접매핑"},
  ...
]
```
4) 특정 요건의 매핑(감사/해결법) 상세
GET /compliance/compliance/{code}/requirements/{req_id}/mappings


예시:
```bash
curl -s http://localhost:8003/compliance/compliance/ISMS-P/requirements/3/mappings | jq
```

응답 예(요약):
```json
{
  "framework": "ISMS-P",
  "requirement": {
    "id": 3, "item_code": "2.5.1.2", "title": "2.5.1.2", "mapping_status": "직접매핑"
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
      "console_fix": "IAM Identity Center → Permission sets → 과다 권한 제거, 필요한 그룹만 할당",
      "cli_fix_cmd": "-"
    },
    ...
  ]
}
```
🧰 CSV 로더 (한 파일로 끝)
python -m scripts.load_csv --requirements ../compliance-gorn.csv --mappings ../mapping-standard.csv
# ✅ CSV 적재 완료


주의: 프로젝트 루트에서 실행해야 모듈 경로가 맞습니다. (python -m scripts.load_csv 형태 유지)

🔒 CORS (프론트에서 붙일 때 필요 시)
```python
# app/main.py
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```
🧪 간단한 호출 모음
```bash
# Health
curl -s http://localhost:8003/health

# Count
curl -s http://localhost:8003/compliance/compliance/stats | jq

# List (ISMS-P)
curl -s "http://localhost:8003/compliance/compliance/ISMS-P/requirements?offset=0&limit=20" | jq

# Detail (ISMS-P, req_id=3)
curl -s http://localhost:8003/compliance/compliance/ISMS-P/requirements/3/mappings | jq
```
🧹 .gitignore 적용 & 푸시

.gitignore는 아래처럼(이미 작성했다면 생략 가능):
```.gitignore
# Python
__pycache__/
*.py[cod]
*.pyo
*.pyd
*.so
*.egg-info/
.dist/
.build/

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

적용 & 커밋 & 푸시:
```bash
# 변경 사항 확인
git status

# .gitignore 먼저 스테이징
git add .gitignore

# 다른 파일들 추가
git add .

# 커밋
git commit -m "docs: README 추가, .gitignore 적용 & CSV 로더/엔드포인트 사용 가이드"

# 원격 생성 안 했으면 먼저
# git remote add origin <YOUR_REPO_URL>

# 푸시
git push origin main
```
🐛 트러블슈팅

ModuleNotFoundError: No module named 'app'

루트에서 실행하세요: python -m scripts.load_csv / python -m app.main

DB가 비어 보이면

CSV 경로 다시 확인 (--requirements, --mappings)

실행 후 "✅ CSV 적재 완료" 로그 확인

sqlite3 data/app.db로 테이블/행 확인

서버 포트 충돌 시

APP_PORT=8004 같은 방식으로 환경 변수 도입하거나 uvicorn 옵션 변경 가능