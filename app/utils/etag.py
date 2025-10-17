# app/utils/etag.py
import hashlib, json
from fastapi import Request, Response

def compute_obj_etag(obj) -> str:
    """
    결과 객체(JSON 직렬화 기준)로 약한 ETag 생성.
    - 키 정렬 + compact 직렬화
    - 직렬화 불가 타입은 default=str
    """
    try:
        payload = json.dumps(
            obj, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
    except TypeError:
        payload = json.dumps(
            obj, sort_keys=True, ensure_ascii=False, default=str, separators=(",", ":")
        ).encode("utf-8")
    h = hashlib.sha1(payload).hexdigest()
    return f'W/"{h}:{len(payload)}"'

def etag_response(request: Request, response: Response, data):
    """
    If-None-Match와 비교해 동일하면 304, 아니면 ETag 부여 후 data 반환.
    """
    etag = compute_obj_etag(data)
    inm = (request.headers.get("If-None-Match") or "").strip()
    if etag and inm == etag:
        response.headers["ETag"] = etag
        return Response(status_code=304)
    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "private, must-revalidate"
    return data
