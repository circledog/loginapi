from fastapi import FastAPI, Response, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx, base64, time
from typing import Dict, Optional
from jose import jwt
from settings import settings

app = FastAPI()

# 允許前端（Vue/CoreUI）跨域呼叫與接收 Set-Cookie
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # 若已知前端來源，建議改成具體網域清單
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
# In-Memory 暫存 API Key（多副本改 Redis）
API_KEY_STORE: Dict[str, dict] = {}  # key: user (或 jwt jti)，val: {id, api_key, expire_at}

class LoginBody(BaseModel):
    username: str
    password: str

def _b64_api_key(api_key_id: str, api_key_secret: str) -> str:
    return "ApiKey " + base64.b64encode(f"{api_key_id}:{api_key_secret}".encode()).decode()

async def _es_password_grant(client: httpx.AsyncClient, username: str, password: str) -> str:
    r = await client.post(f"{settings.ES_URL}/_security/oauth2/token",
                          json={"grant_type":"password","username":username,"password":password})
    if r.status_code != 200:
        raise HTTPException(401, "Elasticsearch authentication failed")
    return r.json()["access_token"]

async def _es_grant_api_key(client: httpx.AsyncClient, access_token: str, username: str):
    r = await client.post(f"{settings.ES_URL}/_security/api_key/grant", json={
        "grant_type": "access_token",
        "access_token": access_token,
        "api_key": {
            "name": f"ui-{username}-{int(time.time())}",
            "expiration": "7d",
            "role_descriptors": {
                "ui_reader": {
                    "cluster": ["monitor"],
                    "index": [
                        {"names": ["logs-*"], "privileges": ["read", "view_index_metadata"]}
                    ]
                }
            }
        }
    })
    if r.status_code != 200:
        raise HTTPException(500, f"Grant API Key failed: {r.text}")
    return r.json()  # {id, api_key, name, expiration, encoded}

async def _kibana_basic_login(client: httpx.AsyncClient, username: str, password: str):
    r = await client.post(f"{settings.KBN_URL}/internal/security/login",
                          json={"providerType":"basic","providerName":"basic",
                                "currentURL":"", "params":{"username":username,"password":password}},
                          follow_redirects=False)
    # 200/204 視版本而定；重點是要拿 set-cookie
    if r.status_code not in (200, 204):
        raise HTTPException(500, f"Kibana login failed: {r.text}")
    return r


@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.post("/api/login")
async def login(body: LoginBody, response: Response):
    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=15) as client:
        access_token = await _es_password_grant(client, body.username, body.password)
        api_key = await _es_grant_api_key(client, access_token, body.username)
        kbn = await _kibana_basic_login(client, body.username, body.password)

    # 將 Kibana 的 Set-Cookie 回傳給瀏覽器（需要同網域或同站 Ingress 才能被瀏覽器收下）
    set_cookies = kbn.headers.get_list("set-cookie")
    for c in set_cookies:
        response.headers.append("set-cookie", c)

    # 安全方案A：發「自家 JWT」給前端；ES API Key 只存在伺服器
    if settings.ISSUE_SERVER_JWT:
        jti = f"{body.username}-{int(time.time())}"
        API_KEY_STORE[jti] = {
            "id": api_key["id"],
            "api_key": api_key["api_key"],
            "expire_at": int(time.time()) + 7*24*3600
        }
        token = jwt.encode(
            {"sub": body.username, "jti": jti, "exp": int(time.time()) + settings.SERVER_JWT_EXPIRE_DAYS*24*3600},
            settings.SERVER_JWT_SECRET, algorithm="HS256"
        )
        return {"token_type":"server_jwt", "token": token, "expiresInDays": settings.SERVER_JWT_EXPIRE_DAYS}

    # 方案B（你硬要把 ES API Key 放瀏覽器）：回 ApiKey 字串，僅供你自家 API 使用
    return {
        "token_type":"es_api_key",
        "token": _b64_api_key(api_key["id"], api_key["api_key"]),
        "expiresInDays": 7
    }


@app.get("/api/kibana/iframe-url")
async def kibana_iframe_url(path: str = "/app/home"):
    """
    提供前端內嵌 Kibana 用的 URL（經由同源代理 /kbn 以利 iframe/frameset）。
    例如：/api/kibana/iframe-url?path=/app/discover#/
    前端可將回傳的 url 放進 <iframe src=...>
    """
    # 透過本服務的同源代理（見 /kbn/{path}）避免 X-Frame-Options/SAMEORIGIN 問題
    # 注意：若你已用 Ingress 將 Kibana 與此 API 同網域，亦可直接給 Kibana 的相對路徑
    return {"url": f"/kbn{path}"}

class LogoutBody(BaseModel):
    # 可選：讓前端傳回 server_jwt 以便後端清掉儲存的 API Key
    token: Optional[str] = None

@app.post("/api/logout")
async def logout(body: Optional[LogoutBody] = None, response: Response = Response()):
    # Kibana 會話登出：簡單作法是清 cookie（也可呼叫 /internal/security/logout）
    response.delete_cookie("sid")   # 名稱視版本/前置 proxy 而異，保守做法是清所有 cookie
    if body and body.token:
        try:
            data = jwt.decode(body.token, settings.SERVER_JWT_SECRET, algorithms=["HS256"])
            API_KEY_STORE.pop(data.get("jti",""), None)
        except Exception:
            pass
    return {"ok": True}

# 供前端「以伺服器身分」打 ES 的轉接端（示例）
@app.get("/api/es/_cat/indices")
async def cat_indices(request: Request):
    # 從 Header 取回 server_jwt（或你前端帶上）
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(401, "Missing server token")
    token = auth[7:]
    try:
        data = jwt.decode(token, settings.SERVER_JWT_SECRET, algorithms=["HS256"])
        rec = API_KEY_STORE.get(data["jti"])
        if not rec or rec["expire_at"] < int(time.time()):
            raise HTTPException(401, "Key expired")
        api_key_header = "ApiKey " + base64.b64encode(f"{rec['id']}:{rec['api_key']}".encode()).decode()
    except Exception:
        raise HTTPException(401, "Invalid token")

    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=15) as client:
        r = await client.get(f"{settings.ES_URL}/_cat/indices?v=true&format=json",
                             headers={"Authorization": api_key_header})
        return r.json(), r.status_code


def _copy_response_headers(src: httpx.Response, dst: Response):
    # 將 Kibana 的 Set-Cookie 透傳給瀏覽器，其餘安全相關會影響 iframe 的標頭予以移除/覆寫
    # 注意：實務上建議在前置 Proxy（如 Nginx/Ingress）層處理
    hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                  "te", "trailers", "transfer-encoding", "upgrade"}
    blocked = {"x-frame-options", "content-security-policy"}

    # Set-Cookie 需逐一追加
    try:
        set_cookies = src.headers.get_list("set-cookie")
        for c in set_cookies:
            dst.headers.append("set-cookie", c)
    except Exception:
        pass

    for k, v in src.headers.items():
        lk = k.lower()
        if lk in hop_by_hop or lk in blocked or lk == "set-cookie":
            continue
        dst.headers[k] = v


@app.api_route("/kbn/{path:path}", methods=["GET"])
async def kibana_proxy(path: str, request: Request):
    """
    以同源路徑代理 Kibana，便於以 frameset/iframe 內嵌。
    僅示範 GET；如需完整代理（POST、WebSocket、壓縮、長連線），建議交由反向代理伺服器或 Ingress。
    """
    target_url = f"{settings.KBN_URL}/{path}"
    # 轉遞查詢字串
    if request.url.query:
        target_url += f"?{request.url.query}"

    # 轉遞 Cookie 與部分標頭
    headers = {k: v for k, v in request.headers.items() if k.lower() in {"cookie", "accept", "user-agent", "accept-encoding", "accept-language"}}

    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=30, follow_redirects=False) as client:
        r = await client.get(target_url, headers=headers)

    # 建立回應並複寫標頭，移除會阻擋 iframe 的標頭
    resp = Response(content=r.content, status_code=r.status_code)
    _copy_response_headers(r, resp)
    return resp
