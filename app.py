from fastapi import FastAPI, Response, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import httpx, base64, time
from typing import Dict, Optional
from jose import jwt
from settings import settings
from urllib.parse import urlsplit, urlunsplit
import re

app = FastAPI()

# 允許前端（Vue/CoreUI）跨域呼叫與接收 Set-Cookie
app.add_middleware(
    CORSMiddleware,
    # 指定可存取的前端來源，確保瀏覽器能接受 Set-Cookie
    allow_origins=[
        "http://localhost:3000",
        "https://localhost:3000",
        "http://127.0.0.1:3000",
        "https://127.0.0.1:3000",
    ],
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
    r = await client.post(
        f"{settings.ES_URL}/_security/oauth2/token",
        json={"grant_type": "password", "username": username, "password": password},
    )
    if r.status_code != 200:
        try:
            detail = r.json()
        except Exception:
            detail = r.text
        raise HTTPException(status_code=401, detail={"stage": "es_password_grant", "response": detail})
    return r.json().get("access_token")

async def _es_grant_api_key(client: httpx.AsyncClient, access_token: str, username: str):
    r = await client.post(
        f"{settings.ES_URL}/_security/api_key/grant",
        json={
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
                        ],
                    }
                },
            },
        },
    )
    if r.status_code != 200:
        try:
            detail = r.json()
        except Exception:
            detail = r.text
        raise HTTPException(status_code=502, detail={"stage": "es_grant_api_key", "response": detail})
    return r.json()

async def _es_api_key_via_password(client: httpx.AsyncClient, username: str, password: str, display_user: str):
    auth_header = "Basic " + base64.b64encode(f"{username}:{password}".encode()).decode()
    payload = {
        "name": f"ui-{display_user}-{int(time.time())}",
        "expiration": "7d",
        "role_descriptors": {
            "ui_reader": {
                "cluster": ["monitor"],
                "index": [{"names": ["logs-*"], "privileges": ["read", "view_index_metadata"]}],
            }
        },
    }
    r = await client.post(
        f"{settings.ES_URL}/_security/api_key",
        headers={"Authorization": auth_header},
        json=payload,
    )
    if r.status_code != 200:
        try:
            detail = r.json()
        except Exception:
            detail = r.text
        raise HTTPException(status_code=401, detail={"stage": "es_basic_create_api_key", "response": detail})
    return r.json()

async def _kibana_basic_login(client: httpx.AsyncClient, username: str, password: str):
    """
    以 basic provider 對 Kibana 登入，並對常見 providerName 進行自動 fallback：
    - 優先使用 settings.KBN_PROVIDER_NAME（若有指定）
    - 其後嘗試 "basic"、"basic1"（ECK 常見）、"cloud-basic"（Elastic Cloud）
    """
    tried = []
    # 準備候選 providerName，並去重
    candidates = []
    if settings.KBN_PROVIDER_NAME:
        candidates.append(settings.KBN_PROVIDER_NAME)
    candidates.extend(["basic", "basic1", "cloud-basic"])
    seen = set()
    candidates = [p for p in candidates if not (p in seen or seen.add(p))]

    last_error_text = None
    for provider in candidates:
        tried.append(provider)
        r = await client.post(
            f"{settings.KBN_URL}/internal/security/login",
            json={
                "providerType": "basic",
                "providerName": provider,
                "currentURL": f"{settings.KBN_URL}/login",
                "params": {"username": username, "password": password},
            },
            headers={"kbn-xsrf": "true"},
            follow_redirects=False,
        )
        if r.status_code in (200, 204):
            return r
        # 累積錯誤資訊，但不立刻拋出，讓後續 providerName 有機會成功
        try:
            last_error_text = r.json()
        except Exception:
            last_error_text = r.text

    # 全部嘗試失敗才回傳 401
    raise HTTPException(
        status_code=401,
        detail={
            "stage": "kibana_login",
            "tried_providers": tried,
            "response": last_error_text,
        },
    )


@app.get("/healthz")
async def healthz():
    return {"ok": True}

@app.post("/api/login")
async def login(body: LoginBody, response: Response, request: Request):
    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=15) as client:
        # 兩種取得 API Key 的方式：token（預設）或 basic 密碼
        # 為了在未啟用 OAuth token API 的環境能自動兼容：
        # 當設定為 token 且失敗時，自動回退到 basic 密碼建立 API Key。
        try:
            if settings.ES_GRANT_FLOW.lower() == "password":
                api_key = await _es_api_key_via_password(client, body.username, body.password, body.username)
            else:
                access_token = await _es_password_grant(client, body.username, body.password)
                api_key = await _es_grant_api_key(client, access_token, body.username)
        except HTTPException as e:
            if settings.ES_GRANT_FLOW.lower() == "token":
                # 回退到 basic 密碼建立 API Key（例如自管叢集常未開 oauth2/token）
                api_key = await _es_api_key_via_password(client, body.username, body.password, body.username)
            else:
                raise
        kbn = await _kibana_basic_login(client, body.username, body.password)

    # 將 Kibana 的 Set-Cookie 回傳給瀏覽器（需要同網域或同站 Ingress 才能被瀏覽器收下）
    set_cookies = kbn.headers.get_list("set-cookie")
    # 針對本地開發：移除 Domain（變成 host-only），若 scheme!=https 則移除 Secure，確保 cookie 會在 HTTP 被瀏覽器帶上
    # 嘗試從代理標頭判斷原始瀏覽器協定（Vite 代理到後端時，request.url.scheme 仍為 http）
    scheme = request.headers.get("x-forwarded-proto") or ("https" if request.headers.get("origin", "").startswith("https://") else request.url.scheme)
    for c in set_cookies:
        response.headers.append("set-cookie", _rewrite_set_cookie(c, new_domain=None, force_insecure=(scheme != "https")))

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
async def kibana_iframe_url(path: str = "/app/home#/"):
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


@app.get("/api/kibana/session")
async def kibana_session_check(request: Request):
    """
    以目前請求的 Cookie 轉呼叫 Kibana /internal/security/me，檢查會話是否有效。
    回傳：{ ok, status, user?, headers }（僅開發除錯用）。
    """
    target_url = f"{settings.KBN_URL}/internal/security/me"
    hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                  "te", "trailers", "transfer-encoding", "upgrade"}
    fwd_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in hop_by_hop or lk == "host":
            continue
        fwd_headers[k] = v
    # 明確 anti-CSRF / JSON
    fwd_headers["kbn-xsrf"] = "true"
    fwd_headers["X-Requested-With"] = "XMLHttpRequest"
    fwd_headers["Accept-Encoding"] = "identity"
    fwd_headers.setdefault("Accept", "application/json, text/plain, */*")

    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=15, follow_redirects=False) as client:
        r = await client.get(target_url, headers=fwd_headers)
    try:
        body = r.json()
    except Exception:
        body = {"raw": r.text[:500]}
    return {
        "ok": r.status_code == 200,
        "status": r.status_code,
        "user": body,
        "headers": {
            "content-type": r.headers.get("content-type", ""),
            "location": r.headers.get("location", ""),
        }
    }

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


def _rewrite_set_cookie(cookie_header: str, new_domain: Optional[str], force_insecure: bool = False) -> str:
    # 解析簡單 Set-Cookie 字串，移除或替換 Domain 屬性；保留其餘屬性
    parts = [p.strip() for p in cookie_header.split(';')]
    if not parts:
        return cookie_header
    out = []
    domain_seen = False
    path_idx = -1
    has_secure = False
    samesite_idx = -1
    for i, p in enumerate(parts):
        pl = p.lower()
        if pl.startswith('domain='):
            domain_seen = True
            if new_domain:
                out.append(f'Domain={new_domain}')
            # 若 new_domain 為 None，則不附加，成為 host-only
            continue
        if pl == 'secure':
            has_secure = True
            if force_insecure:
                # 在 http 開發環境移除 Secure
                continue
            # 在 http 開發環境移除 Secure
            # https 情境保留 Secure
            out.append(p)
            continue
        if pl.startswith('path='):
            path_idx = len(out)
            # 先佔位，稍後檢查是否需要加上 /kbn 前綴
            out.append(p)
            continue
        if pl.startswith('samesite='):
            samesite_idx = len(out)
            out.append(p)
            continue
        out.append(p)
    # 若原本沒有 Domain 且 new_domain 指定，則補上一個
    if new_domain and not domain_seen:
        out.append(f'Domain={new_domain}')
    # 將 Path 正規化為 '/'，確保 cookie 會被帶在 /kbn/* 與 /{hash}/* 等所有子路徑
    if path_idx != -1:
        try:
            kv = out[path_idx].split('=', 1)
            if len(kv) == 2:
                key, _ = kv[0], kv[1]
                out[path_idx] = f'{key}=/'
        except Exception:
            pass
    else:
        # 若上游未附 Path，補上一個最寬的 Path=/
        out.append('Path=/')

    # 在 https（非 force_insecure）情境：確保 Secure 與 SameSite=None 以利跨 iframe/同源代理場景
    if not force_insecure:
        if not has_secure:
            out.append('Secure')
        if samesite_idx == -1:
            out.append('SameSite=None')

    return '; '.join(out)


def _copy_response_headers(src: httpx.Response, dst: Response, request_host: Optional[str] = None, request_scheme: Optional[str] = None, strip_encoding_length: bool = False):
    # 將 Kibana 的 Set-Cookie 透傳給瀏覽器，其餘安全相關會影響 iframe 的標頭予以移除/覆寫
    # 注意：實務上建議在前置 Proxy（如 Nginx/Ingress）層處理
    hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                  "te", "trailers", "transfer-encoding", "upgrade"}
    # 僅在我們改寫了內容（例如 HTML 重寫）時，移除 content-encoding/content-length，避免長度或編碼不相符
    blocked = {"x-frame-options"}
    if strip_encoding_length:
        blocked.update({"content-encoding", "content-length"})

    # Set-Cookie 需逐一追加
    try:
        set_cookies = src.headers.get_list("set-cookie")
        for c in set_cookies:
            dst.headers.append("set-cookie", _rewrite_set_cookie(c, new_domain=None, force_insecure=(request_scheme != "https")))
    except Exception:
        pass

    # 重寫 Location，避免跳離 /kbn 前綴導致跨網域或被 X-Frame-Options 擋下
    loc = src.headers.get("location")
    if loc:
        try:
            # 若是絕對 URL 且以 KBN_URL 開頭，改為 /kbn + path?query#fragment
            if loc.startswith(settings.KBN_URL):
                parts = urlsplit(loc)
                new_path = "/kbn" + parts.path
                if parts.query:
                    new_path += f"?{parts.query}"
                if parts.fragment:
                    new_path += f"#{parts.fragment}"
                dst.headers["location"] = new_path
            # 若是以 / 開頭的相對路徑，也加上 /kbn 前綴
            elif loc.startswith("/"):
                dst.headers["location"] = "/kbn" + loc
            else:
                # 其他情況沿用原值
                dst.headers["location"] = loc
        except Exception:
            dst.headers["location"] = loc

    for k, v in src.headers.items():
        lk = k.lower()
        if lk in hop_by_hop or lk in blocked or lk == "set-cookie" or lk == "location":
            continue
        dst.headers[k] = v


@app.api_route("/kbn/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], include_in_schema=False)
async def kibana_proxy(path: str, request: Request):
    """
    以同源路徑代理 Kibana，便於以 frameset/iframe 內嵌。
    僅示範 GET；如需完整代理（POST、WebSocket、壓縮、長連線），建議交由反向代理伺服器或 Ingress。
    """
    # 特例：若 /kbn/{hash}/internal/* 或 /kbn/{hash}/api/*，需改投遞到 Kibana 的真正 /internal/* 或 /api/*
    hashed_api_match = re.match(r"^(?P<prefix>[0-9a-fA-F]{6,})/(internal|api)/(?P<rest>.*)$", path)
    if hashed_api_match:
        kind = path.split("/", 1)[1].split("/", 1)[0]  # internal 或 api
        rest = hashed_api_match.group("rest")
        target_url = f"{settings.KBN_URL}/{kind}/{rest}"
    else:
        target_url = f"{settings.KBN_URL}/{path}"
    # 轉遞查詢字串
    if request.url.query:
        target_url += f"?{request.url.query}"

    # 轉遞幾乎所有標頭（排除 hop-by-hop 與 host）
    hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                  "te", "trailers", "transfer-encoding", "upgrade"}
    fwd_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        # 丟棄條件式快取標頭，避免上游回 304 導致瀏覽器沿用舊快取（未經我們重寫）
        if lk in hop_by_hop or lk == "host" or lk in {"if-none-match", "if-modified-since", "if-match", "if-unmodified-since"}:
            continue
        fwd_headers[k] = v
    # 明確告知 Kibana 原始協定/主機/埠，避免被視為 http 而觸發嚴格安全檢查
    try:
        orig = request.headers.get("origin")
        orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if (orig and orig.startswith("https://")) else request.url.scheme)
        fwd_headers["X-Forwarded-Proto"] = orig_scheme
        host_hdr = request.headers.get("host")
        if orig:
            parts = urlsplit(orig)
            host_hdr = parts.hostname if parts.hostname else host_hdr
            port = parts.port or (443 if parts.scheme == "https" else 80)
            fwd_headers["X-Forwarded-Port"] = str(port)
        if host_hdr:
            fwd_headers["X-Forwarded-Host"] = host_hdr
    except Exception:
        pass

    # 讀取請求 body（POST/PUT/PATCH）
    body = await request.body()

    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=60, follow_redirects=False) as client:
        # 要求未壓縮，避免任何解壓/標頭不同步問題
        fwd_headers["Accept-Encoding"] = "identity"
        # 若為（含雜湊或非雜湊）internal/api 路徑，補上常見的 anti-CSRF 標頭，避免上游誤回 HTML
        if hashed_api_match or path.startswith("internal/") or path.startswith("api/"):
            fwd_headers.setdefault("kbn-xsrf", "true")
            fwd_headers.setdefault("X-Requested-With", "XMLHttpRequest")
            fwd_headers.setdefault("Accept", "application/json, text/plain, */*")
        r = await client.request(request.method, target_url, headers=fwd_headers, content=body)

    # 建立回應並複寫標頭，移除會阻擋 iframe 的標頭
    content = r.content
    ct = r.headers.get("content-type", "")
    modified_html = False
    modified_js = False
    if "text/html" in ct:
        # 僅重寫 HTML 中的 URL（href/src/action、meta refresh），避免改動 inline script 內容以免觸發 Kibana 的 CSP hash/nonce 失效
        try:
            text = content.decode("utf-8", errors="ignore")
            # 注意：不要刪除 Kibana 內嵌的 meta http-equiv CSP，否則會失去允許 inline bootstrap 的 nonce 設定
            # 1) 絕對 URL -> /kbn/
            kbn_abs = settings.KBN_URL.rstrip('/') + '/'
            text = text.replace(kbn_abs, "/kbn/")
            # 2) href|src|action="/xxx" -> "/kbn/xxx"（若已是 /kbn/ 則不動）
            pattern = re.compile(r'(\b(?:href|src|action)=[\"\"])\/(?!kbn\/)')
            text = pattern.sub(r'\1/kbn/', text)
            # 3) meta refresh 之類的 url=/xxx
            pattern2 = re.compile(r'(url=)\/(?!kbn\/)')
            text = pattern2.sub(r'\1/kbn/', text)
            # 4) 但不要改壞 <base href>。若被改成 /kbn/{hash}/，改回 /{hash}/
            text = re.sub(r'(<base\s+[^>]*href=\")/kbn/([0-9a-fA-F]{6,}/)', r'\1/\2', text, flags=re.IGNORECASE)
            text = re.sub(r"(<base\s+[^>]*href=\')/kbn/([0-9a-fA-F]{6,}/)", r"\1/\2", text, flags=re.IGNORECASE)
            content = text.encode("utf-8")
            modified_html = True
        except Exception:
            pass

    # 不改寫任何 JS，避免破壞壓縮/編碼或語法

    resp = Response(content=content, status_code=r.status_code)
    # 針對常見問題資產增加偵錯標頭（只在開發時使用）
    if "kbn-ui-shared-deps" in target_url and ("javascript" in ct or target_url.endswith(".js")):
        try:
            first = content[:8].hex()
            resp.headers["X-Debug-CT"] = ct
            resp.headers["X-Debug-CE"] = r.headers.get("content-encoding", "")
            resp.headers["X-Debug-First8"] = first
        except Exception:
            pass
    # 一般偵錯資訊：上游 Content-Type、狀態碼與是否為 HTML（協助判斷 JSON 被 HTML 取代）
    try:
        resp.headers["X-Upstream-CT"] = ct
        resp.headers["X-Upstream-Status"] = str(r.status_code)
        if "text/html" in ct:
            resp.headers["X-Proxy-HTML"] = "1"
    except Exception:
        pass
    # Debug header 指示是否進行了內容重寫
    if modified_html:
        resp.headers["X-Proxy-Rewrite"] = "html"
    elif modified_js:
        resp.headers["X-Proxy-Rewrite"] = "js"
    if hashed_api_match:
        resp.headers["X-Proxy-Hashed-API"] = "1"
    # 額外除錯：這次請求是否帶了 Cookie
    try:
        if request.headers.get("cookie"):
            resp.headers["X-Proxy-Has-Cookie"] = "1"
            resp.headers["X-Proxy-Cookie-Len"] = str(len(request.headers.get("cookie","")))
    except Exception:
        pass
    # 判斷原始瀏覽器協定（避免錯誤移除 Secure）
    orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if request.headers.get("origin", "").startswith("https://") else request.url.scheme)
    _copy_response_headers(r, resp, request.url.hostname, orig_scheme, strip_encoding_length=modified_html)
    # 除錯：回傳上游 CSP 內容，便於確認是否包含 nonce
    try:
        csp = r.headers.get("content-security-policy", "")
        if csp:
            resp.headers["X-Upstream-CSP"] = csp[:2048]  # 避免過長
    except Exception:
        pass
    # 放寬 CSP 與框架相關標頭，避免擋到 iframe 與 inline bootstrap（開發/內嵌情境）
    if settings.RELAX_KBN_CSP:
        # 移除會阻擋 iframe 的 X-Frame-Options
        if "X-Frame-Options" in resp.headers:
            del resp.headers["X-Frame-Options"]
    # 保留 Kibana 的原生 CSP 與 nonce/hash；不再改寫 CSP 內容
        # 為了滿足 Kibana 嚴格安全需求（例如 SharedArrayBuffer 需要 cross-origin isolation）
    # 為了讓 iframe 內頁也處於 cross-origin isolated（Kibana 某些功能需要），統一補上；setdefault 不會覆寫上游既有值
    resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
    resp.headers.setdefault("Cross-Origin-Embedder-Policy", "require-corp")
    resp.headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")
    resp.headers.setdefault("Origin-Agent-Cluster", "?1")
    # 避免瀏覽器快取舊版（尤其是 bootstrap.js），當我們做了 html/js 重寫時禁止快取
    if modified_html or modified_js or ("javascript" in ct) or ("text/html" in ct):
        resp.headers["Cache-Control"] = "no-store"
        # MutableHeaders 沒有 pop，需用 del
        if "ETag" in resp.headers:
            del resp.headers["ETag"]
        if "Last-Modified" in resp.headers:
            del resp.headers["Last-Modified"]
    return resp


# 轉發帶雜湊前綴的 /{hash}/internal/* 到真正的 /internal/*（Kibana 可能在前端以 basePath 帶上 hash）
@app.api_route("/{prefix}/internal/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], include_in_schema=False)
async def kibana_hashed_internal_proxy(prefix: str, path: str, request: Request):
    # 僅接受十六進位雜湊前綴，避免誤攔截其他路徑
    if not re.fullmatch(r"[0-9a-fA-F]{6,}", prefix):
        raise HTTPException(404, "Not Found")

    target_url = f"{settings.KBN_URL}/internal/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                  "te", "trailers", "transfer-encoding", "upgrade"}
    fwd_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in hop_by_hop or lk == "host" or lk in {"if-none-match", "if-modified-since", "if-match", "if-unmodified-since"}:
            continue
        fwd_headers[k] = v
    try:
        orig = request.headers.get("origin")
        orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if (orig and orig.startswith("https://")) else request.url.scheme)
        fwd_headers["X-Forwarded-Proto"] = orig_scheme
        host_hdr = request.headers.get("host")
        if orig:
            parts = urlsplit(orig)
            host_hdr = parts.hostname if parts.hostname else host_hdr
            port = parts.port or (443 if parts.scheme == "https" else 80)
            fwd_headers["X-Forwarded-Port"] = str(port)
        if host_hdr:
            fwd_headers["X-Forwarded-Host"] = host_hdr
    except Exception:
        pass

    body = await request.body()
    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=60, follow_redirects=False) as client:
        fwd_headers["Accept-Encoding"] = "identity"
        # 一律加上，避免被視為瀏覽而回 HTML
        fwd_headers.setdefault("kbn-xsrf", "true")
        fwd_headers.setdefault("X-Requested-With", "XMLHttpRequest")
        r = await client.request(request.method, target_url, headers=fwd_headers, content=body)

    resp = Response(content=r.content, status_code=r.status_code)
    orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if request.headers.get("origin", "").startswith("https://") else request.url.scheme)
    _copy_response_headers(r, resp, request.url.hostname, orig_scheme)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Upstream-URL"] = f"/internal/{path}"
    # Debug headers to help spot HTML responses and cookie presence
    try:
        if request.headers.get("cookie"):
            resp.headers["X-Proxy-Has-Cookie"] = "1"
        ct = r.headers.get("content-type", "")
        if "text/html" in ct:
            resp.headers["X-Proxy-HTML"] = "1"
        resp.headers["X-Upstream-CT"] = ct
    except Exception:
        pass
    try:
        if (r.status_code >= 300) or ("text/html" in r.headers.get("content-type", "")):
            print(f"[proxy] HASHED INTERNAL -> HTML or non-2xx: {settings.KBN_URL}/internal/{path} status={r.status_code} ct={r.headers.get('content-type','')} loc={r.headers.get('location','')} ")
    except Exception:
        pass
    return resp


# 轉發帶雜湊前綴的 /{hash}/api/* 到真正的 /api/*
@app.api_route("/{prefix}/api/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], include_in_schema=False)
async def kibana_hashed_api_proxy(prefix: str, path: str, request: Request):
    if not re.fullmatch(r"[0-9a-fA-F]{6,}", prefix):
        raise HTTPException(404, "Not Found")

    target_url = f"{settings.KBN_URL}/api/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                  "te", "trailers", "transfer-encoding", "upgrade"}
    fwd_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in hop_by_hop or lk == "host" or lk in {"if-none-match", "if-modified-since", "if-match", "if-unmodified-since"}:
            continue
        fwd_headers[k] = v
    try:
        orig = request.headers.get("origin")
        orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if (orig and orig.startswith("https://")) else request.url.scheme)
        fwd_headers["X-Forwarded-Proto"] = orig_scheme
        host_hdr = request.headers.get("host")
        if orig:
            parts = urlsplit(orig)
            host_hdr = parts.hostname if parts.hostname else host_hdr
            port = parts.port or (443 if parts.scheme == "https" else 80)
            fwd_headers["X-Forwarded-Port"] = str(port)
        if host_hdr:
            fwd_headers["X-Forwarded-Host"] = host_hdr
    except Exception:
        pass

    body = await request.body()
    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=60, follow_redirects=False) as client:
        fwd_headers["Accept-Encoding"] = "identity"
        fwd_headers.setdefault("kbn-xsrf", "true")
        fwd_headers.setdefault("X-Requested-With", "XMLHttpRequest")
        r = await client.request(request.method, target_url, headers=fwd_headers, content=body)

    resp = Response(content=r.content, status_code=r.status_code)
    orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if request.headers.get("origin", "").startswith("https://") else request.url.scheme)
    _copy_response_headers(r, resp, request.url.hostname, orig_scheme)
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Upstream-URL"] = f"/api/{path}"
    # Debug headers
    try:
        if request.headers.get("cookie"):
            resp.headers["X-Proxy-Has-Cookie"] = "1"
        ct = r.headers.get("content-type", "")
        if "text/html" in ct:
            resp.headers["X-Proxy-HTML"] = "1"
        resp.headers["X-Upstream-CT"] = ct
    except Exception:
        pass
    try:
        if (r.status_code >= 300) or ("text/html" in r.headers.get("content-type", "")):
            print(f"[proxy] HASHED API -> HTML or non-2xx: {settings.KBN_URL}/api/{path} status={r.status_code} ct={r.headers.get('content-type','')} loc={r.headers.get('location','')} ")
    except Exception:
        pass
    return resp


# 轉發 Kibana root 路徑下的 /internal/*（iframe 內的 XHR 常走這個 prefix）
@app.api_route("/internal/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], include_in_schema=False)
async def kibana_internal_proxy(path: str, request: Request):
    target_url = f"{settings.KBN_URL}/internal/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                  "te", "trailers", "transfer-encoding", "upgrade"}
    fwd_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in hop_by_hop or lk == "host" or lk in {"if-none-match", "if-modified-since", "if-match", "if-unmodified-since"}:
            continue
        fwd_headers[k] = v
    try:
        orig = request.headers.get("origin")
        orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if (orig and orig.startswith("https://")) else request.url.scheme)
        fwd_headers["X-Forwarded-Proto"] = orig_scheme
        host_hdr = request.headers.get("host")
        if orig:
            parts = urlsplit(orig)
            host_hdr = parts.hostname if parts.hostname else host_hdr
            port = parts.port or (443 if parts.scheme == "https" else 80)
            fwd_headers["X-Forwarded-Port"] = str(port)
        if host_hdr:
            fwd_headers["X-Forwarded-Host"] = host_hdr
    except Exception:
        pass

    body = await request.body()
    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=60, follow_redirects=False) as client:
        # 統一要求未壓縮，避免上游壓縮但下游缺少對應標頭
        fwd_headers["Accept-Encoding"] = "identity"
        fwd_headers.setdefault("kbn-xsrf", "true")
        fwd_headers.setdefault("X-Requested-With", "XMLHttpRequest")
        r = await client.request(request.method, target_url, headers=fwd_headers, content=body)

    resp = Response(content=r.content, status_code=r.status_code)
    orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if request.headers.get("origin", "").startswith("https://") else request.url.scheme)
    _copy_response_headers(r, resp, request.url.hostname, orig_scheme)
    # API 通常不需快取
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Upstream-URL"] = f"/internal/{path}"
    try:
        if request.headers.get("cookie"):
            resp.headers["X-Proxy-Has-Cookie"] = "1"
        ct = r.headers.get("content-type", "")
        if "text/html" in ct:
            resp.headers["X-Proxy-HTML"] = "1"
        resp.headers["X-Upstream-CT"] = ct
    except Exception:
        pass
    try:
        if (r.status_code >= 300) or ("text/html" in r.headers.get("content-type", "")):
            print(f"[proxy] INTERNAL -> HTML or non-2xx: {settings.KBN_URL}/internal/{path} status={r.status_code} ct={r.headers.get('content-type','')} loc={r.headers.get('location','')} ")
    except Exception:
        pass
    return resp


# 轉發 Kibana 的 /api/* （注意：具體路由如 /api/login 等已在上方定義，FastAPI 會先匹配具體路徑）
@app.api_route("/api/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"], include_in_schema=False)
async def kibana_api_proxy_catchall(path: str, request: Request):
    # 避免誤轉發本應由本服務處理的 API，可加上白名單/黑名單；這裡先簡化交由路由優先級處理。
    target_url = f"{settings.KBN_URL}/api/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                  "te", "trailers", "transfer-encoding", "upgrade"}
    fwd_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in hop_by_hop or lk == "host" or lk in {"if-none-match", "if-modified-since", "if-match", "if-unmodified-since"}:
            continue
        fwd_headers[k] = v
    try:
        orig = request.headers.get("origin")
        orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if (orig and orig.startswith("https://")) else request.url.scheme)
        fwd_headers["X-Forwarded-Proto"] = orig_scheme
        host_hdr = request.headers.get("host")
        if orig:
            parts = urlsplit(orig)
            host_hdr = parts.hostname if parts.hostname else host_hdr
            port = parts.port or (443 if parts.scheme == "https" else 80)
            fwd_headers["X-Forwarded-Port"] = str(port)
        if host_hdr:
            fwd_headers["X-Forwarded-Host"] = host_hdr
    except Exception:
        pass

    body = await request.body()
    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=60, follow_redirects=False) as client:
        # 統一要求未壓縮，避免上游壓縮但下游缺少對應標頭
        fwd_headers["Accept-Encoding"] = "identity"
        fwd_headers.setdefault("kbn-xsrf", "true")
        fwd_headers.setdefault("X-Requested-With", "XMLHttpRequest")
        r = await client.request(request.method, target_url, headers=fwd_headers, content=body)

    resp = Response(content=r.content, status_code=r.status_code)
    orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if request.headers.get("origin", "").startswith("https://") else request.url.scheme)
    _copy_response_headers(r, resp, request.url.hostname, orig_scheme)
    # API 通常不需快取
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["X-Upstream-URL"] = f"/api/{path}"
    try:
        if request.headers.get("cookie"):
            resp.headers["X-Proxy-Has-Cookie"] = "1"
        ct = r.headers.get("content-type", "")
        if "text/html" in ct:
            resp.headers["X-Proxy-HTML"] = "1"
        resp.headers["X-Upstream-CT"] = ct
    except Exception:
        pass
    try:
        if (r.status_code >= 300) or ("text/html" in r.headers.get("content-type", "")):
            print(f"[proxy] API -> HTML or non-2xx: {settings.KBN_URL}/api/{path} status={r.status_code} ct={r.headers.get('content-type','')} loc={r.headers.get('location','')} ")
    except Exception:
        pass
    return resp


# 代理 Kibana 翻譯資源
@app.api_route("/translations/{path:path}", methods=["GET", "HEAD"], include_in_schema=False)
async def kibana_translations(path: str, request: Request):
    """代理 Kibana 的翻譯資源，例如 /translations/a399c2baef20/en.json"""
    target_url = f"{settings.KBN_URL}/translations/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                  "te", "trailers", "transfer-encoding", "upgrade"}
    fwd_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in hop_by_hop or lk == "host":
            continue
        fwd_headers[k] = v
    
    fwd_headers["Accept-Encoding"] = "identity"
    
    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=30, follow_redirects=False) as client:
        r = await client.request(request.method, target_url, headers=fwd_headers)
    
    return Response(content=r.content, status_code=r.status_code, headers=dict(r.headers))


# 代理 Kibana 的雜湊前綴靜態資產：例如 /c8b46e7c4d6/bundles/...、/c8b46e7c4d6/core/core.entry.js、/c8b46e7c4d6/bootstrap.js
@app.api_route("/{prefix}/{rest:path}", methods=["GET", "HEAD"], include_in_schema=False)
async def kibana_hashed_assets(prefix: str, rest: str, request: Request):
    # 僅針對 6+ 位十六進位雜湊前綴，放寬子路徑為任意（部分資產位於 core/ 或直接 bootstrap.js）
    if not re.fullmatch(r"[0-9a-fA-F]{6,}", prefix):
        raise HTTPException(404, "Not Found")

    target_url = f"{settings.KBN_URL}/{prefix}/{rest}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    hop_by_hop = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
                  "te", "trailers", "transfer-encoding", "upgrade"}
    fwd_headers = {}
    for k, v in request.headers.items():
        lk = k.lower()
        if lk in hop_by_hop or lk == "host" or lk in {"if-none-match", "if-modified-since", "if-match", "if-unmodified-since"}:
            continue
        fwd_headers[k] = v
    try:
        orig = request.headers.get("origin")
        orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if (orig and orig.startswith("https://")) else request.url.scheme)
        fwd_headers["X-Forwarded-Proto"] = orig_scheme
        host_hdr = request.headers.get("host")
        if orig:
            parts = urlsplit(orig)
            host_hdr = parts.hostname if parts.hostname else host_hdr
            port = parts.port or (443 if parts.scheme == "https" else 80)
            fwd_headers["X-Forwarded-Port"] = str(port)
        if host_hdr:
            fwd_headers["X-Forwarded-Host"] = host_hdr
    except Exception:
        pass
    # 統一要求未壓縮，避免壓縮/標頭不同步
    fwd_headers["Accept-Encoding"] = "identity"

    async with httpx.AsyncClient(verify=settings.VERIFY_TLS, timeout=60, follow_redirects=False) as client:
        r = await client.request(request.method, target_url, headers=fwd_headers)
        # 若上游 404，嘗試移除 hash 前綴直接取 /{rest}（某些部署 publicPath 僅作 cache-busting 並不真存在）
        if r.status_code == 404:
            target_url2 = f"{settings.KBN_URL}/{rest}"
            if request.url.query:
                target_url2 += f"?{request.url.query}"
            r2 = await client.request(request.method, target_url2, headers=fwd_headers)
            if r2.status_code != 404:
                r = r2

    resp = Response(content=r.content, status_code=r.status_code)
    orig_scheme = request.headers.get("x-forwarded-proto") or ("https" if request.headers.get("origin", "").startswith("https://") else request.url.scheme)
    # 若未改寫內容，保留上游的 content-encoding/length 以利瀏覽器正確處理
    _copy_response_headers(r, resp, request.url.hostname, orig_scheme)
    resp.headers["X-Proxy-Hashed"] = "1"
    # 對 JS 設為 no-store 以避免舊資產殘留
    ct = r.headers.get("content-type", "")
    if "javascript" in ct:
        resp.headers["Cache-Control"] = "no-store"
    # 對 JS/CSS/字型等資產，若仍需防止舊快取，可視情況設定 no-store；先保守不改，除非發現仍拿舊版
    return resp
