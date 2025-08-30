# FastAPI Elasticsearch/Kibana API 文件

本專案提供一組基於 FastAPI 的後端 API，主要用於前端（Vue3 + CoreUI）與 Elasticsearch/Kibana 的整合。此文件將說明 API 的安裝、設定、主要端點與串接方式，協助前端開發者順利呼叫本 API。

## 目錄
- [安裝與啟動](#安裝與啟動)
- [環境變數設定](#環境變數設定)
- [API 端點說明](#api-端點說明)
- [前端串接範例](#前端串接範例)
- [注意事項](#注意事項)

---

## 安裝與啟動

1. 安裝 Python 3.9+。
2. 安裝依賴：
   ```bash
   pip install -r requirements.txt
   ```
3. 啟動服務：
   ```bash
   uvicorn app:app --host 0.0.0.0 --port 8000
   ```

---

## 環境變數設定
可於 `.env` 或系統環境變數設定下列參數：
| 變數名稱              | 預設值                    | 說明 |
|----------------------|---------------------------|------|
| ES_URL               | https://elasticsearch:9200| Elasticsearch 伺服器位址 |
| KBN_URL              | http://kibana:5601        | Kibana 伺服器位址 |
| VERIFY_TLS           | false                     | 是否驗證 TLS 憑證 |
| ISSUE_SERVER_JWT     | true                      | 是否啟用 Server JWT 模式 |
| SERVER_JWT_SECRET    | change-me                 | JWT 簽章密鑰 |
| SERVER_JWT_EXPIRE_DAYS | 7                        | JWT 有效天數 |

---

## API 端點說明

### 1. 健康檢查
- `GET /healthz`
- 回傳：`{"ok": true}`

### 2. 登入取得 Token
- `POST /api/login`
- 輸入：
  ```json
  {
    "username": "帳號",
    "password": "密碼"
  }
  ```
- 回傳（Server JWT 模式）：
  ```json
  {
    "token_type": "server_jwt",
    "token": "...JWT...",
    "expiresInDays": 7
  }
  ```
- 回傳（API Key 模式）：
  ```json
  {
    "token_type": "es_api_key",
    "token": "ApiKey ...",
    "expiresInDays": 7
  }
  ```
- **說明**：
  - Server JWT 模式（預設）：API Key 僅存在後端，前端取得 JWT，後續請帶 `Authorization: Bearer <token>` 呼叫 API。
  - API Key 模式：API Key 直接回傳給前端（不建議於瀏覽器直接呼叫 ES）。

### 3. Kibana IFrame URL
- `GET /api/kibana/iframe-url?path=/app/discover#/`
- 回傳：
  ```json
  { "url": "/kbn/app/discover#/" }
  ```
- **說明**：前端可將回傳的 url 放入 `<iframe src=...>`，以同源代理方式嵌入 Kibana。

### 4. 登出
- `POST /api/logout`
- 輸入（可選）：
  ```json
  { "token": "...JWT..." }
  ```
- 回傳：`{"ok": true}`

### 5. 取得 ES Indices（需登入）
- `GET /api/es/_cat/indices`
- Header：`Authorization: Bearer <token>`
- 回傳：Elasticsearch indices 資料（JSON 格式）

### 6. Kibana 代理
- `GET /kbn/{path}`
- **說明**：同源代理 Kibana，便於前端以 iframe 方式嵌入。

---

## 前端串接範例（Vue3 + Axios）

```js
// 登入取得 token
const res = await axios.post('/api/login', { username, password });
const token = res.data.token;

// 取得 ES indices
const indices = await axios.get('/api/es/_cat/indices', {
  headers: { Authorization: `Bearer ${token}` }
});

// 取得 Kibana iframe url
const { url } = await axios.get('/api/kibana/iframe-url', { params: { path: '/app/discover#/' } }).then(r => r.data);
// <iframe :src="url" />

// 登出
await axios.post('/api/logout', { token });
```

---

## 注意事項
- 跨域（CORS）已開啟，前端可直接呼叫。
- 若部署於不同網域，請調整 `allow_origins`。
- 若啟用 Server JWT 模式，API Key 僅存在後端，前端僅需保存 JWT。
- 若需更高安全性，建議搭配 HTTPS 與 Ingress/Proxy。
- 代理 Kibana 僅示範 GET，完整代理要另外寫 Nginx/Ingress (如果有需要再跟我說)。

---