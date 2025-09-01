# FastAPI Elasticsearch/Kibana API 文件

本專案提供一組基於 FastAPI 的後端 API，主要用於前端（Vue3 + CoreUI）與 Elasticsearch/Kibana 的整合。此文件將說明 API 的安裝、設定、主要端點與串接方式，協助前端開發者順利呼叫本 API。

## 目錄
- [安裝與啟動](#安裝與啟動)
- [快速開始（Windows）](#快速開始windows)
- [Docker 部署](#docker-部署)
- [本機 HTTPS（Windows / mkcert）](#本機-httpswindows--mkcert)
- [環境變數設定](#環境變數設定)
- [API 端點說明](#api-端點說明)
- [前端串接範例（Vue3 + CoreUI）](#前端串接範例vue3--coreui)
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

## 快速開始（Windows）

1. 安裝依賴（於專案根目錄）
  ```powershell
  pip install -r .\requirements.txt
  ```
2. 設定環境變數（依你的環境調整）
  ```powershell
  $env:ES_URL = 'https://127.0.0.1:9200'
  $env:KBN_URL = 'https://127.0.0.1:5601'
  $env:VERIFY_TLS = 'false'  # 若自簽證書或開發環境
  ```
3. 啟動（預設 8000）
  ```powershell
  uvicorn app:app --host 0.0.0.0 --port 8000
  ```
4. 簡單測試
  ```powershell
  # 健康檢查
  Invoke-RestMethod -Uri 'http://127.0.0.1:8000/healthz'

  # 登入（請替換帳密）
  $body = @{ username = 'elastic'; password = 'your-password' } | ConvertTo-Json
  Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/login' -ContentType 'application/json' -Body $body
  ```

---

## Docker 部署

1. 建置映像
  ```powershell
  docker build -t loginapi:latest .
  ```
2. 執行容器（服務埠 8080，見 Dockerfile）
  ```powershell
  docker run --rm -p 8080:8080 `
    -e ES_URL='https://your-es:9200' `
    -e KBN_URL='https://your-kibana:5601' `
    -e VERIFY_TLS='false' `
    -e ISSUE_SERVER_JWT='true' `
    -e SERVER_JWT_SECRET='change-me' `
    -e SERVER_JWT_EXPIRE_DAYS='7' `
    -e ES_GRANT_FLOW='token' `
    -e KBN_PROVIDER_NAME='basic' `
    -e RELAX_KBN_CSP='true' `
    loginapi:latest
  ```
3. 測試
  ```powershell
  Invoke-RestMethod -Uri 'http://127.0.0.1:8080/healthz'
  ```

---

## 本機 HTTPS（Windows / mkcert）

目的：在開發機上讓前端（CoreUI/Vite）以 HTTPS 執行，便於使用 Secure Cookie、部分瀏覽器功能（如 COOP/COEP）與更貼近實際環境。

1) 安裝 Chocolatey 與 mkcert（以系統管理員 PowerShell 執行）

```powershell
# 安裝 Chocolatey（若你在 cmd 環境，可使用以下一行指令）
@"%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoProfile -InputFormat None -ExecutionPolicy Bypass -Command "iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))" && SET "PATH=%PATH%;%ALLUSERSPROFILE%\chocolatey\bin"

# 安裝 mkcert
choco install -y mkcert

# 安裝/註冊本機信任 CA（只需一次）
mkcert -install
```

2) 產生本機憑證（供 Vite 使用）

```powershell
mkcert localhost 127.0.0.1
# 會產生兩個檔案：一個不帶 key 後綴（憑證），一個帶 key 後綴（私鑰）
```

3) 重新命名並放置於前端專案

- 將無 key 後綴的檔案改名為 `dev.crt`
- 將帶 key 後綴的檔案改名為 `dev.key`
- 建立前端專案目錄 `coreui-kibana/cert/`，把兩個檔案放入其中

4) 啟動前端（Vite）為 HTTPS

```powershell
# PowerShell 設定環境變數後啟動
VITE_HTTPS=1 npm run dev
```

## 環境變數設定
服務透過環境變數讀取設定（見 `settings.py`）。以下為可用參數：

| 變數名稱               | 預設值                 | 說明 |
|-----------------------|------------------------|------|
| ES_URL                | https://127.0.0.1:9200 | Elasticsearch URL |
| KBN_URL               | https://127.0.0.1:5601 | Kibana URL |
| VERIFY_TLS            | false                  | 是否驗證 TLS 憑證（自簽/開發環境可設 false） |
| KBN_PROVIDER_NAME     | basic                  | Kibana provider 名稱（Elastic 常見為 basic 或 cloud-basic） |
| ES_GRANT_FLOW         | token                  | 取得 API Key 的流程：token 或 password；若 token 失敗會自動回退 password |
| ISSUE_SERVER_JWT      | true                   | 是否只將自家 JWT 給前端，ES API Key 僅存後端 |
| SERVER_JWT_SECRET     | change-me              | 自家 JWT 簽章密鑰（請務必更改） |
| SERVER_JWT_EXPIRE_DAYS| 7                      | 自家 JWT 有效天數 |
| RELAX_KBN_CSP         | true                   | 開發時鬆綁部分標頭以利 iframe 與內嵌啟動 |

範例 .env（可供 Docker Compose 或其他方式載入）
```dotenv
ES_URL=https://127.0.0.1:9200
KBN_URL=https://127.0.0.1:5601
VERIFY_TLS=false
ISSUE_SERVER_JWT=true
SERVER_JWT_SECRET=change-me
SERVER_JWT_EXPIRE_DAYS=7
ES_GRANT_FLOW=token
KBN_PROVIDER_NAME=basic
RELAX_KBN_CSP=true
```

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
- 測試端點（PowerShell）：
  ```powershell
  $body = @{ username = 'elastic帳號'; password = '密碼' } | ConvertTo-Json
  Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8000/api/login' -ContentType 'application/json' -Body $body
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

## 前端串接範例（Vue3 + CoreUI）

以下示範以 CoreUI for Vue 建立基本頁面，並串接本 API 完成登入、取得 ES indices 與嵌入 Kibana。

1) 建立共用 HTTP 實例（會自動帶上 Bearer Token）

```ts
// src/api/http.ts
import axios from 'axios';

export const http = axios.create({ baseURL: '/' });

http.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) config.headers = { ...config.headers, Authorization: `Bearer ${token}` };
  return config;
});
```

2) 登入頁（CoreUI 表單元件）

```vue
<!-- src/views/Login.vue -->
<script setup lang="ts">
import { ref } from 'vue';
import { useRouter } from 'vue-router';
import { http } from '@/api/http';

const router = useRouter();
const username = ref('');
const password = ref('');
const loading = ref(false);
const error = ref('');

const onSubmit = async () => {
  loading.value = true;
  error.value = '';
  try {
    const { data } = await http.post('/api/login', {
      username: username.value,
      password: password.value,
    });
    localStorage.setItem('token', data.token);
    router.push('/');
  } catch (e: any) {
    error.value = e?.response?.data?.message || '登入失敗';
  } finally {
    loading.value = false;
  }
};
</script>

<template>
  <CCard class="mx-auto" style="max-width: 420px">
    <CCardBody>
      <CForm @submit.prevent="onSubmit">
        <CInputGroup class="mb-3">
          <CInputGroupText>@</CInputGroupText>
          <CFormInput v-model="username" placeholder="帳號" autocomplete="username" required />
        </CInputGroup>
        <CInputGroup class="mb-3">
          <CInputGroupText>***</CInputGroupText>
          <CFormInput v-model="password" type="password" placeholder="密碼" autocomplete="current-password" required />
        </CInputGroup>
        <div class="d-grid">
          <CButton type="submit" color="primary" :disabled="loading">
            {{ loading ? '登入中…' : '登入' }}
          </CButton>
        </div>
        <div v-if="error" class="text-danger mt-2">{{ error }}</div>
      </CForm>
    </CCardBody>
  </CCard>
  
</template>
```

3) 列出 Elasticsearch indices（CoreUI 表格）

```vue
<!-- src/views/Indices.vue -->
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { http } from '@/api/http';

type IndexRow = { index: string; ['docs.count']?: string; ['store.size']?: string };
const indices = ref<IndexRow[]>([]);

onMounted(async () => {
  const { data } = await http.get('/api/es/_cat/indices', { params: { format: 'json' } });
  indices.value = data;
});
</script>

<template>
  <CCard>
    <CCardHeader>Elasticsearch Indices</CCardHeader>
    <CCardBody>
      <CTable
        striped
        small
        :columns="['index', 'docs.count', 'store.size']"
        :items="indices"
      />
    </CCardBody>
  </CCard>
</template>
```

4) 嵌入 Kibana（CoreUI 卡片 + iframe）

```vue
<!-- src/views/Kibana.vue -->
<script setup lang="ts">
import { onMounted, ref } from 'vue';
import { http } from '@/api/http';

const url = ref('');
onMounted(async () => {
  const { data } = await http.get('/api/kibana/iframe-url', { params: { path: '/app/discover#/' } });
  url.value = data.url;
});
</script>

<template>
  <CCard>
    <CCardBody>
      <iframe v-if="url" :src="url" style="width: 100%; height: 80vh; border: 0" />
    </CCardBody>
  </CCard>
</template>
```

5) 登出

```ts
await http.post('/api/logout');
localStorage.removeItem('token');
```

---

## 注意事項
- 跨域（CORS）已開啟，前端可直接呼叫。
- 若部署於不同網域，請調整 `allow_origins`。
- 若啟用 Server JWT 模式，API Key 僅存在後端，前端僅需保存 JWT。
- 若需更高安全性，建議搭配 HTTPS 與 Ingress/Proxy。
- 代理 Kibana 僅示範 GET，完整代理要另外寫 Nginx/Ingress (如果有需要再跟我說)。

---