# FastAPI Elasticsearch/Kibana API 文件

本專案提供一組基於 FastAPI 的後端 API，主要用於前端（Vue3 + CoreUI）與 Elasticsearch/Kibana 的整合。此文件將說明 API 的安裝、設定、主要端點與串接方式，協助前端開發者順利呼叫本 API。

## 目錄
- [安裝與啟動](#安裝與啟動)
- [環境變數設定](#環境變數設定)
- [API 端點說明](#api-端點說明)
- [前端串接範例](#前端串接範例-Vue3-CoreUI)
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
可於 `settings.py` 設定下列參數：
| 變數名稱              | 預設值                    | 說明 |
|----------------------|---------------------------|------|
| ES_URL               | https://elasticsearch節點IP:9200| Elasticsearch 伺服器位址 |
| KBN_URL              | http://kibana節點IP:5601        | Kibana 伺服器位址 |
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
- 測試端點：
  ```powershell
  curl -sS -X POST http://127.0.0.1:8000/api/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"elastic帳號","password":"密碼"}'
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

## 前端串接範例 Vue3 CoreUI

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