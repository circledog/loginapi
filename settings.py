from pydantic import BaseModel
import os

class Settings(BaseModel):
    # 兼容既有命名：若未設 ES_URL，改讀 ELASTIC_URL
    ES_URL: str = os.getenv("ES_URL", os.getenv("ELASTIC_URL", "https://127.0.0.1:9200"))
    # 兼容 KBN_URL：若未設 KBN_URL，可用 ELASTIC_KIBANA_URL（若有）
    KBN_URL: str = os.getenv("KBN_URL", os.getenv("ELASTIC_KIBANA_URL", "https://127.0.0.1:5601"))
    VERIFY_TLS: bool = os.getenv("VERIFY_TLS", "false").lower() == "true"
    # Kibana provider 名稱（Elastic Cloud 常為 cloud-basic）
    KBN_PROVIDER_NAME: str = os.getenv("KBN_PROVIDER_NAME", "basic")
    # 授權流程：token 或 password（預設為 token；可用環境變數切換成 password）
    ES_GRANT_FLOW: str = os.getenv("ES_GRANT_FLOW", "token")
    # 「安全方案A」: 不把 ES API Key 給前端，而是存在後端（例如記憶體/Redis）
    # 這裡 demo 用 In-Memory（多副本時請改 Redis）
    ISSUE_SERVER_JWT: bool = os.getenv("ISSUE_SERVER_JWT", "true").lower() == "true"
    SERVER_JWT_SECRET: str = os.getenv("SERVER_JWT_SECRET", "change-me")
    SERVER_JWT_EXPIRE_DAYS: int = int(os.getenv("SERVER_JWT_EXPIRE_DAYS", "7"))
    # 開發時，為了避免外層或代理覆蓋 CSP 造成 Kibana inline bootstrap 被擋，提供鬆綁選項
    RELAX_KBN_CSP: bool = os.getenv("RELAX_KBN_CSP", "true").lower() == "true"

settings = Settings()
