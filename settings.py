from pydantic import BaseModel
import os

class Settings(BaseModel):
    ES_URL: str = os.getenv("ES_URL", "https://elasticsearch:9200")
    KBN_URL: str = os.getenv("KBN_URL", "http://kibana:5601")
    VERIFY_TLS: bool = os.getenv("VERIFY_TLS", "false").lower() == "true"
    # 「安全方案A」: 不把 ES API Key 給前端，而是存在後端（例如記憶體/Redis）
    # 這裡 demo 用 In-Memory（多副本時請改 Redis）
    ISSUE_SERVER_JWT: bool = os.getenv("ISSUE_SERVER_JWT", "true").lower() == "true"
    SERVER_JWT_SECRET: str = os.getenv("SERVER_JWT_SECRET", "change-me")
    SERVER_JWT_EXPIRE_DAYS: int = int(os.getenv("SERVER_JWT_EXPIRE_DAYS", "7"))

settings = Settings()
