from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "SafeCheck"
    max_requests: int = 12
    request_timeout_seconds: float = 8.0
    user_agent: str = "SafeCheck/0.1 (authorized-security-assessment)"
    llm_api_key: str | None = None
    llm_base_url: str = "https://api.openai.com/v1"
    llm_model: str = "gpt-4.1-mini"


settings = Settings()

