from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    JWT_SECRET: str
    JWT_TTL: int
    JWT_ALGORITHM: str
    DATASOURCE_URL: str
    TEST_DATASOURCE_URL: str


settings = Settings()  # type: ignore
