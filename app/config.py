from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env")
    SECRET_KEY: str
    ALGORITHM: str
    SQLALCHEMY_DATABASE_URL: str
    SQLALCHEMY_TEST_DATABASE_URL: str


settings = Settings()  # type: ignore
