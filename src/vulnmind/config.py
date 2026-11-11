from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Secrets are supplied by environment and must not be logged."""
    model_config = SettingsConfigDict(env_prefix="VULNMIND_", env_file=".env", extra="ignore")
    database_url: str | None = None
    report_root: str | None = None
    evidence_root: str | None = None
    approval_secret: str | None = None
    approval_allowed_signers: str | None = None
    report_signing_key: str | None = None
    report_signing_key_file: str | None = None
    enabled_http_commands: list[str] = ["fetch", "crawl", "validate-run"]
    http_broker_distro: str = "VulnMindLab"
    http_ca_file: str | None = None
