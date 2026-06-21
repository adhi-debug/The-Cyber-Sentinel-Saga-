"""
©adhi-debug | 2026
config.py

Pydantic-settings application configuration loaded from
environment variables and .env file

Defines the Settings model with defaults for: server
(host 0.0.0.0, port 8000, debug, log_level), database
(postgresql+asyncpg URL), Redis URL, GeoIP MaxMind
database path, nginx log path, pipeline queue sizes
(raw 1000, parsed 500, feature 200, alert 100), batch
settings (size 32, timeout 50ms), and ML configuration
(autoencoder/random-forest/isolation-forest at 0.40/0.40
/0.20 with model_validator enforcing sum-to-1.0,
ae_threshold_percentile 99.5, MLflow tracking URI).
Exports a module-level singleton settings instance

Connects to:
  factory.py        - consumed in lifespan and create_app
  __main__.py       - server host/port/reload
  core/ingestion/   - queue sizes, log path
  core/detection/   - model_dir, ensemble weights
  core/enrichment/  - geoip_db_path
"""
from typing import Self

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    """
    Application configuration loaded from environment variables.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    app_name: str = "The-Cyber‑Sentinel-Saga"
    env: str = "development"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8000
    api_key: str = ""
    log_level: str = "INFO"
    database_url: str = "postgresql+asyncpg://adhidebug:adhiadmin@localhost:16969/adhidebug"
    redis_url: str = "redis://localhost:26969"
    geoip_account_id: str = "YOUR_ACCOUNT_ID"
    geoip_license_key: str = "YOUR_LICENSE_KEY"
    geoip_db_path: str = "./data/GeoLite2-City.mmdb"
    nginx_log_path: str = "./data/nginx/access.log"
    raw_queue_size: int = 1000
    parsed_queue_size: int = 500
    feature_queue_size: int = 200
    alert_queue_size: int = 100
    batch_size: int = 32
    batch_timeout_ms: int = 50

    model_dir: str = "data/models"
    detection_mode: str = "rules"
    ensemble_weight_ae: float = 0.40
    ensemble_weight_rf: float = 0.40
    ensemble_weight_if: float = 0.20
    ae_threshold_percentile: float = 99.5
    mlflow_tracking_uri: str = "file:./mlruns"
    skip_auto_train: bool = False

    @model_validator(mode="after")
    def _check_ensemble_weights(self) -> Self:
        """
        Validate that ensemble weights sum to 1.0
        """
        total = (
            self.ensemble_weight_ae
            + self.ensemble_weight_rf
            + self.ensemble_weight_if
        )
        if abs(total - 1.0) > 1e-6:
            raise ValueError(
                f"Ensemble weights must sum to 1.0, got {total:.6f}"
            )
        return self


settings = Settings()
