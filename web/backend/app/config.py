"""
Central configuration for the Triager web backend.

Everything is overridable via environment variables (12-factor style) so the
same code runs in dev, docker, a packaged desktop .exe, or an air-gapped
forensic lab workstation.
"""
from pathlib import Path
from pydantic_settings import BaseSettings

from .runtime_paths import writable_data_dir, tools_dir

_data_dir = writable_data_dir()
_tools_dir = tools_dir()


class Settings(BaseSettings):
    # Storage layout
    # STORAGE_ROOT holds:
    #   uploads/<upload_id>/            raw uploaded zip(s) while being processed
    #   cases/<case_id>/raw/            extracted evidence / triage collections
    #   cases/<case_id>/triager_out/    Triager output directory (CSV artifacts)
    #   cases/<case_id>/case.sqlite     imported, queryable artifact database
    #   cases/<case_id>/jobs/<job_id>.log   stdout/stderr of long-running jobs
    #
    # Resolves next to the .exe (in a "data" folder) when packaged as a
    # desktop app, or under the repo root when run from source, either
    # way it's a stable location that survives restarts (unlike a
    # PyInstaller --onefile build's temp extraction directory).
    storage_root: Path = _data_dir / "storage"

    # Core app database (cases, users, jobs metadata)
    app_db_url: str = f"sqlite:///{(_data_dir / 'triager_app.db').as_posix()}"

    # Auth
    jwt_secret: str = "CHANGE_ME_IN_PRODUCTION"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 12

    # Triager binary
    triager_exe_path: str = str(_tools_dir / "Triager.exe")

    # Ingestion limits
    max_upload_bytes: int = 200 * 1024 * 1024 * 1024  # 200 GB, evidence zips are huge
    upload_chunk_bytes: int = 8 * 1024 * 1024
    csv_import_batch_rows: int = 5000

    # Local LLM defaults (used to pre-fill the AI panel)
    default_llm_endpoint: str = "http://localhost:11434/v1/chat/completions"
    default_llm_model: str = "llama3.1"

    class Config:
        env_prefix = "TRIAGER_WEB_"
        env_file = ".env"


settings = Settings()
settings.storage_root.mkdir(parents=True, exist_ok=True)
(settings.storage_root / "uploads").mkdir(parents=True, exist_ok=True)
(settings.storage_root / "cases").mkdir(parents=True, exist_ok=True)
