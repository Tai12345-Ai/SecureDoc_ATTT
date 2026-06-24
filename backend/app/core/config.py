from pathlib import Path
from pydantic import BaseModel
import os

BASE_DIR = Path(__file__).resolve().parents[3]
DATA_DIR = BASE_DIR / "data"

class Settings(BaseModel):
    data_dir: Path = DATA_DIR
    demo_pki_dir: Path = DATA_DIR / "demo_pki"
    documents_dir: Path = DATA_DIR / "documents"
    signed_packages_dir: Path = DATA_DIR / "signed_packages"
    signed_documents_dir: Path = DATA_DIR / "signed_documents"
    certificates_dir: Path = DATA_DIR / "certificates"
    audit_file: Path = DATA_DIR / "audit_events.jsonl"

settings = Settings()

for directory in [
    settings.data_dir,
    settings.demo_pki_dir,
    settings.documents_dir,
    settings.signed_packages_dir,
    settings.signed_documents_dir,
    settings.certificates_dir,
]:
    directory.mkdir(parents=True, exist_ok=True)
