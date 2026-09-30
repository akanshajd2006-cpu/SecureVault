import os
from dotenv import load_dotenv

load_dotenv()  # reads variables from a local .env file (never commit that file)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # No more hardcoded secret — pulled from environment.
    # Generate one with: python -c "import secrets; print(secrets.token_hex(32))"
    SECRET_KEY = os.environ.get("SECRET_KEY")

    if not SECRET_KEY:
        raise RuntimeError(
            "SECRET_KEY is not set. Create a .env file with SECRET_KEY=<random hex string>."
        )

    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(BASE_DIR, "database", "vault.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Debug is OFF unless explicitly turned on in .env — never leave this True in front of anyone
    DEBUG = os.environ.get("FLASK_DEBUG", "False").lower() == "true"

    # Uploaded files now live outside static/, so they can't be fetched directly by URL
    UPLOAD_FOLDER = os.path.join(BASE_DIR, "secure_storage", "uploads")
