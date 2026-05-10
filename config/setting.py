from pathlib import Path

from dotenv import load_dotenv
import os
env_path = Path(__file__).resolve().parent.parent / ".env"
load_dotenv(env_path)
print(f"[INFO] Loading environment variables from: {env_path}")

POSTGRES_DB = os.getenv("POSTGRES_DB")
POSTGRES_USER = os.getenv("POSTGRES_USER")
POSTGRES_PASSWORD = os.getenv("POSTGRES_PASSWORD")
POSTGRES_HOST = os.getenv("POSTGRES_HOST")
POSTGRES_PORT = os.getenv("POSTGRES_PORT")
OPEN_AI_KEY = os.getenv("OPEN_AI_KEY")
