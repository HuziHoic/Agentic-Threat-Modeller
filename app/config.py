import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://husainc:mdbatmpwd123@cluster0.4h4cmun.mongodb.net/?appName=Cluster0")
    DB_NAME = os.getenv("DB_NAME", "agentic_modeller")

settings = Settings()
