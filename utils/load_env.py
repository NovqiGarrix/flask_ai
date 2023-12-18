import os
from dotenv import load_dotenv

def load():
    if os.environ.get("FLASK_ENV") is None or os.environ.get("FLASK_ENV") == "development":
        load_dotenv()