# database.py
from pymongo import MongoClient
import bcrypt
import os
import certifi

from time_utils import now_utc

# ------------------ MongoDB Connection ------------------
MONGO_URI = os.environ.get("MONGO_URI")
if not MONGO_URI:
    raise Exception("MONGO_URI environment variable not set!")

client = MongoClient(
    MONGO_URI,
    tls=True,
    tlsCAFile=certifi.where()
)

db = client["system_tracking_fastapi"]

users_col = db["users"]
systems_col = db["systems"]
active_col = db["active_usage"]
logs_col = db["usage_logs"]
contributors_col = db["contributors"]
sessions_col = db["sessions"]

# ------------------ Helper Functions ------------------
def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), hashed)

def create_user(name: str, email: str, password: str, role="user"):
    hashed = hash_password(password)
    try:
        users_col.insert_one({
            "name": name,
            "email": email,
            "password": hashed,
            "role": role,
            "created_at": now_utc()    
        })
        return True
    except Exception as e:
        print(f"[DB ERROR] create_user: {e}")
        return False

def user_exists(email: str) -> bool:
    try:
        return users_col.find_one({"email": email}) is not None
    except Exception as e:
        print(f"[DB ERROR] user_exists: {e}")
        return False

def login_user(email: str, password: str):
    try:
        user = users_col.find_one({"email": email})
        if user and check_password(password, user["password"]):
            return {
                "name": user["name"],
                "email": user["email"],
                "role": user["role"]
            }
    except Exception as e:
        print(f"[DB ERROR] login_user: {e}")
    return None

