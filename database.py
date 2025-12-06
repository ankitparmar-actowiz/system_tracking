# database.py
from pymongo import MongoClient, ASCENDING
import bcrypt

# client = MongoClient("mongodb://localhost:27017/")
client = MongoClient("mongodb+srv://ankitparmaractowiz_db_user:M3bjZ3RWX2F5ACdd@systemtrackingapp.4egtw8y.mongodb.net/")
db = client["system_tracking_fastapi"]

users_col = db["users"]
systems_col = db["systems"]
active_col = db["active_usage"]
logs_col = db["usage_logs"]
contributors_col = db["contributors"]
sessions_col = db["sessions"]

systems_col.create_index(["ip"], unique=True)

active_col.create_index([
    ("ip", ASCENDING),
    ("user", ASCENDING),
    ("project", ASCENDING)
], unique=True)

contributors_col.create_index([
    ("main_ip", ASCENDING),
    ("main_user", ASCENDING),
    ("contributor", ASCENDING),
    ("project", ASCENDING)
], unique=True)

def hash_password(password: str) -> bytes:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def check_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed)


def create_user(name: str, email: str, password: str, role="user"):
    hashed = hash_password(password)
    users_col.insert_one({
        "name": name,
        "email": email,
        "password": hashed,
        "role": role,
    })


def user_exists(email: str):
    return users_col.find_one({"email": email})
# client = MongoClient("mongodb+srv://ankitparmaractowiz_db_user:M3bjZ3RWX2F5ACdd@systemtrackingapp.4egtw8y.mongodb.net/")


def login_user(email: str, password: str):
    user = users_col.find_one({"email": email})
    if user and check_password(password, user["password"]):
        return {"name": user["name"], "email": user["email"], "role": user["role"]}

    return None
