# main.py
from fastapi import FastAPI, Request, Response, Depends, Form, HTTPException
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from fastapi.responses import RedirectResponse, Response as FastAPIResponse
from datetime import datetime, timedelta
import secrets
import asyncio
import re

from database import (
    users_col, systems_col, active_col,
    logs_col, contributors_col, sessions_col,
    create_user, user_exists, login_user
)

app = FastAPI()

templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

COOKIE_NAME = "auth_session"

def validate_ip(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def validate_hours(h: str):
    try:
        val = float(h)
        return val if val > 0 else None
    except:
        return None


def get_current_user(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    session = sessions_col.find_one({"session_token": token})
    if not session or session["expires_at"] < datetime.now():
        return None
    user = users_col.find_one({"email": session["email"]}, {"_id": 0, "password": 0})
    return user if user else None


# ===== Helper: HTMX response with toast =====
def htmx_toast_response(message: str, msg_type: str = "success"):
    """Return 204 with HX-Trigger to show toast. Emojis are NOT allowed (headers must be Latin-1)."""
    # Optional: strip non-ASCII to be 100% safe
    safe_message = re.sub(r'[^\x00-\x7F]+', '', message)
    headers = {
        "HX-Trigger": f'{{"showNotification": {{"message": "{safe_message}", "type": "{msg_type}"}}}}'
    }
    return FastAPIResponse(status_code=204, headers=headers)


# ===== Routes =====
@app.get("/")
async def home(request: Request, user=Depends(get_current_user)):
    return RedirectResponse("/dashboard" if user else "/login")


@app.get("/register")
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})


@app.post("/register")
async def register_submit(
    request: Request,
    name: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    if not name.strip() or not email.strip() or len(password) < 5:
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Name, email required; password ≥5 chars."
        })

    if user_exists(email):
        return templates.TemplateResponse("register.html", {
            "request": request,
            "error": "Email already registered!"
        })

    create_user(name, email, password)

    response = templates.TemplateResponse("register.html", {
            "request": request,
            "success": f"Account Created Successfully!"
        })

    await asyncio.sleep(1)

    response.headers["HX-Redirect"] = "/login?message=Account created! Please log in.&msg_type=success"
    return response

@app.get("/login")
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login")
async def login_submit(
    request: Request,
    response: Response,
    email: str = Form(...),
    password: str = Form(...)
):
    user = login_user(email, password)
    if not user:
        return templates.TemplateResponse("login.html", {
            "request": request,
            "error": "Invalid email or password."
        })

    session_token = secrets.token_urlsafe(64)
    client_ip = request.headers.get("X-Forwarded-For", request.client.host).split(",")[0].strip()

    sessions_col.update_one(
        {"email": user["email"]},
        {"$set": {
            "session_token": session_token,
            "email": user["email"],
            "client_ip": client_ip,
            "created_at": datetime.now(),
            "expires_at": datetime.now() + timedelta(days=7),
        }},
        upsert=True
    )

    resp = RedirectResponse("/dashboard", 302)
    resp.set_cookie(COOKIE_NAME, session_token, httponly=True, max_age=86400, path="/", samesite="lax")
    return resp


@app.get("/dashboard")
async def dashboard(request: Request, user=Depends(get_current_user)):
    if not user:
        return RedirectResponse("/login")

    systems = list(systems_col.find({}, {"_id": 0}))
    active_records = list(active_col.find({}, {"_id": 0}))

    active = []
    for a in active_records:
        contribs = list(contributors_col.find({"main_ip": a["ip"], "main_user": a["user"]}, {"_id": 0}))
        a["contributors"] = contribs
        active.append(a)

    today_start = datetime.combine(datetime.today(), datetime.min.time())
    today_end = datetime.combine(datetime.today(), datetime.max.time())
    logs = list(logs_col.find({"start_time": {"$gte": today_start, "$lte": today_end}}, {"_id": 0}))

    normal_users = [u["name"] for u in users_col.find({"role": {"$in": ["user", "assigner"]}}, {"_id": 0, "name": 1})]
    all_users = list(users_col.find({"role": "user"}, {"_id": 0, "email": 1, "name": 1}))

    all_systems = []
    for s in systems:
        all_systems.append({"ip": s["ip"], "status": "free"})
    for a in active:
        all_systems.append({"ip": a["ip"], "status": "used", "owner": a["user"]})

    return templates.TemplateResponse("dashboard.html", {
        "request": request,
        "user": user,
        "systems": systems,
        "active": active,
        "logs": logs,
        "normal_users": normal_users,
        "all_systems": all_systems,
        "all_users": all_users,
        "is_manager": user["role"] == "manager",
        "is_assigner": user["role"] == "assigner"
    })


@app.get("/logout")
async def logout(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        sessions_col.delete_one({"session_token": token})
    resp = RedirectResponse("/login")
    resp.delete_cookie(COOKIE_NAME, path="/")
    return resp


# ===== HTMX Endpoints =====
@app.post("/book")
async def book_system(request: Request, ip: str = Form(...), project: str = Form(...), duration: str = Form(...)):
    user = get_current_user(request)
    if not user:
        return htmx_toast_response("Please log in first.", "error")
    if not project.strip() or validate_hours(duration) is None:
        return htmx_toast_response("Project and valid duration required.", "error")
    try:
        systems_col.delete_one({"ip": ip})
        active_col.insert_one({
            "ip": ip,
            "user": user["name"],
            "project": project,
            "duration": duration,
            "start_time": datetime.now(),
            "main_released": False
        })
        return htmx_toast_response(f"{ip} booked successfully!", "success")
    except Exception as e:
        print(f"Error in /book: {e}")
        return htmx_toast_response(f"Failed to book system or {ip} already Exists.", "error")


@app.post("/assign")
async def assign_system(request: Request, system: str = Form(...), user_name: str = Form(...), project: str = Form(...), duration: str = Form(...)):
    user = get_current_user(request)
    if not user or user["role"] not in ["manager", "assigner"]:
        return htmx_toast_response("Access denied. Only managers or assigners can assign systems.", "error")
    if not project.strip() or validate_hours(duration) is None:
        return htmx_toast_response("Invalid project or duration.", "error")

    try:
        if " - free" in system:
            ip = system.replace(" - free", "")
            systems_col.delete_one({"ip": ip})
            active_col.insert_one({
                "ip": ip,
                "user": user_name,
                "project": project,
                "duration": duration,
                "start_time": datetime.now(),
                "main_released": False
            })
            return htmx_toast_response(f"{ip} assigned to {user_name}.", "success")
        else:
            # Parse used system: "192.168.1.10 - using (Owner: Alice)"
            if " - using (Owner: " not in system:
                return htmx_toast_response("Invalid system format.", "error")
            ip = system.split(" - using (Owner: ")[0]
            owner = system.split("(Owner: ")[1].rstrip(")")
            contributors_col.insert_one({
                "main_ip": ip,
                "main_user": owner,
                "contributor": user_name,
                "project": project,
                "duration": duration,
                "start_time": datetime.now()
            })
            return htmx_toast_response(f"{user_name} added as contributor to {ip}.", "success")
    except Exception as e:
        print(f"Error in /assign: {e}")
        return htmx_toast_response("Failed to assign system. Please try again.", "error")

@app.post("/self/contribute")
async def self_contribute(request: Request, system: str = Form(...), project: str = Form(...), duration: str = Form(...)):
    user = get_current_user(request)
    if not user:
        return htmx_toast_response("Please log in first.", "error")

    if user["role"] not in ["user"]:
        return htmx_toast_response("Only normal users can self-contribute.", "error")

    if not project.strip() or validate_hours(duration) is None:
        return htmx_toast_response("Project and valid duration required.", "error")

    # system comes like: 192.168.1.10 - using (Owner: Alice)
    try:
        if " - using (Owner: " not in system:
            return htmx_toast_response("Invalid system format.", "error")

        ip = system.split(" - using (Owner: ")[0]
        owner = system.split("(Owner: ")[1].rstrip(")")

        # Prevent duplicate contribution
        already = contributors_col.find_one({"main_ip": ip, "contributor": user["name"]})
        if already:
            return htmx_toast_response("You are already a contributor.", "error")

        contributors_col.insert_one({
            "main_ip": ip,
            "main_user": owner,
            "contributor": user["name"],
            "project": project,
            "duration": duration,
            "start_time": datetime.now()
        })

        return htmx_toast_response(f"Joined {ip} as contributor!", "success")

    except Exception as e:
        print(f"Error in /self/contribute: {e}")
        return htmx_toast_response("Failed to contribute.", "error")
    
@app.post("/release/main")
async def release_main(request: Request, ip: str = Form(...)):
    user = get_current_user(request)
    if not user:
        raise HTTPException(403)
    record = active_col.find_one({"ip": ip, "user": user["name"]})
    if not record:
        raise HTTPException(404)

    contrib_count = contributors_col.count_documents({"main_ip": ip, "main_user": user["name"]})
    logs_col.insert_one({
        "ip": ip,
        "user": user["name"],
        "project": record["project"],
        "duration": record["duration"],
        "start_time": record["start_time"],
        "end_time": datetime.now(),
        "is_contribution": False
    })

    if contrib_count == 0:
        try:
            systems_col.insert_one({"ip": ip})
        except:
            pass
        active_col.delete_one({"ip": ip})
        return htmx_toast_response(f"{ip} released.", "success")
    else:
        active_col.update_one({"ip": ip}, {"$set": {"main_released": True}})
        return htmx_toast_response(f"{ip} released it. Contributors remains.", "success")


@app.post("/release/contrib")
async def release_contrib(request: Request, main_ip: str = Form(...), contributor: str = Form(...)):
    user = get_current_user(request)
    if not user:
        raise HTTPException(403)
    c = contributors_col.find_one({"main_ip": main_ip, "contributor": contributor})
    if c:
        logs_col.insert_one({
            "ip": main_ip,
            "user": contributor,
            "main_user": c["main_user"],
            "project": c["project"],
            "duration": c["duration"],
            "start_time": c["start_time"],
            "end_time": datetime.now(),
            "is_contribution": True
        })
        contributors_col.delete_one({"main_ip": main_ip, "contributor": contributor})

        remaining = contributors_col.count_documents({"main_ip": main_ip})
        main_released = active_col.find_one({"ip": main_ip, "main_released": True})
        if remaining == 0 and main_released:
            try:
                systems_col.insert_one({"ip": main_ip})
            except:
                pass
            active_col.delete_one({"ip": main_ip})
            return htmx_toast_response(f"{main_ip} fully released!", "success")
        else:
            return htmx_toast_response(f"Contribution of {main_ip} released.", "success")
    return htmx_toast_response(f"Contribution not found on {main_ip}.", "error")


@app.post("/add/system")
@app.post("/add/system")
async def add_system(request: Request, ip: str = Form(...)):
    user = get_current_user(request)
    if not user or user["role"] not in ["manager", "assigner"]:
        return htmx_toast_response("Access denied.", "error")
    
    if not validate_ip(ip):
        return htmx_toast_response(f"{ip} is in Invalid format!", "error")
    
    try:
        systems_col.insert_one({"ip": ip})
        return htmx_toast_response(f"{ip} is added successfully!", "success")
    except Exception as e:
        print(e)
        return htmx_toast_response(f"{ip} already exists!", "error")

@app.post("/remove/system")
async def remove_system(request: Request, ip: str = Form(...)):
    user = get_current_user(request)
    if not user or user["role"] not in ["manager", "assigner"]:
        raise HTTPException(403)
    systems_col.delete_one({"ip": ip})
    active_col.delete_one({"ip": ip})
    contributors_col.delete_many({"main_ip": ip})
    return htmx_toast_response(f"{ip} removed!", "error")


@app.post("/promote")
async def promote_user(request: Request, email: str = Form(...), role: str = Form(...)):
    user = get_current_user(request)
    if not user or user["role"] != "manager":
        raise HTTPException(403)
    if role in ["manager", "assigner"]:
        users_col.update_one({"email": email}, {"$set": {"role": role}})
        return htmx_toast_response(f"{email} promoted as {role}!", "success")
    return htmx_toast_response(f"Invalid role for {email}", "error")


from fastapi.middleware.cors import CORSMiddleware

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from mangum import Mangum
handler = Mangum(app)
