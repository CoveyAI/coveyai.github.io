
import os
import secrets
import sqlite3
import time
from pathlib import Path
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request, UploadFile, File, Header, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware

# ---------------- CONFIG ----------------

CLIENT_KEY = os.environ["TIKTOK_CLIENT_KEY"].strip()
CLIENT_SECRET = os.environ["TIKTOK_CLIENT_SECRET"].strip()
REDIRECT_URI = os.environ["TIKTOK_REDIRECT_URI"].strip()
SESSION_SECRET = os.environ["SESSION_SECRET"]
API_SECRET = os.environ["COVEYAI_API_SECRET"]

DATABASE_PATH = os.getenv("DATABASE_PATH", "./coveyai.db")

TIKTOK_TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
TIKTOK_UPLOAD_INIT = (
    "https://open.tiktokapis.com/v2/post/publish/inbox/video/init/"
)
TIKTOK_STATUS_URL = (
    "https://open.tiktokapis.com/v2/post/publish/status/fetch/"
)

MAX_VIDEO_SIZE = 64 * 1024 * 1024

app = FastAPI(title="CoveyAI TikTok API")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=True,
    same_site="lax",
)

# ---------------- DATABASE ----------------

def get_db():
    path = Path(DATABASE_PATH)
    path.parent.mkdir(parents=True, exist_ok=True)

    db = sqlite3.connect(str(path))
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with get_db() as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                open_id TEXT PRIMARY KEY,
                access_token TEXT NOT NULL,
                refresh_token TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                refresh_expires_at INTEGER NOT NULL
            )
        """)


init_db()


def save_user(data):
    now = int(time.time())

    with get_db() as db:
        db.execute("""
            INSERT OR REPLACE INTO users
            (open_id, access_token, refresh_token,
             expires_at, refresh_expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (
            data["open_id"],
            data["access_token"],
            data["refresh_token"],
            now + int(data["expires_in"]),
            now + int(data["refresh_expires_in"]),
        ))


def get_user(open_id):
    with get_db() as db:
        return db.execute(
            "SELECT * FROM users WHERE open_id = ?",
            (open_id,)
        ).fetchone()


# ---------------- TOKEN MANAGEMENT ----------------

async def get_valid_token(open_id):
    user = get_user(open_id)

    if not user:
        raise HTTPException(404, "TikTok account is not connected")

    now = int(time.time())

    if user["expires_at"] > now + 300:
        return user["access_token"]

    if user["refresh_expires_at"] <= now:
        raise HTTPException(
            401,
            "TikTok authorization expired. Connect TikTok again."
        )

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            TIKTOK_TOKEN_URL,
            data={
                "client_key": CLIENT_KEY,
                "client_secret": CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": user["refresh_token"],
            },
        )

    if response.status_code != 200:
        raise HTTPException(502, "TikTok token refresh failed")

    result = response.json()

    if result.get("error") != "ok":
        raise HTTPException(502, "TikTok rejected token refresh")

    data = result["data"]

    save_user({
        "open_id": open_id,
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "expires_in": data["expires_in"],
        "refresh_expires_in": data["refresh_expires_in"],
    })

    return data["access_token"]


# ---------------- HOME ----------------

@app.get("/")
async def home():
    return HTMLResponse("""
    <html>
    <head><title>CoveyAI</title></head>
    <body style="background:#101010;color:white;
    font-family:Arial;padding:40px">
        <h1>CoveyAI</h1>
        <p>TikTok integration</p>
        <a href="/login" style="color:#aaa">
            Connect TikTok
        </a>
    </body>
    </html>
    """)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "CoveyAI"}


# ---------------- OAUTH LOGIN ----------------

@app.get("/login")
async def login(request: Request):
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    params = {
        "client_key": CLIENT_KEY,
        "response_type": "code",
        "scope": "user.info.basic,video.upload",
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    url = (
        "https://www.tiktok.com/v2/auth/authorize/?"
        + urlencode(params)
    )

    return RedirectResponse(url)


@app.get("/callback")
async def callback(request: Request):
    error = request.query_params.get("error")

    if error:
        return HTMLResponse(
            "TikTok authorization was not completed.",
            status_code=400,
        )

    code = request.query_params.get("code")
    state = request.query_params.get("state")
    saved_state = request.session.pop("oauth_state", None)

    if not code or not state or not saved_state:
        raise HTTPException(400, "Missing authorization data")

    if not secrets.compare_digest(state, saved_state):
        raise HTTPException(400, "Invalid OAuth state")

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            TIKTOK_TOKEN_URL,
            data={
                "client_key": CLIENT_KEY,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
            },
        )

    if response.status_code != 200:
        raise HTTPException(502, "TikTok token request failed")

    result = response.json()

    if result.get("error") != "ok":
        raise HTTPException(400, "TikTok authorization error")

    data = result["data"]

    save_user({
        "open_id": data["open_id"],
        "access_token": data["access_token"],
        "refresh_token": data["refresh_token"],
        "expires_in": data["expires_in"],
        "refresh_expires_in": data["refresh_expires_in"],
    })

    request.session["tiktok_open_id"] = data["open_id"]

    return HTMLResponse("""
    <html>
    <body style="background:#101010;color:white;
    font-family:Arial;padding:40px">
        <h1>CoveyAI</h1>
        <h2>TikTok connected successfully!</h2>
        <p>Your account is connected.</p>
        <p>You can close this page.</p>
    </body>
    </html>
    """)


# ---------------- API SECURITY ----------------

def check_api_key(api_key):
    if not api_key or not secrets.compare_digest(
        api_key, API_SECRET
    ):
        raise HTTPException(401, "Invalid API key")


# ---------------- VIDEO UPLOAD ----------------

@app.post("/upload")
async def upload_video(
    open_id: str,
    file: UploadFile = File(...),
    x_api_key: str = Header(None),
):
    check_api_key(x_api_key)

    if file.content_type not in (
        "video/mp4",
        "video/quicktime",
        "video/webm",
        "application/octet-stream",
    ):
        raise HTTPException(400, "Unsupported video format")

    video = await file.read(MAX_VIDEO_SIZE + 1)

    if not video:
        raise HTTPException(400, "Empty video")

    if len(video) > MAX_VIDEO_SIZE:
        raise HTTPException(
            413,
            "Video is too large. Maximum size is 64 MB."
        )

    if not video.startswith(b"\x00\x00\x00") and not (
        video.startswith(b"\x1a\x45\xdf\xa3")
    ):
        raise HTTPException(
            400,
            "File does not appear to be a supported video."
        )

    token = await get_valid_token(open_id)
    video_size = len(video)

    async with httpx.AsyncClient(timeout=120) as client:
        init_response = await client.post(
            TIKTOK_UPLOAD_INIT,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={
                "source_info": {
                    "source": "FILE_UPLOAD",
                    "video_size": video_size,
                    "chunk_size": video_size,
                    "total_chunk_count": 1,
                }
            },
        )

        if init_response.status_code != 200:
            raise HTTPException(
                502,
                "TikTok upload initialization failed"
            )

        init_data = init_response.json()

        if init_data.get("error", {}).get("code") != "ok":
            raise HTTPException(
                400,
                "TikTok: " + init_data.get("error", {}).get(
                    "message", "Upload initialization error"
                )
            )

        upload_info = init_data["data"]
        upload_url = upload_info["upload_url"]

        upload_response = await client.put(
            upload_url,
            content=video,
            headers={
                "Content-Type": file.content_type
                if file.content_type != "application/octet-stream"
                else "video/mp4",
                "Content-Length": str(video_size),
                "Content-Range": f"bytes 0-{video_size - 1}/{video_size}",
            },
        )

        if upload_response.status_code not in (200, 201, 206):
            raise HTTPException(
                502,
                "TikTok video transfer failed"
            )

    return {
        "success": True,
        "message": (
            "Video uploaded to TikTok inbox. "
            "The creator must open TikTok and finish posting."
        ),
        "publish_id": upload_info["publish_id"],
    }


# ---------------- UPLOAD STATUS ----------------

@app.post("/upload/status")
async def upload_status(
    publish_id: str,
    open_id: str,
    x_api_key: str = Header(None),
):
    check_api_key(x_api_key)

    token = await get_valid_token(open_id)

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            TIKTOK_STATUS_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={"publish_id": publish_id},
        )

    if response.status_code != 200:
        raise HTTPException(502, "Status request failed")

    result = response.json()

    if result.get("error", {}).get("code") != "ok":
        raise HTTPException(400, "TikTok status error")

    return result


# ---------------- END ----------------

