
import os
import secrets
import sqlite3
import math
import time
import html
import hashlib

import httpx
from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware

# ============== SETTINGS ==============

CLIENT_KEY = os.environ["TIKTOK_CLIENT_KEY"].strip()
CLIENT_SECRET = os.environ["TIKTOK_CLIENT_SECRET"].strip()
REDIRECT_URI = os.environ["TIKTOK_REDIRECT_URI"].strip()
SESSION_SECRET = os.environ["SESSION_SECRET"]

TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "https://coveyai-github-io.onrender.com").rstrip("/")
TELEGRAM_API = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}" if TELEGRAM_BOT_TOKEN else ""
TELEGRAM_WEBHOOK_SECRET = hashlib.sha256(("CoveyAI:" + TELEGRAM_BOT_TOKEN).encode()).hexdigest() if TELEGRAM_BOT_TOKEN else ""

DATABASE_PATH = os.getenv("DATABASE_PATH", "./coveyai.db")

AUTH_URL = "https://www.tiktok.com/v2/auth/authorize/"
TOKEN_URL = "https://open.tiktokapis.com/v2/oauth/token/"
UPLOAD_INIT_URL = (
    "https://open.tiktokapis.com/v2/post/publish/inbox/video/init/"
)
STATUS_URL = (
    "https://open.tiktokapis.com/v2/post/publish/status/fetch/"
)

MAX_VIDEO_SIZE = 512 * 1024 * 1024
CHUNK_SIZE = 64 * 1024 * 1024

app = FastAPI(title="CoveyAI")

app.add_middleware(
    SessionMiddleware,
    secret_key=SESSION_SECRET,
    https_only=True,
    same_site="lax",
)

# ============== DATABASE ==============

def db_connect():
    db = sqlite3.connect(DATABASE_PATH)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    with db_connect() as db:
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


def save_tokens(data):
    now = int(time.time())

    with db_connect() as db:
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
    with db_connect() as db:
        return db.execute(
            "SELECT * FROM users WHERE open_id = ?",
            (open_id,)
        ).fetchone()


# ============== ERROR HANDLING ==============

def oauth_error(response, result):
    # TikTok OAuth v2 returns errors at the top level:
    # {"error": "...", "error_description": "...", "log_id": "..."}
    return {
        "detail": "TikTok OAuth returned an error",
        "http_status": response.status_code,
        "tiktok_error": result.get("error", "unknown"),
        "tiktok_message": result.get("error_description", ""),
        "log_id": result.get("log_id"),
    }


def check_oauth_response(response):
    try:
        result = response.json()
    except Exception:
        raise HTTPException(
            502,
            detail={
                "detail": "TikTok OAuth returned a non-JSON response",
                "http_status": response.status_code,
            },
        )

    if response.status_code != 200 or result.get("error"):
        raise HTTPException(
            502,
            detail=oauth_error(response, result),
        )

    # OAuth v2 success response is FLAT: access_token, refresh_token,
    # open_id, expires_in, refresh_expires_in. It is not wrapped in data.
    return result


def tiktok_error(response, result):
    error = result.get("error", {})
    if not isinstance(error, dict):
        error = {}

    return {
        "detail": "TikTok API returned an error",
        "http_status": response.status_code,
        "tiktok_code": error.get("code", "unknown"),
        "tiktok_message": error.get("message", ""),
        "log_id": error.get("log_id") or result.get("log_id"),
    }


def check_tiktok_response(response):
    try:
        result = response.json()
    except Exception:
        raise HTTPException(
            502,
            detail={
                "detail": "TikTok API returned an unreadable response",
                "http_status": response.status_code,
            },
        )

    if response.status_code != 200:
        raise HTTPException(
            502,
            detail=tiktok_error(response, result),
        )

    error = result.get("error", {})
    if isinstance(error, dict) and error.get("code") not in (None, "ok"):
        raise HTTPException(
            400,
            detail=tiktok_error(response, result),
        )

    return result.get("data", {})


# ============== HOME ==============

@app.get("/")
async def home():
    return HTMLResponse("""
    <html>
    <body style="background:#101010;color:white;
    font-family:Arial;padding:40px">
        <h1>CoveyAI</h1>
        <p>TikTok integration</p>
        <a href="/login" style="color:white">
            Connect TikTok
        </a>
    </body>
    </html>
    """)


@app.get("/health")
async def health():
    return {
        "status": "ok",
        "service": "CoveyAI"
    }


# ============== TIKTOK LOGIN ==============

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

    url = AUTH_URL + "?" + __import__(
        "urllib.parse", fromlist=["urlencode"]
    ).urlencode(params)

    return RedirectResponse(url)


@app.get("/callback")
async def callback(request: Request):
    error = request.query_params.get("error")

    if error:
        description = request.query_params.get(
            "error_description", "No details provided"
        )

        return JSONResponse({
            "detail": "TikTok authorization was not completed",
            "tiktok_error": error,
            "description": description,
        }, status_code=400)

    code = request.query_params.get("code")
    state = request.query_params.get("state")

    saved_state = request.session.pop("oauth_state", None)

    if not code:
        return JSONResponse({
            "detail": "TikTok did not return authorization code",
            "received_parameters": list(request.query_params.keys()),
        }, status_code=400)

    if not state or not saved_state:
        return JSONResponse({
            "detail": "OAuth state is missing",
            "hint": "Start authorization again using /login",
        }, status_code=400)

    if not secrets.compare_digest(state, saved_state):
        raise HTTPException(400, "OAuth state does not match")

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            TOKEN_URL,
            data={
                "client_key": CLIENT_KEY,
                "client_secret": CLIENT_SECRET,
                "code": code,
                "grant_type": "authorization_code",
                "redirect_uri": REDIRECT_URI,
            },
        )

    data = check_oauth_response(response)

    required = [
        "open_id",
        "access_token",
        "refresh_token",
        "expires_in",
        "refresh_expires_in",
    ]

    if any(key not in data for key in required):
        raise HTTPException(
            502,
            "TikTok token response is incomplete"
        )

    save_tokens(data)
    request.session["tiktok_open_id"] = data["open_id"]

    return HTMLResponse("""
    <html>
    <body style="background:#101010;color:white;
    font-family:Arial;padding:40px">
        <h1>CoveyAI</h1>
        <h2>TikTok connected successfully!</h2>
        <p>Your TikTok account is connected.</p>
        <p>You can close this page.</p>
    </body>
    </html>
    """)


# ============== TOKEN REFRESH ==============

async def get_access_token(open_id):
    user = get_user(open_id)

    if not user:
        raise HTTPException(
            401,
            "TikTok account is not connected"
        )

    now = int(time.time())

    if user["expires_at"] > now + 300:
        return user["access_token"]

    if user["refresh_expires_at"] <= now:
        raise HTTPException(
            401,
            "TikTok authorization expired. Connect again."
        )

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            TOKEN_URL,
            data={
                "client_key": CLIENT_KEY,
                "client_secret": CLIENT_SECRET,
                "grant_type": "refresh_token",
                "refresh_token": user["refresh_token"],
            },
        )

    data = check_oauth_response(response)

    data["open_id"] = open_id
    save_tokens(data)

    return data["access_token"]


# ============== VIDEO UPLOAD ==============

@app.post("/upload")
async def upload_video(
    request: Request,
    file: UploadFile = File(...),
):
    open_id = request.session.get("tiktok_open_id")

    if not open_id:
        raise HTTPException(
            401,
            "Connect TikTok first using /login"
        )

    allowed_types = {
        "video/mp4",
        "video/quicktime",
        "video/webm",
    }

    if file.content_type not in allowed_types:
        raise HTTPException(
            400,
            "Supported formats: MP4, MOV, WEBM"
        )

    video = await file.read(MAX_VIDEO_SIZE + 1)

    if not video:
        raise HTTPException(400, "Empty video")

    if len(video) > MAX_VIDEO_SIZE:
        raise HTTPException(
            413,
            "Maximum video size is 512 MB"
        )

    video_size = len(video)
    chunk_size = min(CHUNK_SIZE, video_size)
    total_chunks = math.ceil(video_size / chunk_size)

    token = await get_access_token(open_id)

    async with httpx.AsyncClient(timeout=180) as client:

        init_response = await client.post(
            UPLOAD_INIT_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json; charset=UTF-8",
            },
            json={
                "source_info": {
                    "source": "FILE_UPLOAD",
                    "video_size": video_size,
                    "chunk_size": chunk_size,
                    "total_chunk_count": total_chunks,
                }
            },
        )

        upload_data = check_tiktok_response(init_response)

        upload_url = upload_data.get("upload_url")
        publish_id = upload_data.get("publish_id")

        if not upload_url or not publish_id:
            raise HTTPException(
                502,
                "TikTok did not return upload information"
            )

        for index in range(total_chunks):
            start = index * chunk_size
            end = min(start + chunk_size, video_size)
            chunk = video[start:end]

            upload_response = await client.put(
                upload_url,
                content=chunk,
                headers={
                    "Content-Type": file.content_type,
                    "Content-Length": str(len(chunk)),
                    "Content-Range": (
                        f"bytes {start}-{end - 1}/{video_size}"
                    ),
                },
            )

            if upload_response.status_code not in (200, 201, 206):
                raise HTTPException(
                    502,
                    "TikTok video transfer failed"
                )

    return {
        "success": True,
        "publish_id": publish_id,
        "message": (
            "Video sent to TikTok inbox. "
            "Open TikTok to edit and finish posting."
        ),
    }


# ============== UPLOAD STATUS ==============

@app.post("/upload/status")
async def upload_status(
    request: Request,
    publish_id: str,
):
    open_id = request.session.get("tiktok_open_id")

    if not open_id:
        raise HTTPException(
            401,
            "Connect TikTok first"
        )

    token = await get_access_token(open_id)

    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            STATUS_URL,
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json",
            },
            json={
                "publish_id": publish_id
            },
        )

    data = check_tiktok_response(response)

    return {
        "success": True,
        "data": data
    }

# ============== TELEGRAM BOT ==============

async def telegram_call(method: str, payload: dict):
    if not TELEGRAM_BOT_TOKEN:
        return None
    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(f"{TELEGRAM_API}/{method}", json=payload)
        response.raise_for_status()
        result = response.json()
        if not result.get("ok"):
            raise RuntimeError("Telegram API request failed")
        return result.get("result")


async def telegram_send(chat_id: int, text: str):
    keyboard = {
        "keyboard": [
            [{"text": "🔎 Найти видео"}, {"text": "🎬 Мои видео"}],
            [{"text": "📤 Отправить в TikTok"}, {"text": "⭐ Подписка"}],
        ],
        "resize_keyboard": True,
    }
    await telegram_call("sendMessage", {
        "chat_id": chat_id,
        "text": text,
        "reply_markup": keyboard,
    })


@app.on_event("startup")
async def configure_telegram_webhook():
    if not TELEGRAM_BOT_TOKEN:
        print("Telegram bot is not configured: TELEGRAM_BOT_TOKEN is missing")
        return
    webhook_url = f"{PUBLIC_BASE_URL}/telegram/webhook/{TELEGRAM_WEBHOOK_SECRET}"
    try:
        await telegram_call("setWebhook", {
            "url": webhook_url,
            "allowed_updates": ["message"],
        })
        print("CoveyAI Telegram webhook configured")
    except Exception as exc:
        # Do not prevent the TikTok API from starting if Telegram is temporarily unavailable.
        print(f"Telegram webhook setup failed: {type(exc).__name__}")


@app.post("/telegram/webhook/{secret}")
async def telegram_webhook(secret: str, request: Request):
    if not TELEGRAM_BOT_TOKEN or not secrets.compare_digest(secret, TELEGRAM_WEBHOOK_SECRET):
        raise HTTPException(404, "Not found")

    update = await request.json()
    message = update.get("message") or {}
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    text = (message.get("text") or "").strip()
    if not chat_id or not text:
        return {"ok": True}

    if text.startswith("/start"):
        await telegram_send(
            chat_id,
            "Привет! Это CoveyAI 🎬\n\n"
            "Здесь будет поиск видео, предварительный просмотр, "
            "обработка собственных видео или материалов с разрешением "
            "и отправка в TikTok Inbox.\n\n"
            "Выбери раздел в меню ниже.",
        )
    elif text.startswith("/help"):
        await telegram_send(chat_id, "Используй меню CoveyAI. Функции подключаются поэтапно.")
    elif text == "🔎 Найти видео":
        await telegram_send(chat_id, "Поиск видео — следующий этап разработки. Используй только видео, на которые у тебя есть права или разрешение.")
    elif text == "🎬 Мои видео":
        await telegram_send(chat_id, "История видео появится после подключения обработки и сохранения заданий.")
    elif text == "📤 Отправить в TikTok":
        await telegram_send(chat_id, "Отправка через Telegram подключается следующим этапом. TikTok сейчас уже принимает тестовую загрузку через сервер.")
    elif text == "⭐ Подписка":
        await telegram_send(chat_id, "Тарифы и лимит 5 видео в день подключим на этапе подписок. Пока оплата не активна.")
    else:
        await telegram_send(chat_id, "Выбери действие в меню CoveyAI или отправь /help.")

    return {"ok": True}
