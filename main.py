import os
import secrets
import sqlite3
import math
import time
import html
import hashlib
import re
import asyncio
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote_plus, urlparse

import httpx
from fastapi import FastAPI, Request, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.middleware.sessions import SessionMiddleware

# ============== SETTINGS ==============

CLIENT_KEY = os.environ["TIKTOK_CLIENT_KEY"].strip()
CLIENT_SECRET = os.environ["TIKTOK_CLIENT_SECRET"].strip()
REDIRECT_URI = os.environ["TIKTOK_REDIRECT_URI"].strip()
SESSION_SECRET = os.environ["SESSION_SECRET"]

DATABASE_PATH = os.getenv("DATABASE_PATH", "./coveyai.db")
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
PUBLIC_BASE_URL = os.getenv(
    "PUBLIC_BASE_URL", "https://coveyai-github-io.onrender.com"
).rstrip("/")
TELEGRAM_WEBHOOK_PATH_SECRET = hashlib.sha256(
    SESSION_SECRET.encode("utf-8")
).hexdigest()[:40]
TELEGRAM_WEBHOOK_PATH = f"/telegram/webhook/{TELEGRAM_WEBHOOK_PATH_SECRET}"
TELEGRAM_FILE_LIMIT = 20 * 1024 * 1024  # Telegram Bot API download limit

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
        db.execute("""
            CREATE TABLE IF NOT EXISTS telegram_accounts (
                chat_id TEXT PRIMARY KEY,
                open_id TEXT NOT NULL,
                connected_at INTEGER NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS pending_tiktok_links (
                state TEXT PRIMARY KEY,
                chat_id TEXT NOT NULL,
                expires_at INTEGER NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS telegram_uploads (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                publish_id TEXT NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS telegram_search_sessions (
                chat_id TEXT PRIMARY KEY,
                waiting_for_query INTEGER NOT NULL DEFAULT 0
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS bot_workflows (
                chat_id TEXT PRIMARY KEY,
                stage TEXT NOT NULL,
                source_url TEXT,
                media_id INTEGER,
                updated_at INTEGER NOT NULL
            )
        """)
        db.execute("""
            CREATE TABLE IF NOT EXISTS media_files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                chat_id TEXT NOT NULL,
                source_url TEXT,
                original_file_id TEXT NOT NULL,
                processed_file_id TEXT,
                original_size INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'uploaded',
                created_at INTEGER NOT NULL,
                processed_at INTEGER,
                published_at INTEGER,
                publish_id TEXT
            )
        """)
        db.execute("CREATE INDEX IF NOT EXISTS idx_media_chat_created ON media_files(chat_id, created_at DESC)")


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
    # TikTok OAuth v2 returns errors at the top level.
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
        "service": "CoveyAI",
        "telegram_configured": bool(TELEGRAM_BOT_TOKEN),
        "tiktok_search_mode": "search_link",
        "media_library": "telegram_file_ids_and_sqlite",
        "video_processing": "ffmpeg_vertical_mp4",
        "publishing": "tiktok_inbox",
        "direct_media_url_hosts_configured": bool(MEDIA_URL_ALLOWED_HOSTS),
        "publish_job_mode": "background_with_status_messages",
    }


# ============== TIKTOK LOGIN ==============

@app.get("/login")
async def login(request: Request):
    supplied_state = request.query_params.get("state")
    if supplied_state:
        with db_connect() as db:
            pending = db.execute(
                "SELECT state, expires_at FROM pending_tiktok_links WHERE state = ?",
                (supplied_state,),
            ).fetchone()
        if not pending or pending["expires_at"] < int(time.time()):
            raise HTTPException(400, "This Telegram connection link is invalid or expired")
        state = supplied_state
    else:
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
    pending_link = None
    if state:
        with db_connect() as db:
            pending_link = db.execute(
                "SELECT chat_id, expires_at FROM pending_tiktok_links WHERE state = ?",
                (state,),
            ).fetchone()

    if not code:
        return JSONResponse({
            "detail": "TikTok did not return authorization code",
            "received_parameters": list(request.query_params.keys()),
        }, status_code=400)

    is_telegram_link = bool(
        pending_link and pending_link["expires_at"] >= int(time.time())
    )
    if not is_telegram_link:
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

    if is_telegram_link:
        chat_id = pending_link["chat_id"]
        with db_connect() as db:
            db.execute(
                "INSERT OR REPLACE INTO telegram_accounts (chat_id, open_id, connected_at) VALUES (?, ?, ?)",
                (chat_id, data["open_id"], int(time.time())),
            )
            db.execute("DELETE FROM pending_tiktok_links WHERE state = ?", (state,))
        await telegram_send_message(
            chat_id,
            "✅ TikTok успешно подключён к CoveyAI! Теперь отправьте видео через кнопку «Опубликовать видео».",
            reply_markup=telegram_main_keyboard(),
        )

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


async def upload_video_bytes(open_id, video, content_type):
    allowed_types = {"video/mp4", "video/quicktime", "video/webm"}
    if content_type not in allowed_types:
        raise HTTPException(400, "Supported formats: MP4, MOV, WEBM")
    if not video:
        raise HTTPException(400, "Empty video")
    if len(video) > MAX_VIDEO_SIZE:
        raise HTTPException(413, "Maximum video size is 512 MB")

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
            raise HTTPException(502, "TikTok did not return upload information")

        for index in range(total_chunks):
            start = index * chunk_size
            end = min(start + chunk_size, video_size)
            chunk = video[start:end]
            upload_response = await client.put(
                upload_url,
                content=chunk,
                headers={
                    "Content-Type": content_type,
                    "Content-Length": str(len(chunk)),
                    "Content-Range": f"bytes {start}-{end - 1}/{video_size}",
                },
            )
            if upload_response.status_code not in (200, 201, 206):
                raise HTTPException(502, "TikTok video transfer failed")

    return publish_id


# ============== VIDEO UPLOAD ==============

@app.post("/upload")
async def upload_video(
    request: Request,
    file: UploadFile = File(...),
):
    open_id = request.session.get("tiktok_open_id")
    if not open_id:
        raise HTTPException(401, "Connect TikTok first using /login")

    video = await file.read(MAX_VIDEO_SIZE + 1)
    publish_id = await upload_video_bytes(open_id, video, file.content_type)
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

TG_API = "https://api.telegram.org/bot{}"
SITE_URL = "https://coveyai.github.io/"
TIKTOK_SEARCH_URL = "https://www.tiktok.com/search?q={}"
TELEGRAM_MAX_VIDEO_BYTES = 20 * 1024 * 1024
MAX_PROCESS_SECONDS = 180
DAILY_UPLOAD_LIMIT = 5
# Optional HTTPS hosts that may serve user-owned/licensed direct video files.
# Example Render Environment value: media.example.com,cdn.example.com
MEDIA_URL_ALLOWED_HOSTS = {
    item.strip().lower().lstrip(".")
    for item in os.getenv("MEDIA_URL_ALLOWED_HOSTS", "").split(",")
    if item.strip()
}


def telegram_main_keyboard():
    return {
        "keyboard": [
            [{"text": "🔎 Найти видео"}, {"text": "🔥 TikTok тренды"}],
            [{"text": "✨ Обработать видео"}, {"text": "🚀 Опубликовать видео"}],
            [{"text": "📁 Мои файлы"}, {"text": "📊 Статистика"}],
            [{"text": "👤 Мои аккаунты"}, {"text": "📱 Наше приложение"}],
            [{"text": "💳 Монетизация"}],
        ],
        "resize_keyboard": True,
        "is_persistent": True,
    }


def telegram_accounts_keyboard():
    return {
        "keyboard": [
            [{"text": "➕ Добавить аккаунт"}, {"text": "👁 Мои аккаунты"}],
            [{"text": "TikTok"}],
            [{"text": "Instagram"}, {"text": "YouTube"}],
            [{"text": "⬅️ Главное меню"}],
        ],
        "resize_keyboard": True,
        "is_persistent": True,
    }


async def telegram_api(method, payload=None):
    if not TELEGRAM_BOT_TOKEN:
        return None
    async with httpx.AsyncClient(timeout=40) as client:
        response = await client.post(
            f"{TG_API.format(TELEGRAM_BOT_TOKEN)}/{method}",
            json=payload or {},
        )
    try:
        result = response.json()
    except Exception:
        result = {"ok": False, "description": "Telegram returned an unreadable response"}
    if response.status_code != 200 or not result.get("ok"):
        raise RuntimeError(result.get("description", "Telegram API error"))
    return result.get("result")


async def telegram_send_message(chat_id, text, reply_markup=None):
    if not TELEGRAM_BOT_TOKEN:
        return
    payload = {"chat_id": chat_id, "text": str(text), "disable_web_page_preview": True}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    await telegram_api("sendMessage", payload)


async def telegram_send_video_bytes(chat_id, video_bytes, caption=None):
    if not TELEGRAM_BOT_TOKEN:
        raise RuntimeError("Telegram bot is not configured")
    if len(video_bytes) > TELEGRAM_MAX_VIDEO_BYTES:
        raise RuntimeError("Готовый файл больше 20 МБ. Отправьте более короткое или компактное видео.")
    data = {"chat_id": str(chat_id)}
    if caption:
        data["caption"] = caption[:900]
    async with httpx.AsyncClient(timeout=180) as client:
        response = await client.post(
            f"{TG_API.format(TELEGRAM_BOT_TOKEN)}/sendVideo",
            data=data,
            files={"video": ("coveyai_processed.mp4", video_bytes, "video/mp4")},
        )
    try:
        result = response.json()
    except Exception:
        raise RuntimeError("Telegram вернул нечитаемый ответ при отправке готового видео")
    if response.status_code != 200 or not result.get("ok"):
        raise RuntimeError(result.get("description", "Не удалось отправить готовое видео в Telegram"))
    return result.get("result") or {}


def set_search_waiting(chat_id, waiting):
    with db_connect() as db:
        if waiting:
            db.execute(
                "INSERT OR REPLACE INTO telegram_search_sessions (chat_id, waiting_for_query) VALUES (?, 1)",
                (str(chat_id),),
            )
        else:
            db.execute("DELETE FROM telegram_search_sessions WHERE chat_id = ?", (str(chat_id),))


def is_search_waiting(chat_id):
    with db_connect() as db:
        row = db.execute(
            "SELECT waiting_for_query FROM telegram_search_sessions WHERE chat_id = ?",
            (str(chat_id),),
        ).fetchone()
    return bool(row and row["waiting_for_query"])


def set_workflow(chat_id, stage, source_url=None, media_id=None):
    with db_connect() as db:
        db.execute(
            """INSERT OR REPLACE INTO bot_workflows
               (chat_id, stage, source_url, media_id, updated_at)
               VALUES (?, ?, ?, ?, ?)""",
            (str(chat_id), stage, source_url, media_id, int(time.time())),
        )


def get_workflow(chat_id):
    with db_connect() as db:
        return db.execute(
            "SELECT * FROM bot_workflows WHERE chat_id = ?",
            (str(chat_id),),
        ).fetchone()


def clear_workflow(chat_id):
    with db_connect() as db:
        db.execute("DELETE FROM bot_workflows WHERE chat_id = ?", (str(chat_id),))
    set_search_waiting(chat_id, False)


def make_tiktok_search_url(query):
    return TIKTOK_SEARCH_URL.format(quote_plus(query.strip()))


async def send_tiktok_search(chat_id, query):
    query = (query or "").strip()[:100]
    if not query:
        await telegram_send_message(chat_id, "Напишите тему для поиска, например: футбол или машины.", telegram_main_keyboard())
        return
    search_url = make_tiktok_search_url(query)
    set_workflow(chat_id, "waiting_tiktok_link")
    await telegram_send_message(
        chat_id,
        f"🔎 Поиск TikTok по запросу: {query}\n\n"
        f"Откройте результаты поиска и выберите понравившийся ролик:\n{search_url}\n\n"
        "Затем отправьте сюда ссылку на конкретный ролик. После этого бот попросит загрузить ваш исходный видеофайл или материал, на который у вас есть разрешение. По одной ссылке бот не скачивает чужое видео.",
        telegram_main_keyboard(),
    )


def is_tiktok_video_url(value):
    """Accept TikTok post URLs and TikTok short links; do not fetch the URL."""
    try:
        parsed = urlparse(value.strip())
        host = (parsed.hostname or "").lower()
        allowed = (
            host == "tiktok.com"
            or host.endswith(".tiktok.com")
        )
        if parsed.scheme not in ("http", "https") or not allowed:
            return False
        path = parsed.path.lower()
        return ("/video/" in path) or host in {"vm.tiktok.com", "vt.tiktok.com"}
    except Exception:
        return False


def is_allowed_media_url(value):
    """Accept only HTTPS direct video URLs hosted on explicitly allowlisted domains."""
    try:
        parsed = urlparse(value.strip())
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.scheme != "https" or not host or parsed.username or parsed.password:
            return False
        if parsed.port not in (None, 443):
            return False
        if not any(host == allowed or host.endswith("." + allowed)
                   for allowed in MEDIA_URL_ALLOWED_HOSTS):
            return False
        path = parsed.path.lower()
        return path.endswith((".mp4", ".mov", ".webm"))
    except (ValueError, TypeError):
        return False


async def download_authorized_media_url(url):
    """Download a direct video file from a user-configured trusted HTTPS host."""
    if not is_allowed_media_url(url):
        raise RuntimeError(
            "Эта ссылка не является прямой ссылкой MP4/MOV/WEBM с разрешённого домена. "
            "TikTok-ссылка подходит для выбора ролика, но не является исходным файлом."
        )

    chunks = []
    total = 0
    async with httpx.AsyncClient(timeout=90, follow_redirects=False) as client:
        async with client.stream("GET", url, headers={"User-Agent": "CoveyAI/1.0"}) as response:
            if response.status_code in (301, 302, 303, 307, 308):
                raise RuntimeError(
                    "Хранилище перенаправило ссылку. Добавьте конечный HTTPS-домен в "
                    "MEDIA_URL_ALLOWED_HOSTS и отправьте прямую ссылку на MP4."
                )
            if response.status_code != 200:
                raise RuntimeError(f"Не удалось получить видео по ссылке (HTTP {response.status_code}).")
            content_type = response.headers.get("content-type", "").split(";", 1)[0].lower()
            if not (content_type.startswith("video/") or content_type == "application/octet-stream"):
                raise RuntimeError("Ссылка открывает не видеофайл. Нужен прямой MP4, MOV или WEBM.")
            declared_size = response.headers.get("content-length")
            if declared_size and declared_size.isdigit() and int(declared_size) > TELEGRAM_MAX_VIDEO_BYTES:
                raise RuntimeError("Видео по ссылке больше 20 МБ. Для текущей версии нужен файл до 20 МБ.")
            async for chunk in response.aiter_bytes(1024 * 256):
                total += len(chunk)
                if total > TELEGRAM_MAX_VIDEO_BYTES:
                    raise RuntimeError("Видео по ссылке больше 20 МБ. Для текущей версии нужен файл до 20 МБ.")
                chunks.append(chunk)

    content = b"".join(chunks)
    if not content:
        raise RuntimeError("По ссылке получен пустой файл.")
    return content


async def save_media_from_direct_url(chat_id, url):
    """Fetch an allowlisted direct media URL, send it to Telegram, and store its file_id."""
    await telegram_send_message(chat_id, "⏳ Получаю видео по прямой ссылке…")
    video_bytes = await download_authorized_media_url(url)
    workflow = get_workflow(chat_id)
    source_url = workflow["source_url"] if workflow else url
    sent = await telegram_send_video_bytes(
        chat_id,
        video_bytes,
        "✅ Видео по ссылке получено. Проверьте, что это ваш ролик или материал с разрешением. Теперь нажмите «✨ Обработать видео»."
    )
    sent_video = sent.get("video") or sent.get("document") or {}
    file_id = sent_video.get("file_id")
    if not file_id:
        raise RuntimeError("Telegram не вернул file_id полученного видео.")
    media_id = save_media_file(chat_id, file_id, len(video_bytes), source_url=source_url)
    await telegram_send_message(
        chat_id,
        f"✅ Исходный файл сохранён в «📁 Мои файлы» под номером #{media_id}. Нажмите «✨ Обработать видео»."
    )


def get_media(chat_id, media_id):
    with db_connect() as db:
        return db.execute(
            "SELECT * FROM media_files WHERE id = ? AND chat_id = ?",
            (int(media_id), str(chat_id)),
        ).fetchone()


def get_latest_media(chat_id, needs_processing=False):
    query = "SELECT * FROM media_files WHERE chat_id = ?"
    args = [str(chat_id)]
    if needs_processing:
        query += " AND processed_file_id IS NULL"
    query += " ORDER BY id DESC LIMIT 1"
    with db_connect() as db:
        return db.execute(query, args).fetchone()


def save_media_file(chat_id, file_id, file_size, source_url=None):
    now = int(time.time())
    with db_connect() as db:
        cursor = db.execute(
            """INSERT INTO media_files
               (chat_id, source_url, original_file_id, original_size, status, created_at)
               VALUES (?, ?, ?, ?, 'uploaded', ?)""",
            (str(chat_id), source_url, file_id, int(file_size or 0), now),
        )
        media_id = cursor.lastrowid
    set_workflow(chat_id, "ready_process", source_url=source_url, media_id=media_id)
    return media_id


async def telegram_set_webhook():
    if not TELEGRAM_BOT_TOKEN:
        return
    try:
        await telegram_api("setWebhook", {
            "url": PUBLIC_BASE_URL + TELEGRAM_WEBHOOK_PATH,
            "allowed_updates": ["message"],
            "drop_pending_updates": False,
        })
    except Exception as exc:
        print(f"Telegram webhook setup failed: {exc}")


@app.on_event("startup")
async def configure_telegram_webhook():
    await telegram_set_webhook()


@app.get("/telegram/status")
async def telegram_status():
    return {
        "configured": bool(TELEGRAM_BOT_TOKEN),
        "webhook_url": PUBLIC_BASE_URL + TELEGRAM_WEBHOOK_PATH if TELEGRAM_BOT_TOKEN else None,
    }


def get_telegram_open_id(chat_id):
    with db_connect() as db:
        row = db.execute(
            "SELECT open_id FROM telegram_accounts WHERE chat_id = ?",
            (str(chat_id),),
        ).fetchone()
    return row["open_id"] if row else None


async def telegram_start_tiktok_link(chat_id):
    state = secrets.token_urlsafe(32)
    with db_connect() as db:
        db.execute(
            "INSERT INTO pending_tiktok_links (state, chat_id, expires_at) VALUES (?, ?, ?)",
            (state, str(chat_id), int(time.time()) + 600),
        )
    login_url = f"{PUBLIC_BASE_URL}/login?state={state}"
    await telegram_send_message(
        chat_id,
        "Чтобы подключить TikTok, откройте персональную ссылку и подтвердите доступ в TikTok. Ссылка действует 10 минут:\n" + login_url,
        reply_markup=telegram_accounts_keyboard(),
    )


async def telegram_download_file(file_id):
    info = await telegram_api("getFile", {"file_id": file_id})
    file_path = info.get("file_path") if info else None
    if not file_path:
        raise RuntimeError("Telegram не вернул файл")
    file_size = info.get("file_size", 0)
    if file_size and file_size > TELEGRAM_MAX_VIDEO_BYTES:
        raise RuntimeError("Через текущий Telegram Bot API можно скачать видео размером до 20 МБ.")
    url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}"
    async with httpx.AsyncClient(timeout=120) as client:
        response = await client.get(url)
    if response.status_code != 200:
        raise RuntimeError("Не удалось скачать видео из Telegram")
    if len(response.content) > TELEGRAM_MAX_VIDEO_BYTES:
        raise RuntimeError("Видео превышает лимит 20 МБ")
    return response.content


def find_ffmpeg():
    try:
        import imageio_ffmpeg  # provided by requirements.txt
        path = imageio_ffmpeg.get_ffmpeg_exe()
        if path and Path(path).exists():
            return path
    except Exception:
        pass
    return shutil.which("ffmpeg")


def transcode_video(video_bytes):
    """Prepare an owned/licensed clip for TikTok: vertical canvas and MP4 re-encode.

    This deliberately does not remove logos/watermarks or disguise ownership.
    The full frame is preserved and padded rather than cropped.
    """
    ffmpeg = find_ffmpeg()
    if not ffmpeg:
        raise RuntimeError("На сервере не найден FFmpeg. Установите зависимости из нового requirements.txt и выполните Deploy.")

    with tempfile.TemporaryDirectory(prefix="coveyai_") as temp_dir:
        input_path = Path(temp_dir) / "input_video"
        output_path = Path(temp_dir) / "processed.mp4"
        input_path.write_bytes(video_bytes)

        base_args = [
            ffmpeg, "-hide_banner", "-loglevel", "error", "-y",
            "-i", str(input_path),
            "-map", "0:v:0", "-map", "0:a?",
            "-vf", "scale=720:1280:force_original_aspect_ratio=decrease,pad=720:1280:(ow-iw)/2:(oh-ih)/2:color=black,setsar=1,fps=30,eq=contrast=1.03:saturation=1.04",
            "-c:v", "libx264", "-preset", "veryfast",
            "-pix_fmt", "yuv420p", "-c:a", "aac", "-b:a", "96k",
            "-movflags", "+faststart", "-threads", "2", str(output_path),
        ]

        # First pass. If the output is too large for Telegram, reduce bitrate once.
        first = base_args[:-1] + ["-b:v", "1400k", "-maxrate", "1400k", "-bufsize", "2800k", base_args[-1]]
        result = subprocess.run(first, capture_output=True, text=True, timeout=240)
        if result.returncode != 0:
            detail = (result.stderr or "FFmpeg failed")[-900:]
            raise RuntimeError("Не удалось обработать видео. Проверьте, что файл действительно является видео MP4/MOV/WEBM. " + detail)

        if not output_path.exists():
            raise RuntimeError("FFmpeg не создал готовый файл")
        if output_path.stat().st_size > TELEGRAM_MAX_VIDEO_BYTES:
            output_path.unlink(missing_ok=True)
            second = base_args[:-1] + ["-b:v", "850k", "-maxrate", "850k", "-bufsize", "1700k", "-b:a", "64k", base_args[-1]]
            result = subprocess.run(second, capture_output=True, text=True, timeout=240)
            if result.returncode != 0 or not output_path.exists():
                raise RuntimeError("Не удалось сжать видео до лимита Telegram")

        processed = output_path.read_bytes()
        if not processed or len(processed) > TELEGRAM_MAX_VIDEO_BYTES:
            raise RuntimeError("Готовое видео превышает 20 МБ. Попробуйте более короткий исходный файл.")
        return processed


async def process_latest_video(chat_id):
    workflow = get_workflow(chat_id)
    media = None
    if workflow and workflow["media_id"]:
        media = get_media(chat_id, workflow["media_id"])
    if not media or media["processed_file_id"]:
        media = get_latest_media(chat_id, needs_processing=True)
    if not media:
        latest = get_latest_media(chat_id)
        if latest and latest["processed_file_id"]:
            await telegram_send_message(chat_id, "Последнее видео уже обработано. Нажмите «🚀 Опубликовать видео» или отправьте новое видео.", telegram_main_keyboard())
        else:
            previous_source = workflow["source_url"] if workflow else None
            set_workflow(chat_id, "waiting_video_file", source_url=previous_source)
            await telegram_send_message(
                chat_id,
                "Сначала отправьте сюда исходный видеофайл MP4, MOV или WEBM размером до 20 МБ. Используйте своё видео или материал, на который у вас есть разрешение. Затем нажмите «✨ Обработать видео».",
                telegram_main_keyboard(),
            )
        return

    await telegram_send_message(chat_id, "⏳ Готовлю видео: привожу к вертикальному формату 9:16, сохраняю весь кадр и перекодирую в MP4…")
    try:
        original = await telegram_download_file(media["original_file_id"])
        processed = await asyncio.to_thread(transcode_video, original)
        sent = await telegram_send_video_bytes(
            chat_id,
            processed,
            "✅ Готово! Это подготовленная версия вашего видео. Проверьте результат перед публикацией.",
        )
        sent_video = sent.get("video") or sent.get("document") or {}
        processed_file_id = sent_video.get("file_id")
        if not processed_file_id:
            raise RuntimeError("Telegram не вернул file_id обработанного видео")
        with db_connect() as db:
            db.execute(
                "UPDATE media_files SET processed_file_id = ?, status = 'processed', processed_at = ? WHERE id = ? AND chat_id = ?",
                (processed_file_id, int(time.time()), media["id"], str(chat_id)),
            )
        set_workflow(chat_id, "ready_publish", source_url=media["source_url"], media_id=media["id"])
        await telegram_send_message(
            chat_id,
            "Следующий шаг: посмотрите готовый ролик выше. Если всё устраивает, нажмите «🚀 Опубликовать видео». Файл также сохранён в «📁 Мои файлы».",
            telegram_main_keyboard(),
        )
    except Exception as exc:
        print(f"Video processing error for chat {chat_id}: {exc}")
        await telegram_send_message(chat_id, "Не удалось обработать видео: " + str(exc), telegram_main_keyboard())


async def publish_latest_processed_video(chat_id, announce=True):
    open_id = get_telegram_open_id(chat_id)
    if not open_id:
        await telegram_send_message(chat_id, "Сначала подключите TikTok: «👤 Мои аккаунты» → «➕ Добавить аккаунт» → «TikTok».", telegram_main_keyboard())
        return

    with db_connect() as db:
        media = db.execute(
            "SELECT * FROM media_files WHERE chat_id = ? AND processed_file_id IS NOT NULL AND published_at IS NULL ORDER BY id DESC LIMIT 1",
            (str(chat_id),),
        ).fetchone()
        today_start = int(time.time()) - (int(time.time()) % 86400)
        today_count = db.execute(
            "SELECT COUNT(*) AS n FROM telegram_uploads WHERE chat_id = ? AND created_at >= ?",
            (str(chat_id), today_start),
        ).fetchone()["n"]

    if not media:
        latest = get_latest_media(chat_id)
        if latest and not latest["processed_file_id"]:
            await telegram_send_message(chat_id, "Сначала нажмите «✨ Обработать видео», чтобы подготовить последний загруженный ролик.", telegram_main_keyboard())
        else:
            await telegram_send_message(chat_id, "Пока нет готового видео. Сначала отправьте исходный ролик, затем нажмите «✨ Обработать видео».", telegram_main_keyboard())
        return
    if today_count >= DAILY_UPLOAD_LIMIT:
        await telegram_send_message(chat_id, f"На сегодня достигнут лимит — {DAILY_UPLOAD_LIMIT} отправок в TikTok Inbox. Попробуйте завтра.", telegram_main_keyboard())
        return

    # Reserve the selected item so repeated taps/webhook retries cannot send it twice.
    with db_connect() as db:
        reserved = db.execute(
            "UPDATE media_files SET status = 'publishing' WHERE id = ? AND chat_id = ? AND published_at IS NULL AND status != 'publishing'",
            (media["id"], str(chat_id)),
        ).rowcount
    if not reserved:
        await telegram_send_message(chat_id, "⏳ Это видео уже отправляется или уже было передано в TikTok Inbox.", telegram_main_keyboard())
        return

    try:
        if announce:
            await telegram_send_message(chat_id, "⏳ Отправляю подготовленное видео в TikTok Inbox…")
        content = await telegram_download_file(media["processed_file_id"])
        publish_id = await upload_video_bytes(open_id, content, "video/mp4")
        now = int(time.time())
        with db_connect() as db:
            db.execute(
                "INSERT INTO telegram_uploads (chat_id, created_at, publish_id) VALUES (?, ?, ?)",
                (str(chat_id), now, publish_id),
            )
            db.execute(
                "UPDATE media_files SET status = 'sent_to_inbox', published_at = ?, publish_id = ? WHERE id = ? AND chat_id = ?",
                (now, publish_id, media["id"], str(chat_id)),
            )
        set_workflow(chat_id, "done", source_url=media["source_url"], media_id=media["id"])
        await telegram_send_message(
            chat_id,
            "✅ Видео передано в TikTok Inbox. Откройте TikTok, найдите уведомление, проверьте подпись и завершите публикацию в приложении. Это ещё не означает, что ролик уже опубликован в профиле.",
            telegram_main_keyboard(),
        )
    except HTTPException as exc:
        with db_connect() as db:
            db.execute("UPDATE media_files SET status = 'processed' WHERE id = ? AND chat_id = ? AND published_at IS NULL", (media["id"], str(chat_id)))
        await telegram_send_message(chat_id, "TikTok не принял видео: " + str(exc.detail) + "\nМожно проверить подключение и повторить отправку.", telegram_main_keyboard())
    except Exception as exc:
        with db_connect() as db:
            db.execute("UPDATE media_files SET status = 'processed' WHERE id = ? AND chat_id = ? AND published_at IS NULL", (media["id"], str(chat_id)))
        print(f"TikTok publish upload error for chat {chat_id}: {exc}")
        await telegram_send_message(chat_id, "Не удалось передать видео в TikTok Inbox: " + str(exc) + "\nМожно проверить подключение и повторить отправку.", telegram_main_keyboard())


async def show_my_files(chat_id):
    with db_connect() as db:
        rows = db.execute(
            "SELECT id, source_url, status, created_at FROM media_files WHERE chat_id = ? ORDER BY id DESC LIMIT 10",
            (str(chat_id),),
        ).fetchall()
    if not rows:
        await telegram_send_message(chat_id, "📁 Пока нет сохранённых видео. Нажмите «🔎 Найти видео», выберите ролик и отправьте сюда свой исходный файл с разрешением на использование.", telegram_main_keyboard())
        return
    status_names = {
        "uploaded": "загружено, ожидает обработки",
        "processed": "обработано, готово к проверке",
        "sent_to_inbox": "передано в TikTok Inbox",
    }
    lines = ["📁 Ваши последние видео:"]
    for row in rows:
        stamp = time.strftime("%d.%m.%Y %H:%M", time.localtime(row["created_at"]))
        lines.append(f"\n#{row['id']} · {stamp}\nСтатус: {status_names.get(row['status'], row['status'])}")
        if row["source_url"]:
            lines.append("Ссылка: " + row["source_url"][:250])
    lines.append("\nВидео хранятся в Telegram, а CoveyAI сохраняет их file_id и статус в своей базе данных.")
    await telegram_send_message(chat_id, "\n".join(lines), telegram_main_keyboard())


async def show_stats(chat_id):
    since = int(time.time()) - (int(time.time()) % 86400)
    with db_connect() as db:
        total_files = db.execute("SELECT COUNT(*) AS n FROM media_files WHERE chat_id = ?", (str(chat_id),)).fetchone()["n"]
        processed = db.execute("SELECT COUNT(*) AS n FROM media_files WHERE chat_id = ? AND processed_file_id IS NOT NULL", (str(chat_id),)).fetchone()["n"]
        sent_total = db.execute("SELECT COUNT(*) AS n FROM telegram_uploads WHERE chat_id = ?", (str(chat_id),)).fetchone()["n"]
        sent_today = db.execute("SELECT COUNT(*) AS n FROM telegram_uploads WHERE chat_id = ? AND created_at >= ?", (str(chat_id), since)).fetchone()["n"]
    await telegram_send_message(
        chat_id,
        f"📊 Статистика CoveyAI\nСохранено видео: {total_files}\nОбработано видео: {processed}\nОтправлено в TikTok Inbox всего: {sent_total}\nСегодня отправлено: {sent_today}/{DAILY_UPLOAD_LIMIT}",
        telegram_main_keyboard(),
    )


async def handle_uploaded_video(message, chat_id):
    video = message.get("video")
    document = message.get("document")
    file_id = None
    file_size = 0
    mime_type = "video/mp4"
    if video:
        file_id = video.get("file_id")
        file_size = video.get("file_size", 0)
        mime_type = video.get("mime_type") or "video/mp4"
    elif document and (document.get("mime_type") or "").startswith("video/"):
        file_id = document.get("file_id")
        file_size = document.get("file_size", 0)
        mime_type = document.get("mime_type")

    if not file_id:
        return False
    if mime_type not in {"video/mp4", "video/quicktime", "video/webm", "video/x-matroska"}:
        await telegram_send_message(chat_id, "Поддерживаются видео MP4, MOV или WEBM. Отправьте видео как файл, если Telegram не распознал его.", telegram_main_keyboard())
        return True
    if file_size and file_size > TELEGRAM_MAX_VIDEO_BYTES:
        await telegram_send_message(chat_id, "Файл больше 20 МБ. Для этой версии бота нужен ролик до 20 МБ.", telegram_main_keyboard())
        return True

    workflow = get_workflow(chat_id)
    source_url = workflow["source_url"] if workflow else None
    media_id = save_media_file(chat_id, file_id, file_size, source_url=source_url)
    await telegram_send_message(
        chat_id,
        f"✅ Видео сохранено в «Мои файлы» под номером #{media_id}.\n\nКогда будете готовы, нажмите «✨ Обработать видео». Используйте только собственные ролики или материалы, на которые у вас есть разрешение.",
        telegram_main_keyboard(),
    )
    return True


async def handle_telegram_message(message):
    chat = message.get("chat", {})
    chat_id = chat.get("id")
    if not chat_id:
        return
    text_value = (message.get("text") or "").strip()

    # Video uploads are stored first. They are never published automatically.
    if await handle_uploaded_video(message, chat_id):
        return

    if text_value in ("/start", "/menu", "⬅️ Главное меню"):
        clear_workflow(chat_id)
        await telegram_send_message(chat_id, "Добро пожаловать в CoveyAI! Выберите действие в меню.", telegram_main_keyboard())
        return

    if text_value in ("/cancel", "❌ Отмена", "Отмена"):
        clear_workflow(chat_id)
        await telegram_send_message(chat_id, "Текущий шаг отменён. Загруженные видео не удалены.", telegram_main_keyboard())
        return

    if text_value.startswith("/search"):
        query = text_value[len("/search"):].strip()
        if query:
            await send_tiktok_search(chat_id, query)
        else:
            set_search_waiting(chat_id, True)
            set_workflow(chat_id, "waiting_search_query")
            await telegram_send_message(chat_id, "🔎 Напишите тему для поиска в TikTok. Например: футбол, машины, животные.\n\nДля отмены отправьте /cancel.", telegram_main_keyboard())
        return

    workflow = get_workflow(chat_id)
    stage = workflow["stage"] if workflow else None

    if text_value == "🔎 Найти видео":
        set_search_waiting(chat_id, True)
        set_workflow(chat_id, "waiting_search_query")
        await telegram_send_message(chat_id, "🔎 Напишите тему для поиска в TikTok. Например: футбол, машины, животные.\n\nЯ пришлю ссылку на результаты поиска. Для отмены отправьте /cancel.", telegram_main_keyboard())
        return

    if stage == "waiting_search_query" and text_value and not text_value.startswith("/"):
        set_search_waiting(chat_id, False)
        await send_tiktok_search(chat_id, text_value)
        return

    if stage == "waiting_tiktok_link" and text_value:
        if is_tiktok_video_url(text_value):
            set_workflow(chat_id, "waiting_video_file", source_url=text_value)
            await telegram_send_message(
                chat_id,
                "✅ Ссылка на выбранный ролик сохранена.\n\nСама страница TikTok не даёт боту исходный MP4. Для обработки отправьте сюда свой исходный видеофайл ИЛИ прямую HTTPS-ссылку на MP4/MOV/WEBM с домена, добавленного в MEDIA_URL_ALLOWED_HOSTS на Render. Используйте только свои видео или материалы с разрешением. После получения файла нажмите «✨ Обработать видео».",
                telegram_main_keyboard(),
            )
        else:
            await telegram_send_message(chat_id, "Это не похоже на ссылку на отдельный ролик TikTok. Отправьте ссылку вида https://www.tiktok.com/@user/video/123… или короткую vm.tiktok.com ссылку.", telegram_main_keyboard())
        return

    if text_value.startswith("http://") or text_value.startswith("https://"):
        if is_tiktok_video_url(text_value):
            set_workflow(chat_id, "waiting_video_file", source_url=text_value)
            await telegram_send_message(
                chat_id,
                "✅ Ссылка TikTok сохранена как ссылка на выбранный ролик.\n\nЧтобы обработать его по ссылке, отправьте прямой HTTPS-адрес MP4/MOV/WEBM с домена, добавленного в MEDIA_URL_ALLOWED_HOSTS на Render. Обычная ссылка страницы TikTok не является ссылкой на MP4. Также можно отправить свой исходный файл в Telegram. Используйте только свои или разрешённые материалы.",
                telegram_main_keyboard(),
            )
        elif is_allowed_media_url(text_value):
            try:
                await save_media_from_direct_url(chat_id, text_value)
            except Exception as exc:
                print(f"Direct media URL error for chat {chat_id}: {exc}")
                await telegram_send_message(chat_id, "Не удалось получить видео по ссылке: " + str(exc), telegram_main_keyboard())
        else:
            await telegram_send_message(
                chat_id,
                "Я принимаю ссылки на отдельные ролики TikTok как ссылки для выбора, а для загрузки исходника — только прямые HTTPS-ссылки MP4/MOV/WEBM с домена, разрешённого в MEDIA_URL_ALLOWED_HOSTS. Можно также отправить исходный файл в Telegram.",
                telegram_main_keyboard(),
            )
        return

    if text_value == "🔥 TikTok тренды":
        await telegram_send_message(
            chat_id,
            "🔥 TikTok Creative Center — тренды и популярные темы:\n"
            "https://ads.tiktok.com/creative/creativeCenter/trends/video?region=UA&period=7\n\n"
            "Откройте интересующий ролик. CoveyAI не скачивает чужие ролики по ссылке; для обработки загрузите свой исходный файл или разрешённый материал.",
            telegram_main_keyboard(),
        )
        return

    if text_value == "✨ Обработать видео":
        await process_latest_video(chat_id)
        return

    if text_value == "🚀 Опубликовать видео":
        await publish_latest_processed_video(chat_id)
        return

    if text_value == "📁 Мои файлы":
        await show_my_files(chat_id)
        return

    if text_value == "📊 Статистика":
        await show_stats(chat_id)
        return

    if text_value == "💳 Монетизация":
        await telegram_send_message(
            chat_id,
            "💳 Монетизация\nСейчас CoveyAI работает в тестовом бесплатном режиме: до 5 отправок в TikTok Inbox в день. Платёжная система не подключена, подписки и списания не оформляются. Эта кнопка показывает текущий статус, а не принимает оплату.",
            telegram_main_keyboard(),
        )
        return

    if text_value == "👤 Мои аккаунты":
        open_id = get_telegram_open_id(chat_id)
        if open_id:
            await telegram_send_message(chat_id, "✅ TikTok подключён.\nID аккаунта: " + html.escape(open_id) + "\n\nInstagram и YouTube в этой версии ещё не подключены.", telegram_accounts_keyboard())
        else:
            await telegram_send_message(chat_id, "TikTok пока не подключён. Нажмите «➕ Добавить аккаунт» → «TikTok». Instagram и YouTube пока не подключены.", telegram_accounts_keyboard())
        return

    if text_value == "➕ Добавить аккаунт":
        await telegram_send_message(chat_id, "В этой версии доступно подключение TikTok. Выберите TikTok ниже.", telegram_accounts_keyboard())
        return

    if text_value == "TikTok":
        await telegram_start_tiktok_link(chat_id)
        return

    if text_value == "Instagram":
        await telegram_send_message(chat_id, "Instagram пока не подключён в CoveyAI. Эта кнопка сообщает статус; публикация в Instagram ещё не настроена.", telegram_accounts_keyboard())
        return

    if text_value == "YouTube":
        await telegram_send_message(chat_id, "YouTube пока не подключён в CoveyAI. Эта кнопка сообщает статус; публикация в YouTube ещё не настроена.", telegram_accounts_keyboard())
        return

    if text_value == "👁 Мои аккаунты":
        open_id = get_telegram_open_id(chat_id)
        if open_id:
            await telegram_send_message(chat_id, "✅ TikTok подключён.\nID аккаунта: " + html.escape(open_id), telegram_accounts_keyboard())
        else:
            await telegram_send_message(chat_id, "Пока не подключено ни одного аккаунта. Нажмите «➕ Добавить аккаунт» → «TikTok».", telegram_accounts_keyboard())
        return

    if text_value == "📱 Наше приложение":
        await telegram_send_message(chat_id, "🌐 Откройте сайт CoveyAI:\n" + SITE_URL, telegram_main_keyboard())
        return

    if text_value:
        await telegram_send_message(chat_id, "Не распознал команду. Используйте кнопки меню или /cancel, чтобы отменить текущий шаг.", telegram_main_keyboard())
        return

    await telegram_send_message(chat_id, "Выберите действие с помощью кнопок меню.", telegram_main_keyboard())


@app.post(TELEGRAM_WEBHOOK_PATH)
async def telegram_webhook(request: Request, background_tasks: BackgroundTasks):
    if not TELEGRAM_BOT_TOKEN:
        raise HTTPException(503, "Telegram bot is not configured")
    update = await request.json()
    message = update.get("message")
    if message:
        text_value = (message.get("text") or "").strip()
        chat_id = (message.get("chat") or {}).get("id")
        if chat_id and text_value == "✨ Обработать видео":
            # Long FFmpeg jobs run after the webhook acknowledgement; the job itself sends progress messages.
            background_tasks.add_task(process_latest_video, chat_id)
        elif chat_id and text_value == "🚀 Опубликовать видео":
            # TikTok upload runs after the webhook acknowledgement; the job sends start and final messages.
            background_tasks.add_task(publish_latest_processed_video, chat_id, True)
        else:
            await handle_telegram_message(message)
    return {"ok": True}
