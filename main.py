import os
import secrets
import sqlite3
import math
import time
import html
import hashlib
from urllib.parse import quote_plus

import httpx
from fastapi import FastAPI, Request, UploadFile, File, HTTPException
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


def telegram_main_keyboard():
    return {
        "keyboard": [
            [{"text": "🔎 Найти видео"}, {"text": "🔥 TikTok тренды"}],
            [{"text": "✨ Обработать видео"}, {"text": "🚀 Опубликовать видео"}],
            [{"text": "💳 Монетизация"}],
            [{"text": "📁 Мои файлы"}, {"text": "📊 Статистика"}],
            [{"text": "👤 Мои аккаунты"}, {"text": "📱 Наше приложение"}],
        ],
        "resize_keyboard": True,
        "is_persistent": True,
    }


def telegram_accounts_keyboard():
    return {
        "keyboard": [
            [{"text": "➕ Добавить аккаунт"}, {"text": "👁 Мои аккаунты"}],
            [{"text": "TikTok"}, {"text": "Instagram"}],
            [{"text": "YouTube"}, {"text": "⬅️ Главное меню"}],
        ],
        "resize_keyboard": True,
        "is_persistent": True,
    }


async def telegram_api(method, payload=None):
    if not TELEGRAM_BOT_TOKEN:
        return None
    async with httpx.AsyncClient(timeout=30) as client:
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
    payload = {"chat_id": chat_id, "text": text, "disable_web_page_preview": True}
    if reply_markup:
        payload["reply_markup"] = reply_markup
    await telegram_api("sendMessage", payload)


async def telegram_send_video(chat_id, video_url, caption=None):
    if not TELEGRAM_BOT_TOKEN:
        return
    payload = {"chat_id": chat_id, "video": video_url}
    if caption:
        payload["caption"] = caption[:900]
    await telegram_api("sendVideo", payload)


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


def make_tiktok_search_url(query):
    """Create a TikTok search URL for a user-entered topic."""
    safe_query = quote_plus(query.strip())
    return TIKTOK_SEARCH_URL.format(safe_query)


async def send_tiktok_search(chat_id, query):
    query = query.strip()[:100]
    if not query:
        await telegram_send_message(
            chat_id,
            "Напишите тему для поиска. Например: футбол, машины, животные.",
            telegram_main_keyboard(),
        )
        return

    search_url = make_tiktok_search_url(query)
    await telegram_send_message(
        chat_id,
        f"🔎 Поиск TikTok по запросу: {query}\n\n"
        f"Откройте результаты поиска:\n{search_url}\n\n"
        "Это ссылка на поиск внутри TikTok. Бот пока не получает автоматически список роликов и не скачивает их.",
        telegram_main_keyboard(),
    )


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
    if file_size and file_size > TELEGRAM_FILE_LIMIT:
        raise RuntimeError("Через Telegram можно отправить видео размером до 20 МБ. Большие файлы добавим через сайт.")
    url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}"
    async with httpx.AsyncClient(timeout=90) as client:
        response = await client.get(url)
    if response.status_code != 200:
        raise RuntimeError("Не удалось скачать видео из Telegram")
    if len(response.content) > TELEGRAM_FILE_LIMIT:
        raise RuntimeError("Видео превышает лимит Telegram 20 МБ")
    return response.content


async def handle_telegram_message(message):
    chat = message.get("chat", {})
    chat_id = chat.get("id")
    if not chat_id:
        return
    text_value = (message.get("text") or "").strip()

    if text_value in ("/start", "/menu", "⬅️ Главное меню"):
        set_search_waiting(chat_id, False)
        await telegram_send_message(
            chat_id,
            "Добро пожаловать в CoveyAI! Выберите нужный раздел в меню.",
            reply_markup=telegram_main_keyboard(),
        )
        return

    # Direct command: /search football or /search футбол
    if text_value.startswith("/search"):
        query = text_value[len("/search"):].strip()
        set_search_waiting(chat_id, False)
        if query:
            await send_tiktok_search(chat_id, query)
        else:
            set_search_waiting(chat_id, True)
            await telegram_send_message(
                chat_id,
                "🔎 Напишите тему для поиска в TikTok. Например: футбол, машины, животные.",
                telegram_main_keyboard(),
            )
        return

    if text_value == "🔥 TikTok тренды":
        await telegram_send_message(
            chat_id,
            "🔥 TikTok Creative Center — раздел с популярными видео и трендами:\n"
            "https://ads.tiktok.com/creative/creativeCenter/trends/video?region=UA&period=7\n\n"
            "Откройте ролик, чтобы посмотреть тренд. CoveyAI пока не скачивает чужие TikTok-ролики.\n"
            "Для обработки и отправки в TikTok Inbox загрузите своё видео или материал, на который у вас есть разрешение.",
            telegram_main_keyboard(),
        )
        return

    if text_value == "📱 Наше приложение":
        await telegram_send_message(chat_id, "🌐 Откройте сайт CoveyAI:\n" + SITE_URL, telegram_main_keyboard())
        return

    if text_value == "👤 Мои аккаунты":
        await telegram_send_message(chat_id, "Раздел аккаунтов. Здесь можно подключить TikTok и посмотреть подключённые аккаунты.", telegram_accounts_keyboard())
        return

    if text_value == "➕ Добавить аккаунт":
        await telegram_send_message(
            chat_id,
            "Выберите платформу для подключения. Сейчас доступен TikTok.",
            telegram_accounts_keyboard(),
        )
        return

    if text_value == "TikTok":
        await telegram_start_tiktok_link(chat_id)
        return

    if text_value == "👁 Мои аккаунты":
        open_id = get_telegram_open_id(chat_id)
        if open_id:
            await telegram_send_message(chat_id, "✅ TikTok подключён.\nID аккаунта: " + html.escape(open_id), telegram_accounts_keyboard())
        else:
            await telegram_send_message(chat_id, "Пока не подключено ни одного аккаунта. Нажмите «➕ Добавить аккаунт», чтобы подключить TikTok.", telegram_accounts_keyboard())
        return

    if text_value == "🔎 Найти видео":
        set_search_waiting(chat_id, True)
        await telegram_send_message(
            chat_id,
            "🔎 Напишите тему для поиска видео в TikTok. Например: футбол, машины, животные, путешествия.\n\n"
            "Я отправлю ссылку на результаты поиска.",
            telegram_main_keyboard(),
        )
        return

    if text_value == "✨ Обработать видео":
        await telegram_send_message(chat_id, "✨ ИИ-обработка и монтаж — следующий модуль. Он будет редактировать ваши видео, а не обходить авторские права или системы распознавания.", telegram_main_keyboard())
        return

    if text_value == "🚀 Опубликовать видео":
        if not get_telegram_open_id(chat_id):
            await telegram_send_message(chat_id, "Сначала подключите TikTok: «Мои аккаунты» → «Добавить аккаунт».", telegram_main_keyboard())
        else:
            await telegram_send_message(chat_id, "Отправьте сюда видео MP4, MOV или WEBM размером до 20 МБ. Я передам его в ваш TikTok Inbox как загрузку для дальнейшего оформления и публикации.", telegram_main_keyboard())
        return

    if text_value == "💳 Монетизация":
        await telegram_send_message(chat_id, "💳 Раздел подписок и оплаты готовится. Сейчас платные списания не подключены, поэтому ничего оплачивать не нужно.", telegram_main_keyboard())
        return

    if text_value == "📁 Мои файлы":
        await telegram_send_message(chat_id, "📁 Хранилище файлов — следующий модуль. Пока файлы не сохраняются в личной библиотеке бота.", telegram_main_keyboard())
        return

    if text_value == "📊 Статистика":
        since = int(time.time()) - (int(time.time()) % 86400)
        with db_connect() as db:
            total = db.execute("SELECT COUNT(*) AS n FROM telegram_uploads WHERE chat_id = ?", (str(chat_id),)).fetchone()["n"]
            today = db.execute("SELECT COUNT(*) AS n FROM telegram_uploads WHERE chat_id = ? AND created_at >= ?", (str(chat_id), since)).fetchone()["n"]
        await telegram_send_message(chat_id, f"📊 Ваша статистика\nУспешных отправок всего: {total}\nСегодня: {today}\nДневной лимит на старте: 5 видео.", telegram_main_keyboard())
        return

    # Accept an uploaded Telegram video/document and send it to the linked TikTok inbox.
    video = message.get("video")
    document = message.get("document")
    file_id = None
    content_type = None
    file_size = 0
    if video:
        file_id = video.get("file_id")
        content_type = video.get("mime_type") or "video/mp4"
        file_size = video.get("file_size", 0)
    elif document and (document.get("mime_type") or "").startswith("video/"):
        file_id = document.get("file_id")
        content_type = document.get("mime_type")
        file_size = document.get("file_size", 0)

    if file_id:
        open_id = get_telegram_open_id(chat_id)
        if not open_id:
            await telegram_send_message(chat_id, "Сначала подключите TikTok через «Мои аккаунты» → «Добавить аккаунт».", telegram_main_keyboard())
            return
        if file_size and file_size > TELEGRAM_FILE_LIMIT:
            await telegram_send_message(chat_id, "Файл больше 20 МБ. Пока Telegram не позволяет боту скачать такой файл. Загрузку больших видео через сайт добавим отдельно.", telegram_main_keyboard())
            return
        with db_connect() as db:
            today_count = db.execute(
                "SELECT COUNT(*) AS n FROM telegram_uploads WHERE chat_id = ? AND created_at >= ?",
                (str(chat_id), int(time.time()) - (int(time.time()) % 86400)),
            ).fetchone()["n"]
        if today_count >= 5:
            await telegram_send_message(chat_id, "На сегодня достигнут стартовый лимит — 5 видео. Попробуйте завтра.", telegram_main_keyboard())
            return
        try:
            await telegram_send_message(chat_id, "⏳ Получаю видео и отправляю его в TikTok Inbox…")
            content = await telegram_download_file(file_id)
            publish_id = await upload_video_bytes(open_id, content, content_type)
            with db_connect() as db:
                db.execute(
                    "INSERT INTO telegram_uploads (chat_id, created_at, publish_id) VALUES (?, ?, ?)",
                    (str(chat_id), int(time.time()), publish_id),
                )
            await telegram_send_message(chat_id, "✅ Видео передано в TikTok Inbox. Откройте TikTok, найдите уведомление и завершите оформление и публикацию там.", telegram_main_keyboard())
        except HTTPException as exc:
            await telegram_send_message(chat_id, "Не удалось отправить видео в TikTok: " + str(exc.detail), telegram_main_keyboard())
        except Exception as exc:
            print(f"Telegram video upload error: {exc}")
            await telegram_send_message(chat_id, "Не удалось обработать файл. Проверьте формат MP4, MOV или WEBM и попробуйте ещё раз.", telegram_main_keyboard())
        return

    # A topic entered after pressing the search button becomes a TikTok search link.
    if text_value and is_search_waiting(chat_id) and not text_value.startswith("/"):
        set_search_waiting(chat_id, False)
        await send_tiktok_search(chat_id, text_value)
        return

    if text_value in ("Instagram", "YouTube"):
        await telegram_send_message(chat_id, f"{text_value} пока не подключён. Сейчас работает только TikTok; остальные платформы добавим позже.", telegram_accounts_keyboard())
        return

    await telegram_send_message(chat_id, "Выберите раздел с помощью кнопок меню.", telegram_main_keyboard())


@app.post(TELEGRAM_WEBHOOK_PATH)
async def telegram_webhook(request: Request):
    if not TELEGRAM_BOT_TOKEN:
        raise HTTPException(503, "Telegram bot is not configured")
    update = await request.json()
    message = update.get("message")
    if message:
        await handle_telegram_message(message)
    return {"ok": True}
