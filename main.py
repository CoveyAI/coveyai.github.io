
import os
import secrets
from urllib.parse import urlencode

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse, HTMLResponse

app = FastAPI()

CLIENT_KEY = os.getenv("TIKTOK_CLIENT_KEY")
REDIRECT_URI = os.getenv("TIKTOK_REDIRECT_URI")

@app.get("/")
def home():
    return HTMLResponse("""
    <h1>CoveyAI</h1>
    <p>TikTok connection service</p>
    <a href="/login">Connect TikTok</a>
    """)

@app.get("/login")
def login(request: Request):
    if not CLIENT_KEY or not REDIRECT_URI:
        return HTMLResponse("Server configuration is incomplete", status_code=500)

    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    params = {
        "client_key": CLIENT_KEY,
        "response_type": "code",
        "scope": "user.info.basic,video.upload",
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    return RedirectResponse(
        "https://www.tiktok.com/v2/auth/authorize/?" + urlencode(params)
    )
