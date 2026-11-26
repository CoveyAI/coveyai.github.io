
import os
import secrets
from urllib.parse import urlencode

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.middleware.sessions import SessionMiddleware

app = FastAPI()

app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ["SESSION_SECRET"],
    https_only=True,
    same_site="lax",
)

CLIENT_KEY = os.environ["TIKTOK_CLIENT_KEY"].strip()
CLIENT_SECRET = os.environ["TIKTOK_CLIENT_SECRET"]
REDIRECT_URI = os.environ["TIKTOK_REDIRECT_URI"]

@app.get("/")
def home():
    return HTMLResponse("""
    <h1>CoveyAI</h1>
    <p>TikTok connection test</p>
    <a href="/login">Connect TikTok</a>
    """)

@app.get("/login")
def login(request: Request):
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state

    params = {
        "client_key": CLIENT_KEY,
        "response_type": "code",
        "scope": "user.info.basic",
        "redirect_uri": REDIRECT_URI,
        "state": state,
    }

    url = "https://www.tiktok.com/v2/auth/authorize/?" + urlencode(params)
    return RedirectResponse(url)

@app.get("/callback")
async def callback(request: Request):
    error = request.query_params.get("error")
    if error:
        return HTMLResponse("TikTok authorization was not completed.")

    code = request.query_params.get("code")
    state = request.query_params.get("state")
    saved_state = request.session.pop("oauth_state", None)

    if not code or not state or state != saved_state:
        return HTMLResponse("Authorization check failed.", status_code=400)

    data = {
        "client_key": CLIENT_KEY,
        "client_secret": CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
    }

    async with httpx.AsyncClient(timeout=20) as client:
        response = await client.post(
            "https://open.tiktokapis.com/v2/oauth/token/",
            data=data,
        )

    if response.status_code != 200:
        return HTMLResponse("TikTok token exchange failed.", status_code=400)

    result = response.json()

    if result.get("error"):
        return HTMLResponse("TikTok returned an authorization error.", status_code=400)

    return HTMLResponse("""
    <h1>CoveyAI</h1>
    <p>TikTok authorization test completed successfully.</p>
    <p>You can close this page.</p>
    """)
