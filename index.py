import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from datetime import datetime, timezone

import requests
from flask import Flask, jsonify, request

app = Flask(__name__)


# ----------------------------------------------------------------------------
# Config (all secrets come from Vercel environment variables, never the code)
# ----------------------------------------------------------------------------
def env(name, default=""):
    return os.environ.get(name, default)


def title_id():
    return env("PLAYFAB_TITLE_ID")


def playfab_secret():
    return env("PLAYFAB_SECRET_KEY")


def token_secret():
    s = env("TOKEN_SECRET")
    if not s:
        raise RuntimeError("TOKEN_SECRET is not set")
    return s


SESSION_TTL = 3600    # session token lifetime (seconds)


# ----------------------------------------------------------------------------
# Stateless signed tokens (Vercel is serverless, so no in-memory sessions)
# ----------------------------------------------------------------------------
def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def sign_token(payload: dict, ttl: int) -> str:
    payload = dict(payload, exp=int(time.time()) + ttl, jti=secrets.token_hex(8))
    body = _b64(json.dumps(payload, separators=(",", ":")).encode())
    sig = _b64(hmac.new(token_secret().encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{sig}"


def verify_token(token, kind):
    try:
        body, sig = token.split(".")
        expected = _b64(hmac.new(token_secret().encode(), body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(sig, expected):
            return None
        payload = json.loads(_unb64(body))
        if payload.get("exp", 0) < time.time() or payload.get("kind") != kind:
            return None
        return payload
    except Exception:
        return None


def bearer_token():
    h = request.headers.get("Authorization", "")
    if h.lower().startswith("bearer "):
        return h[7:].strip()
    return (request.get_json(silent=True) or {}).get("SessionToken", "")


# ----------------------------------------------------------------------------
# Discord logging (never put tokens or keys in here)
# ----------------------------------------------------------------------------
def client_ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?").split(",")[0].strip()


def log_discord(title, fields=None, color=0x5865F2):
    url = env("DISCORD_WEBHOOK_URL")
    if not url:
        return
    fields = dict(fields or {})
    fields.setdefault("IP", client_ip())
    embed = {
        "title": title,
        "color": color,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "fields": [
            {"name": str(k)[:250], "value": (str(v) or "-")[:300], "inline": True}
            for k, v in fields.items()
        ][:20],
    }
    try:
        requests.post(url, json={"embeds": [embed]}, timeout=3)
    except Exception:
        pass  # logging must never break auth


GREEN, RED, YELLOW = 0x57F287, 0xED4245, 0xFEE75C


# ----------------------------------------------------------------------------
# PlayFab helper
# ----------------------------------------------------------------------------
def playfab(path, body):
    r = requests.post(
        f"https://{title_id()}.playfabapi.com{path}",
        json=body,
        headers={"Content-Type": "application/json", "X-SecretKey": playfab_secret()},
        timeout=10,
    )
    try:
        data = r.json()
    except Exception:
        data = {"errorMessage": r.text}
    return r.status_code, data


def parse_ban(data):
    """Pull ban reason/expiration out of a PlayFab 1002 (AccountBanned) error."""
    details = data.get("errorDetails", {}) or {}
    reason = next(iter(details.keys()), "No ban reason provided.")
    exp_list = details.get(reason, [])
    expiration = exp_list[0] if exp_list else "No expiration date provided."
    return reason, expiration


# ----------------------------------------------------------------------------
# Routes
# ----------------------------------------------------------------------------
# 1) AUTH (no Meta / platform credentials needed - works for itch.io builds)
# ----------------------------------------------------------------------------
# The client generates a long random ID once (e.g. Guid.NewGuid() saved in
# PlayerPrefs) and sends it as CustomId. That ID acts as the player's password.
# NOTE: without a store platform (Steam/Meta) there is no way to truly prove a
# request comes from your real game build, so this protects accounts, not
# against modified clients.
import re
CUSTOM_ID_RE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")


@app.route("/api/auth/login", methods=["POST"])
def login():
    d = request.get_json(silent=True) or {}
    custom_id = str(d.get("CustomId", "")).strip()
    device = str(d.get("Device", "Unknown"))[:40]

    # optional shared key so random internet traffic can't create accounts
    required_key = env("CLIENT_KEY")
    if required_key and not hmac.compare_digest(str(d.get("ClientKey", "")), required_key):
        log_discord("Login rejected: bad client key", {"Device": device}, RED)
        return jsonify({"Error": "Unauthorized"}), 401

    if not CUSTOM_ID_RE.match(custom_id):
        log_discord("Login rejected: bad CustomId format", {"Device": device}, RED)
        return jsonify({"Error": "Invalid CustomId (16-128 chars, letters/numbers/_/-)"}), 400

    status, pf = playfab("/Server/LoginWithServerCustomId",
                         {"ServerCustomId": custom_id, "CreateAccount": True})

    if status != 200:
        if status == 403 and pf.get("errorCode") == 1002:
            reason, expiration = parse_ban(pf)
            log_discord("BANNED login attempt",
                        {"CustomId": custom_id[:8] + "...", "Reason": reason, "Expires": expiration}, RED)
            return jsonify({"BanReason": reason, "BanExpiration": expiration}), 403
        log_discord("PlayFab login error",
                    {"CustomId": custom_id[:8] + "...", "Error": pf.get("errorMessage", "unknown")}, RED)
        return jsonify({"Error": "PlayFab login error",
                        "Message": pf.get("errorMessage", "Unknown error")}), status

    result = pf.get("data", {})
    playfab_id = result.get("PlayFabId")

    session = sign_token({"kind": "session", "pid": playfab_id, "cid": custom_id}, SESSION_TTL)
    log_discord("Login OK", {"PlayFabId": playfab_id, "NewAccount": result.get("NewlyCreated"),
                             "Device": device}, GREEN)

    return jsonify({
        "status": "success",
        "PlayFabId": playfab_id,
        "SessionToken": session,
        "SessionTicket": result.get("SessionTicket"),
        "ExpiresIn": SESSION_TTL,
        "Photon": {
            "RealtimeAppId": env("PHOTON_REALTIME_APP_ID"),
            "VoiceAppId": env("PHOTON_VOICE_APP_ID"),
        },
    })


# ----------------------------------------------------------------------------
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# 3) PHOTON CUSTOM AUTH ------------------------------------------------------
# Set this URL as the Custom Authentication Service in BOTH your Realtime and
# Voice apps in the Photon dashboard. Client sends AuthGetParameters like:
#   "token=<SessionToken>"
# Photon calls us (GET or POST) and expects ResultCode 1 = success.
@app.route("/api/photon/auth", methods=["GET", "POST"])
def photon_auth():
    token = request.values.get("token", "")
    if not token and request.is_json:
        token = (request.get_json(silent=True) or {}).get("token", "")

    session = verify_token(token, "session")
    if not session:
        log_discord("Photon auth FAILED", {}, RED)
        return jsonify({"ResultCode": 3, "Message": "Invalid or expired session"})

    log_discord("Photon auth OK", {"PlayFabId": session["pid"]}, GREEN)
    return jsonify({
        "ResultCode": 1,
        "UserId": session["pid"],
        "Nickname": request.values.get("nickname", session["pid"])[:20],
    })


# 4) MOTHERSHIP (your original endpoint, merged + hardened) -------------------
@app.route("/api/CORP/Mothership-Auth", methods=["POST"])
def mothership_auth():
    datp = request.get_json(silent=True) or {}

    session = verify_token(bearer_token(), "session")
    if not session:
        return jsonify({"Error": "Unauthorized", "Message": "Invalid or expired session"}), 401

    GameMode = datp.get("GameMode", "DefaultMode")
    DeviceType = datp.get("Device", "Unknown")
    Region = datp.get("Region", "global")

    # Identity is taken from the verified session, not from the request body.
    CustomId = session["cid"]
    PlayFabId = session["pid"]

    MetaLog = {
        "CustomId": CustomId,
        "PlayFabId": PlayFabId,
        "GameMode": GameMode,
        "Device": DeviceType,
        "Region": Region,
    }

    status, pf = playfab("/Server/LoginWithServerCustomId",
                         {"ServerCustomId": CustomId, "CreateAccount": False})

    if status != 200:
        if status == 403:
            if pf.get("errorCode") == 1002:
                reason, expiration = parse_ban(pf)
                log_discord("[BAN DETECTED] Mothership", MetaLog, RED)
                return jsonify({
                    "BanReason": reason,
                    "BanExpiration": expiration,
                    "Region": Region,
                    "GameMode": GameMode,
                }), 403
            return jsonify({"Error": "Forbidden",
                            "Message": pf.get("errorMessage", "Unknown reason"),
                            "Meta": MetaLog}), 403
        return jsonify({"Error": "PlayFab Login Error",
                        "Message": pf.get("errorMessage", "Unknown error"),
                        "Meta": MetaLog}), status

    # Make sure the server custom id is linked to this account (no ForceLink,
    # so it can never steal a link from another account).
    link_status, link = playfab("/Server/LinkServerCustomId",
                                {"PlayFabId": PlayFabId, "ServerCustomId": CustomId,
                                 "ForceLink": False})
    # Already being linked to this account is fine; anything else is just logged.
    if link_status != 200:
        log_discord("Mothership link note",
                    dict(MetaLog, Info=str(link.get("errorMessage", ""))[:200]), YELLOW)

    services = {
        "CosmeticsSync": True,
        "FriendsInit": True,
        "GuildSync": False,
        "SeasonalEvents": True,
    }

    log_discord("Mothership auth OK", MetaLog, GREEN)

    return jsonify({
        "status": "success",
        "GameMode": GameMode,
        "Region": Region,
        "Device": DeviceType,
        "loginData": pf,
        "linkData": link,
        "servicesInitialized": services,
        "meta": MetaLog,
    })
