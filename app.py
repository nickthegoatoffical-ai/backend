import base64
import hashlib
import hmac
import json
import os
import re
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
    try:
        r = requests.post(
            f"https://{title_id()}.playfabapi.com{path}",
            json=body,
            headers={"Content-Type": "application/json", "X-SecretKey": playfab_secret()},
            timeout=10,
        )
    except Exception as e:  # network error / bad title id: never crash the endpoint
        return 503, {"errorMessage": "Could not reach PlayFab: " + type(e).__name__}
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

    # Build gate: only let known game builds in. ALLOWED_BUILD_HASHES is a
    # comma-separated list (e.g. "v1.0.3-ab12cd,v1.0.4-ef34gh"). Leave it unset
    # to disable. This stops old builds and casual tampering, not skilled cheaters.
    allowed = [h.strip() for h in env("ALLOWED_BUILD_HASHES").split(",") if h.strip()]
    build = str(d.get("BuildHash", ""))[:80]
    if allowed and build not in allowed:
        log_discord("Login rejected: unknown build",
                    {"Build": build or "none", "Device": device,
                     "CustomId": custom_id[:8] + "..."}, YELLOW)
        return jsonify({"Error": "Outdated or modified build. Please update the game."}), 426

    # NOTE: this endpoint no longer talks to PlayFab, so it can never create a
    # "server custom id" player. The real player account is the one the game itself
    # logs into (PlayFabAuthenticator), which is where your cosmetics live. This
    # endpoint only checks the key / build, logs the launch, and hands out a session
    # token. Photon auth uses the game's own PlayFab ticket (see /api/photon/auth).
    display_name = env("DEFAULT_NAME", "AxisApe")
    session = sign_token({"kind": "session", "pid": "", "cid": custom_id,
                          "nm": str(display_name)[:25]}, SESSION_TTL)
    log_discord("Game login OK", {
        "Device": device,
        "Build": build or "n/a",
        "CustomId": custom_id[:6] + "...",
        "Note": "no PlayFab account touched (real ID is logged by Photon auth)",
    }, GREEN)

    return jsonify({
        "status": "success",
        "PlayFabId": "",
        "SessionToken": session,
        "SessionTicket": "",
        "ExpiresIn": SESSION_TTL,
        "Photon": {
            "RealtimeAppId": env("PHOTON_REALTIME_APP_ID"),
            "VoiceAppId": env("PHOTON_VOICE_APP_ID"),
        },
    })


# ----------------------------------------------------------------------------
# Client pings (no login needed, so they work even when login can't)
# ----------------------------------------------------------------------------
def _clean(v, n=60):
    return "".join(ch for ch in str(v) if ch.isprintable())[:n] or "-"


def _client_key_ok(d):
    required = env("CLIENT_KEY")
    return not required or hmac.compare_digest(str(d.get("ClientKey", "")), required)


@app.route("/api/client/open", methods=["POST"])
def client_open():
    """Game just launched (before login)."""
    d = request.get_json(silent=True) or {}
    if not _client_key_ok(d):
        return jsonify({"Error": "Unauthorized"}), 401
    log_discord("Game opened", {
        "Device": _clean(d.get("Device")),
        "Build": _clean(d.get("BuildHash")),
        "Version": _clean(d.get("Version")),
        "OS": _clean(d.get("OS")),
        "Session": _clean(d.get("Session"), 12),
    }, 0x5865F2)
    return jsonify({"status": "ok"})


@app.route("/api/client/report", methods=["POST"])
def client_report():
    """Game hit a connection problem (can't reach backend / Photon)."""
    d = request.get_json(silent=True) or {}
    if not _client_key_ok(d):
        return jsonify({"Error": "Unauthorized"}), 401
    log_discord("Connection problem", {
        "Where": _clean(d.get("Where")),
        "Reason": _clean(d.get("Reason"), 120),
        "Attempt": _clean(d.get("Attempt")),
        "Auto-fix": _clean(d.get("Fix")),
        "Device": _clean(d.get("Device")),
        "Session": _clean(d.get("Session"), 12),
    }, YELLOW)
    return jsonify({"status": "ok"})


@app.route("/api/client/mod-violation", methods=["POST"])
def client_mod_violation():
    """Game auto-disabled a mod (e.g. platforms while untagged in a public lobby)."""
    d = request.get_json(silent=True) or {}
    if not _client_key_ok(d):
        return jsonify({"Error": "Unauthorized"}), 401
    log_discord("Mod auto-disabled", {
        "Player ID": _clean(d.get("UserId"), 64),
        "Username": _clean(d.get("Username"), 40),
        "Device": _clean(d.get("Device"), 80),
        "Mod": _clean(d.get("Mod"), 40),
        "Room": _clean(d.get("Room"), 40),
    }, YELLOW)
    return jsonify({"status": "ok"})


# ----------------------------------------------------------------------------
# Announcements: the admin page posts a message, every running game polls for it.
# Stored in PlayFab title INTERNAL data so it survives between serverless calls.
# ----------------------------------------------------------------------------
ANNOUNCE_KEY = "Announcement"
ANNOUNCE_MAX = 140


@app.after_request
def announce_cors(resp):
    if request.path.startswith("/api/announce"):
        resp.headers["Access-Control-Allow-Origin"] = "*"
        resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Admin-Key"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    return resp


@app.route("/api/announce", methods=["POST", "OPTIONS"])
def announce_post():
    if request.method == "OPTIONS":
        return ("", 204)
    admin_key = env("ADMIN_KEY")
    if not admin_key or not hmac.compare_digest(request.headers.get("X-Admin-Key", ""), admin_key):
        log_discord("Announcement rejected: bad admin key", {}, RED)
        return jsonify({"Error": "Unauthorized"}), 401

    d = request.get_json(silent=True) or {}
    text = str(d.get("text", "")).strip()[:ANNOUNCE_MAX]
    if not text:
        return jsonify({"Error": "Empty message"}), 400

    payload = {"id": secrets.token_hex(4), "text": text, "ts": int(time.time())}
    status, pf = playfab("/Server/SetTitleInternalData",
                         {"Key": ANNOUNCE_KEY, "Value": json.dumps(payload, ensure_ascii=False)})
    if status != 200:
        return jsonify({"Error": "Could not save", "Message": pf.get("errorMessage", "")}), 502
    log_discord("Announcement sent", {"Text": text[:200]}, 0x5865F2)
    return jsonify({"status": "sent", "id": payload["id"]})


@app.route("/api/announce/latest", methods=["GET", "OPTIONS"])
def announce_latest():
    if request.method == "OPTIONS":
        return ("", 204)
    status, pf = playfab("/Server/GetTitleInternalData", {"Keys": [ANNOUNCE_KEY]})
    raw = ((pf.get("data") or {}).get("Data") or {}).get(ANNOUNCE_KEY) if status == 200 else None
    try:
        payload = json.loads(raw) if raw else {"id": "", "text": "", "ts": 0}
    except Exception:
        payload = {"id": "", "text": "", "ts": 0}
    payload["now"] = int(time.time())
    resp = jsonify(payload)
    resp.headers["Cache-Control"] = "public, s-maxage=3, stale-while-revalidate=5"
    return resp


@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


# 3) PHOTON CUSTOM AUTH ------------------------------------------------------
# Set this URL as the Custom Authentication Service in BOTH your Realtime and
# Voice apps in the Photon dashboard. Client sends AuthGetParameters like:
#   "token=<SessionToken>"
# Photon calls us (GET or POST) and expects ResultCode 1 = success.

# Staff ids that must never be trusted from an unverified claim (add more in Vercel: PROTECTED_IDS=ID1,ID2)
_STAFF_IDS = ["88FF99D61F7A1B28", "1A9DADB18D860B07", "1A7678D3987ADE70", "B132B0A47C80E08F",
              "73651B37CC4EDD03", "7548033070FBDEE0", "C0A8B095A070F3D0"]

def protected_ids():
    extra = [x.strip().upper() for x in env("PROTECTED_IDS").split(",") if x.strip()]
    return set(_STAFF_IDS) | set(extra)

@app.route("/api/photon/auth", methods=["GET", "POST"])
def photon_auth():
    # Photon may send the extra data as JSON, as a form, or as plain text, with or without a
    # JSON content-type. Read it every way so the PlayFab ticket is never missed.
    body = request.get_json(force=True, silent=True)
    if not isinstance(body, dict):
        body = {}
        raw = request.get_data(as_text=True) or ""
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                body = parsed
        except Exception:
            pass

    def param(*names):
        for n in names:
            v = request.values.get(n) or body.get(n)
            if v:
                return str(v)
        return ""

    default_name = env("DEFAULT_NAME", "AxisApe")
    token = param("token", "Token")

    # A) a session token that carries a PlayFab identity (older tokens)
    session = verify_token(token, "session") if token else None
    if session and session.get("pid"):
        name = (param("nickname") or session.get("nm") or default_name)[:20]
        log_discord("Photon auth OK", {"In-game name": name, "PlayFabId": session["pid"],
                                       "Method": "session token"}, GREEN)
        return jsonify({"ResultCode": 1, "UserId": session["pid"], "Nickname": name})

    # B) the game's own PlayFab session ticket. Try every value that could hold it.
    candidates = []
    for n in ("ticket", "Ticket", "sessionTicket", "SessionTicket", "token", "Token"):
        v = request.values.get(n) or body.get(n)
        if v and str(v) not in candidates:
            candidates.append(str(v))
    last_err = ""
    for ticket in candidates:
        if verify_token(ticket, "session"):
            continue  # that's our own session token, not a PlayFab ticket
        status, pf = playfab("/Server/AuthenticateSessionTicket", {"SessionTicket": ticket})
        data = pf.get("data") or {}
        info = data.get("UserInfo") or {}
        pid = info.get("PlayFabId")
        if status == 200 and pid and not data.get("IsSessionTicketExpired"):
            claimed = param("username", "userId", "UserId", "playfabid", "PlayFabId")
            if claimed and claimed != pid:
                log_discord("Photon auth: id mismatch (using ticket's real id)",
                            {"Claimed": claimed, "PlayFabId": pid}, YELLOW)
            name = (param("nickname") or (info.get("TitleInfo") or {}).get("DisplayName")
                    or default_name)[:20]
            log_discord("Photon auth OK", {"In-game name": name, "PlayFabId": pid,
                                           "Device": request.headers.get("User-Agent", "unknown")[:80],
                                           "Method": "PlayFab ticket"}, GREEN)
            return jsonify({"ResultCode": 1, "UserId": pid, "Nickname": name})
        last_err = str(pf.get("errorMessage") or pf.get("error") or status)[:120]

    if session and not session.get("pid"):
        why = "only a backend session token was sent (no PlayFab ticket)"
    elif not candidates:
        why = "no token/ticket in the request"
    else:
        why = "PlayFab rejected the ticket: " + last_err

    claimed = param("username", "userId", "UserId", "playfabid", "PlayFabId")
    name = (param("nickname") or default_name)[:20]
    device = request.headers.get("User-Agent", "unknown")[:80]

    # LOG-ONLY MODE (default): never block anyone, just record who connected.
    # Set PHOTON_ENFORCE=1 in Vercel to reject connections without a valid PlayFab ticket again.
    if env("PHOTON_ENFORCE").strip().lower() not in ("1", "true", "yes"):
        # Use the PlayFab id the game says it is as the Photon UserId, so the CloudScript revision sees REAL
        # PlayFab ids in report / ban events (a ban needs a real PlayFab id). Because the claim is unverified:
        #   - it must look like a PlayFab id (14-16 hex chars), and
        #   - staff ids are NEVER accepted this way (so nobody can pretend to be staff by claiming their id).
        # Turn this off with PHOTON_TRUST_CLAIMED=0 in Vercel.
        use_claimed = False
        if env("PHOTON_TRUST_CLAIMED", "1").strip().lower() not in ("0", "false", "no"):
            c = (claimed or "").strip().upper()
            if re.fullmatch(r"[0-9A-F]{14,16}", c) and c not in protected_ids():
                use_claimed = True
        log_discord("Photon auth OK (unverified)", {
            "In-game name": name,
            "PlayFabId (claimed)": claimed or "unknown",
            "Photon UserId set to": (claimed.strip().upper() if use_claimed else "client's own id"),
            "Device": device,
            "Why unverified": why,
        }, YELLOW)
        resp = {"ResultCode": 1, "Nickname": name}
        if use_claimed:
            resp["UserId"] = claimed.strip().upper()
        return jsonify(resp)

    log_discord("Photon auth FAILED", {
        "Why": why,
        "Params sent": ", ".join(sorted(set(request.values.keys()) | set(body.keys())))[:200] or "none",
        "Content-Type": (request.content_type or "none")[:60],
    }, RED)
    return jsonify({"ResultCode": 2, "Message": "bad ticket"})


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
    PlayFabId = session.get("pid", "")

    MetaLog = {
        "CustomId": CustomId[:8] + "...",
        "PlayFabId": PlayFabId or "n/a (game's own PlayFab login is separate)",
        "GameMode": GameMode,
        "Device": DeviceType,
        "Region": Region,
    }
    # No PlayFab calls here: this endpoint must never create or link a player.
    pf = {}
    link = {}

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
