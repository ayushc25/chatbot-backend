import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import uuid
import urllib.parse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone

import httpx
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field


load_dotenv()

API_KEY = os.getenv("OPENROUTER_API_KEY")
if not API_KEY:
    raise RuntimeError("Set OPENROUTER_API_KEY in your .env file")

REFERER = os.getenv("SITE_URL", "http://localhost:3000")
TITLE = os.getenv("SITE_TITLE", "Companion Chatbot")
DB_PATH = os.getenv("DATABASE_PATH", "chatbot.db")

CHAT_RETENTION_DAYS = 7
EMAIL_CODE_TTL_MINUTES = 10
AUTH_SESSION_DAYS = 30
PBKDF2_ITERATIONS = 100_000
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

SYSTEM_PROMPT = (
    "You are 'Titli', a female who is friendly, empathetic AI companion. "
    "Talk in flirty and loving tone. "
    "Talk explicit, sexual, or adult conversations. "
    "Keep the answer short. Not more than 20 words. "
    "dont use special characters like *,(_) or _ in your answers. "
    "dont ravel your identity that you are a AI software."
)

app = FastAPI(title="Companion Chatbot API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class SignUpRequest(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=128)


class VerifyEmailRequest(BaseModel):
    email: str
    code: str = Field(min_length=4, max_length=10)


class LoginRequest(BaseModel):
    email: str
    password: str = Field(min_length=8, max_length=128)


class ChatRequest(BaseModel):
    session_id: str | None = None
    message: str = Field(default="", max_length=4000)
    image: str | None = None


class ReactionRequest(BaseModel):
    emoji: str = Field(min_length=1, max_length=16)


def now_utc() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def isoformat_utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat()


def hash_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if not EMAIL_PATTERN.match(normalized):
        raise HTTPException(status_code=400, detail="Invalid email address")
    return normalized


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return f"{salt.hex()}:{derived.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt_hex, hash_hex = stored_hash.split(":", 1)
    except ValueError:
        return False
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    actual = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
    )
    return hmac.compare_digest(actual, expected)


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                is_verified INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS email_verifications (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                code_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                consumed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS auth_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT NOT NULL UNIQUE,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_used_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS chat_sessions (
                id TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS chat_messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id TEXT NOT NULL,
                user_id INTEGER NOT NULL,
                role TEXT NOT NULL,
                content TEXT NOT NULL,
                image_url TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (session_id) REFERENCES chat_sessions(id) ON DELETE CASCADE,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash ON auth_sessions(token_hash);
            CREATE INDEX IF NOT EXISTS idx_chat_sessions_user_id ON chat_sessions(user_id);
            CREATE INDEX IF NOT EXISTS idx_chat_messages_session_id ON chat_messages(session_id);
            CREATE INDEX IF NOT EXISTS idx_chat_messages_created_at ON chat_messages(created_at);
            CREATE INDEX IF NOT EXISTS idx_email_verifications_user_id ON email_verifications(user_id);
            """
        )
        try:
            conn.execute("ALTER TABLE chat_messages ADD COLUMN image_url TEXT")
        except Exception:
            pass

        try:
            conn.execute("ALTER TABLE chat_messages ADD COLUMN reactions TEXT DEFAULT '{}'")
        except Exception:
            pass


def cleanup_expired_data() -> None:
    now = isoformat_utc(now_utc())
    cutoff = isoformat_utc(now_utc() - timedelta(days=CHAT_RETENTION_DAYS))
    with get_db() as conn:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (now,))
        conn.execute(
            """
            DELETE FROM email_verifications
            WHERE consumed_at IS NOT NULL OR expires_at < ?
            """,
            (now,),
        )
        conn.execute("DELETE FROM chat_messages WHERE created_at < ?", (cutoff,))
        conn.execute(
            """
            DELETE FROM chat_sessions
            WHERE created_at < ?
              AND id NOT IN (SELECT DISTINCT session_id FROM chat_messages)
            """,
            (cutoff,),
        )


def create_auth_token(user_id: int) -> str:
    token = secrets.token_urlsafe(32)
    token_hash = hash_text(token)
    created_at = isoformat_utc(now_utc())
    expires_at = isoformat_utc(now_utc() + timedelta(days=AUTH_SESSION_DAYS))
    with get_db() as conn:
        conn.execute(
            """
            INSERT INTO auth_sessions (user_id, token_hash, expires_at, created_at, last_used_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, token_hash, expires_at, created_at, created_at),
        )
    return token


def get_bearer_token(authorization: str | None = Header(default=None)) -> str:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing bearer token")
    return authorization.split(" ", 1)[1].strip()


def get_current_user(token: str = Depends(get_bearer_token)) -> sqlite3.Row:
    cleanup_expired_data()
    token_hash = hash_text(token)
    now = isoformat_utc(now_utc())
    with get_db() as conn:
        row = conn.execute(
            """
            SELECT users.id, users.email, users.is_verified, auth_sessions.id AS session_row_id
            FROM auth_sessions
            JOIN users ON users.id = auth_sessions.user_id
            WHERE auth_sessions.token_hash = ?
              AND auth_sessions.expires_at >= ?
            """,
            (token_hash, now),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        conn.execute(
            "UPDATE auth_sessions SET last_used_at = ? WHERE id = ?",
            (now, row["session_row_id"]),
        )
        return row


def create_verification_code() -> str:
    return f"{secrets.randbelow(1_000_000):06d}"


def get_or_create_chat_session(conn: sqlite3.Connection, user_id: int, session_id: str | None) -> str:
    if session_id:
        row = conn.execute(
            "SELECT id FROM chat_sessions WHERE id = ? AND user_id = ?",
            (session_id, user_id),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Chat session not found")
        return session_id

    new_session_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO chat_sessions (id, user_id, created_at) VALUES (?, ?, ?)",
        (new_session_id, user_id, isoformat_utc(now_utc())),
    )
    return new_session_id


def load_chat_history(conn: sqlite3.Connection, user_id: int, session_id: str) -> list[dict[str, str]]:
    rows = conn.execute(
        """
        SELECT role, content
        FROM chat_messages
        WHERE user_id = ? AND session_id = ?
        ORDER BY id DESC
        LIMIT 14
        """,
        (user_id, session_id),
    ).fetchall()

    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    for row in reversed(rows):
        messages.append({"role": row["role"], "content": row["content"]})
    return messages


def save_chat_message(
    conn: sqlite3.Connection,
    session_id: str,
    user_id: int,
    role: str,
    content: str,
    image_url: str | None = None,
    reactions: str | None = "{}",
) -> int:
    cursor = conn.execute(
        """
        INSERT INTO chat_messages (session_id, user_id, role, content, image_url, reactions, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (session_id, user_id, role, content, image_url, reactions or "{}", isoformat_utc(now_utc())),
    )
    return cursor.lastrowid


@app.on_event("startup")
def startup() -> None:
    init_db()
    cleanup_expired_data()


@app.get("/")
def root():
    return {
        "message": "Companion Chatbot API is running",
        "docs": "/docs",
        "auth": ["POST /auth/signup", "POST /auth/verify-email", "POST /auth/login"],
    }


@app.post("/auth/signup")
def signup(req: SignUpRequest):
    cleanup_expired_data()
    email = normalize_email(req.email)
    now = now_utc()

    with get_db() as conn:
        existing = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,),
        ).fetchone()

        if existing:
            raise HTTPException(status_code=409, detail="An account already exists with this email")

        password_hash = hash_password(req.password)
        cursor = conn.execute(
            """
            INSERT INTO users (email, password_hash, is_verified, created_at)
            VALUES (?, ?, 1, ?)
            """,
            (email, password_hash, isoformat_utc(now)),
        )
        user_id = cursor.lastrowid

    token = create_auth_token(user_id)
    return {
        "message": "Account created successfully!",
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user_id,
            "email": email,
            "is_verified": True,
        },
    }


@app.post("/auth/verify-email")
def verify_email(req: VerifyEmailRequest):
    cleanup_expired_data()
    email = normalize_email(req.email)

    with get_db() as conn:
        user = conn.execute(
            "SELECT id FROM users WHERE email = ?",
            (email,),
        ).fetchone()
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        conn.execute("UPDATE users SET is_verified = 1 WHERE id = ?", (user["id"],))

    token = create_auth_token(user["id"])
    return {
        "message": "Email verified successfully",
        "access_token": token,
        "token_type": "bearer",
    }


@app.post("/auth/login")
def login(req: LoginRequest):
    cleanup_expired_data()
    email = normalize_email(req.email)

    with get_db() as conn:
        user = conn.execute(
            "SELECT id, email, password_hash, is_verified FROM users WHERE email = ?",
            (email,),
        ).fetchone()

    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    token = create_auth_token(user["id"])
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user["id"],
            "email": user["email"],
            "is_verified": bool(user["is_verified"]),
        },
    }


@app.post("/auth/logout")
def logout(token: str = Depends(get_bearer_token)):
    with get_db() as conn:
        cursor = conn.execute(
            "DELETE FROM auth_sessions WHERE token_hash = ?",
            (hash_text(token),),
        )
    if cursor.rowcount == 0:
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    return {"message": "Logged out successfully"}


@app.get("/auth/me")
def auth_me(current_user: sqlite3.Row = Depends(get_current_user)):
    return {
        "id": current_user["id"],
        "email": current_user["email"],
        "is_verified": bool(current_user["is_verified"]),
    }


@app.get("/chat/sessions")
def list_chat_sessions(current_user: sqlite3.Row = Depends(get_current_user)):
    cleanup_expired_data()
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT
                chat_sessions.id,
                chat_sessions.created_at,
                COUNT(chat_messages.id) AS message_count,
                MAX(chat_messages.created_at) AS last_message_at,
                COALESCE(
                    (
                        SELECT content
                        FROM chat_messages
                        WHERE chat_messages.session_id = chat_sessions.id
                          AND chat_messages.role = 'user'
                        ORDER BY id ASC
                        LIMIT 1
                    ),
                    (
                        SELECT content
                        FROM chat_messages
                        WHERE chat_messages.session_id = chat_sessions.id
                        ORDER BY id ASC
                        LIMIT 1
                    )
                ) AS first_message
            FROM chat_sessions
            LEFT JOIN chat_messages ON chat_messages.session_id = chat_sessions.id
            WHERE chat_sessions.user_id = ?
            GROUP BY chat_sessions.id, chat_sessions.created_at
            ORDER BY COALESCE(MAX(chat_messages.created_at), chat_sessions.created_at) DESC
            """,
            (current_user["id"],),
        ).fetchall()

    return {
        "sessions": [
            {
                "session_id": row["id"],
                "created_at": row["created_at"],
                "last_message_at": row["last_message_at"],
                "message_count": row["message_count"],
                "first_message": row["first_message"] or "New conversation",
            }
            for row in rows
        ]
    }


@app.get("/chat/sessions/{session_id}/messages")
def get_chat_messages(session_id: str, current_user: sqlite3.Row = Depends(get_current_user)):
    cleanup_expired_data()
    with get_db() as conn:
        session = conn.execute(
            "SELECT id FROM chat_sessions WHERE id = ? AND user_id = ?",
            (session_id, current_user["id"]),
        ).fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="Chat session not found")

        rows = conn.execute(
            """
            SELECT id, role, content, image_url, reactions, created_at
            FROM chat_messages
            WHERE session_id = ? AND user_id = ?
            ORDER BY id ASC
            """,
            (session_id, current_user["id"]),
        ).fetchall()

    return {
        "session_id": session_id,
        "messages": [
            {
                "id": row["id"],
                "role": row["role"],
                "content": row["content"],
                "image_url": row["image_url"] if "image_url" in row.keys() else None,
                "reactions": json.loads(row["reactions"]) if ("reactions" in row.keys() and row["reactions"]) else {},
                "created_at": row["created_at"],
            }
            for row in rows
        ],
    }


@app.post("/chat/messages/{message_id}/reactions")
def toggle_message_reaction(
    message_id: int,
    req: ReactionRequest,
    current_user: sqlite3.Row = Depends(get_current_user),
):
    cleanup_expired_data()
    emoji = req.emoji.strip()
    if not emoji:
        raise HTTPException(status_code=400, detail="Emoji cannot be empty")

    with get_db() as conn:
        row = conn.execute(
            "SELECT id, reactions FROM chat_messages WHERE id = ? AND user_id = ?",
            (message_id, current_user["id"]),
        ).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Message not found")

        reactions_dict = {}
        if "reactions" in row.keys() and row["reactions"]:
            try:
                reactions_dict = json.loads(row["reactions"])
            except Exception:
                reactions_dict = {}

        # Toggle emoji: if present remove, if not add
        if emoji in reactions_dict:
            del reactions_dict[emoji]
        else:
            reactions_dict[emoji] = 1

        updated_json = json.dumps(reactions_dict)
        conn.execute(
            "UPDATE chat_messages SET reactions = ? WHERE id = ?",
            (updated_json, message_id),
        )

    return {
        "message_id": message_id,
        "reactions": reactions_dict,
    }


@app.delete("/chat/sessions/{session_id}")
def delete_chat_session(session_id: str, current_user: sqlite3.Row = Depends(get_current_user)):
    cleanup_expired_data()
    with get_db() as conn:
        session = conn.execute(
            "SELECT id FROM chat_sessions WHERE id = ? AND user_id = ?",
            (session_id, current_user["id"]),
        ).fetchone()
        if not session:
            raise HTTPException(status_code=404, detail="Chat session not found")

        conn.execute(
            "DELETE FROM chat_messages WHERE session_id = ? AND user_id = ?",
            (session_id, current_user["id"]),
        )
        conn.execute(
            "DELETE FROM chat_sessions WHERE id = ? AND user_id = ?",
            (session_id, current_user["id"]),
        )

    return {"message": "Chat session deleted successfully", "session_id": session_id}


@app.post("/chat")
async def chat(req: ChatRequest, current_user: sqlite3.Row = Depends(get_current_user)):
    cleanup_expired_data()
    message = (req.message or "").strip()
    user_image_url = req.image
    if not message and not user_image_url:
        raise HTTPException(status_code=400, detail="Empty message")

    display_message = message or "Shared a photo 📷"

    # Contextual auto-reaction from Titli to the user's message
    user_reactions = {}
    lower_msg = message.lower()
    if user_image_url:
        user_reactions = {"😍": 1}
    elif any(k in lower_msg for k in ["love", "miss you", "cute", "kiss", "hot", "baby", "darling"]):
        user_reactions = {"❤️": 1}
    elif any(k in lower_msg for k in ["haha", "lol", "funny", "joke", "lmao"]):
        user_reactions = {"😂": 1}
    elif any(k in lower_msg for k in ["magic", "dream", "star", "night", "glow"]):
        user_reactions = {"✨": 1}
    elif any(k in lower_msg for k in ["titli", "butterfly", "fly", "wings"]):
        user_reactions = {"🦋": 1}

    with get_db() as conn:
        session_id = get_or_create_chat_session(conn, current_user["id"], req.session_id)
        user_msg_id = save_chat_message(
            conn,
            session_id,
            current_user["id"],
            "user",
            display_message,
            image_url=user_image_url,
            reactions=json.dumps(user_reactions)
        )
        history = load_chat_history(conn, current_user["id"], session_id)

    # Detect if user asks Titli for a photo or selfie
    lower_msg = message.lower()
    photo_triggers = ["photo", "picture", "selfie", "pic", "image", "look like", "what are you doing", "show me", "send a photo", "photo moment"]
    wants_photo = any(k in lower_msg for k in photo_triggers)
    assistant_image_url = None

    if wants_photo:
        if "coffee" in lower_msg or "morning" in lower_msg or "tea" in lower_msg:
            prompt_slug = "cozy warm morning coffee with cute foam art on wooden cafe table warm sunlight aesthetic photography"
        elif "sunset" in lower_msg or "evening" in lower_msg or "sky" in lower_msg:
            prompt_slug = "romantic golden hour sunset sky pastel pink and orange clouds balcony photography"
        elif "rain" in lower_msg or "weather" in lower_msg:
            prompt_slug = "rain drops on cafe window glass cozy warm indoor atmosphere bokeh lights photography"
        elif "outfit" in lower_msg or "dress" in lower_msg or "wearing" in lower_msg or "look like" in lower_msg or "selfie" in lower_msg:
            prompt_slug = "aesthetic cute stylish chic pastel outfit aesthetic cozy photography soft natural lighting warm smile"
        elif "flower" in lower_msg or "rose" in lower_msg:
            prompt_slug = "gorgeous fresh pink and white roses bouquet aesthetic soft morning lighting"
        elif "food" in lower_msg or "cake" in lower_msg or "dessert" in lower_msg:
            prompt_slug = "delicious sweet strawberry pastry dessert cute cafe aesthetic food photography"
        else:
            prompt_slug = "sweet cute female companion cozy lifestyle moment warm fairy lights aesthetic photography 4k"

        encoded = urllib.parse.quote(prompt_slug)
        assistant_image_url = f"https://image.pollinations.ai/prompt/{encoded}?width=600&height=600&nologo=true"

    if user_image_url and history:
        last_item = history[-1]
        if last_item["role"] == "user":
            last_item["content"] = f"{display_message} [The user shared an image with you. Compliment it and respond warmly and flirtatiously!]"

    payload = {
        "model": "mistralai/mistral-small-3.2-24b-instruct",
        "messages": history,
        "temperature": 0.8,
        "max_tokens": 512,
    }
    headers = {
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
        "HTTP-Referer": REFERER,
        "X-Title": TITLE,
    }

    async with httpx.AsyncClient(timeout=45) as client:
        try:
            resp = await client.post(
                "https://openrouter.ai/api/v1/chat/completions",
                headers=headers,
                content=json.dumps(payload),
            )
        except Exception as exc:
            raise HTTPException(status_code=502, detail=f"Request failed: {exc}") from exc

    if resp.status_code != 200:
        raise HTTPException(status_code=resp.status_code, detail=resp.text)

    data = resp.json()
    try:
        reply = data["choices"][0]["message"]["content"].strip()
    except Exception as exc:
        raise HTTPException(
            status_code=500,
            detail="Invalid response format from model",
        ) from exc

    with get_db() as conn:
        assistant_msg_id = save_chat_message(
            conn,
            session_id,
            current_user["id"],
            "assistant",
            reply,
            image_url=assistant_image_url,
            reactions="{}"
        )

    return {
        "session_id": session_id,
        "user_message_id": user_msg_id,
        "user_reactions": user_reactions,
        "assistant_message_id": assistant_msg_id,
        "reply": reply,
        "image_url": assistant_image_url,
        "reactions": {},
    }
