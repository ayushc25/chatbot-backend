# Companion Chatbot Backend

A high-performance asynchronous REST API built with **FastAPI** and **SQLite**, powering the Titli Companion Lounge. Features user authentication with PBKDF2 password hashing, persistent private chat sessions with cascading history, message emoji reactions, multimodal photo moments with Pollinations.ai, and OpenRouter integration for conversational replies.

---

## Features

- **Authentication & Security**: PBKDF2 password hashing with 100,000 iterations and secure token-based session management.
- **Message Reactions**: Interactive emoji reactions on user and assistant messages with database persistence.
- **Multimodal Photo Moments**: Zero-cost AI photo generation via Pollinations.ai and user photo sharing.
- **Private Chat Sessions**: Users have isolated conversations. Each user has their own session list and message archives.
- **Session Management & Deletion**: Create, list, fetch, and delete chat sessions and their associated history on demand.
- **Auto Data Retention**: Automatic cleanup of sessions after the retention window (default 7 days).
- **CORS Enabled**: Ready for local development and production web clients.

---

## Prerequisites

- **Python 3.10+** (Python 3.11 or 3.12 recommended)
- **pip** package manager
- An **OpenRouter API Key** for conversational generation

---

## Quick Start Guide

### 1. Navigate to the backend directory
```powershell
# Windows
cd "d:\Click MicroSystem\advice chatbot\backend"
```
```bash
# Linux / macOS
cd backend
```

### 2. Create and Activate Virtual Environment

**On Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```
*(If PowerShell restricts script execution, run: `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`)*

**On Linux / macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables
Create or edit your `.env` file in the `backend/` directory:

```env
# OpenRouter API Key for conversational completions
OPENROUTER_API_KEY=your_openrouter_api_key_here

# Frontend Application URL (used for CORS and HTTP Referer headers)
SITE_URL=http://localhost:3000
SITE_TITLE="Titli Companion"

# Local SQLite Database file name or path
DATABASE_PATH=chatbot.db

# SMTP Configuration for verification emails
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USERNAME=your_email@gmail.com
SMTP_PASSWORD=your_app_password_here
SMTP_FROM_EMAIL=your_email@gmail.com
SMTP_USE_TLS=true
```

> **Note on Gmail:** If using Gmail for SMTP, generate an **App Password** from your Google Account (Security -> 2-Step Verification -> App Passwords).

### 5. Run the Server

**Development Mode (with auto-reload):**
```bash
uvicorn app:app --reload --host 127.0.0.1 --port 8000
```

The API will start at:
- **Base URL**: `http://127.0.0.1:8000`
- **Interactive Swagger Docs**: `http://127.0.0.1:8000/docs`
- **Alternative ReDoc**: `http://127.0.0.1:8000/redoc`

---

## API Endpoints Reference

### Authentication
| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `POST` | `/auth/signup` | Register email & password, dispatch verification code | No |
| `POST` | `/auth/verify-email` | Validate code and receive access bearer token | No |
| `POST` | `/auth/login` | Login with verified account credentials | No |
| `GET` | `/auth/me` | Retrieve profile of the current logged-in user | Bearer Token |
| `POST` | `/auth/logout` | Invalidate active session token | Bearer Token |

### Chat Operations
| Method | Endpoint | Description | Auth Required |
|---|---|---|---|
| `GET` | `/chat/sessions` | List all saved chat sessions with message counts | Bearer Token |
| `GET` | `/chat/sessions/{session_id}/messages` | Fetch complete message history for a specific session | Bearer Token |
| `DELETE` | `/chat/sessions/{session_id}` | Delete a chat session and all its messages | Bearer Token |
| `POST` | `/chat` | Send a message to continue or start a session | Bearer Token |

---

## Database Architecture

The SQLite database (`chatbot.db`) is automatically initialized on application startup with the following tables:

- `users`: Stores user accounts, verified state, and password hashes.
- `email_verifications`: Tracks SHA-256 hashed one-time verification codes with expiration timestamps.
- `auth_sessions`: Active bearer tokens and session expiry timestamps.
- `chat_sessions`: Unique session IDs linked to user accounts.
- `chat_messages`: Stored conversation messages (`role`, `content`, `created_at`) with foreign key cascading deletion.
