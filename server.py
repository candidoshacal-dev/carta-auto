import os
import json
import base64
import hashlib
import hmac
import secrets
import sqlite3
import random
import smtplib
import logging
from contextlib import asynccontextmanager
from email.message import EmailMessage
from datetime import datetime, timedelta, timezone
from typing import Optional, List, Dict, Any, Tuple

import pyotp
from cryptography.fernet import Fernet
from fastapi import FastAPI, HTTPException, Depends, Header, Query, Request, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel

from database import get_connection, init_db, hash_password, verify_password, USE_POSTGRES

APP_ENV = os.environ.get('CAT_ENV', 'development').lower()
SESSION_SECRET = os.environ.get('SESSION_SECRET', 'local-development-only-change-before-deploy')
REQUIRE_ADMIN_MFA = os.environ.get('CAT_REQUIRE_ADMIN_MFA', 'false').strip().lower() in {'1', 'true', 'yes', 'on'}
if APP_ENV == 'production' and (len(SESSION_SECRET) < 40 or SESSION_SECRET.startswith('CHANGE_ME')):
    raise RuntimeError("Defina SESSION_SECRET com pelo menos 40 caracteres em produção.")
DOCS_URL = None if APP_ENV == 'production' else '/docs'
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(_app: FastAPI):
    # Uvicorn imports `server:app` and does not execute this module as __main__.
    # Initialise the persistent database during application startup instead.
    init_db()
    logger.info("Database initialised (postgres=%s)", USE_POSTGRES)
    yield


app = FastAPI(title="Carta Auto Testes API", version="1.1.0", lifespan=lifespan, docs_url=DOCS_URL, redoc_url=None, openapi_url=None if APP_ENV == 'production' else '/openapi.json')
ALLOWED_ORIGINS = [origin.strip() for origin in os.environ.get('CORS_ORIGINS', 'http://127.0.0.1:8000,http://localhost:8000').split(',') if origin.strip()]

@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
    if APP_ENV == 'production':
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
    return response

def reject_public_debug():
    if APP_ENV == 'production':
        raise HTTPException(status_code=404, detail="Não encontrado.")



@app.get("/debug/login/{email}")
def debug_login(email: str):
    reject_public_debug()
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE LOWER(email) = LOWER(?)", (email.strip(),))
        user = c.fetchone()
        if not user:
            return {"status": "error", "message": "User not found"}
        
        user_dict = dict(user)
        return {
            "status": "success", 
            "user_found": True,
            "user_id": user_dict['id'],
            "role": user_dict['role'],
            "email": user_dict['email'],
            "is_active": user_dict['is_active'],
            "password_hash": user_dict['password_hash'][:50] + "...",
            "totp_enabled": user_dict.get('totp_enabled', 0)
        }
    except Exception as e:
        import traceback
        return {"status": "error", "error": str(e), "traceback": traceback.format_exc()}



@app.get("/debug/simple")
def debug_simple():
    reject_public_debug()
    return {"status": "ok", "message": "Debug endpoint working"}

@app.get("/debug/db")
def debug_db():
    reject_public_debug()
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("SELECT 1")
        result = c.fetchone()
        conn.close()
        return {"status": "success", "db": "connected", "result": result, "use_postgres": USE_POSTGRES}
    except Exception as e:
        import traceback
        return {"status": "error", "db": "failed", "error": str(e), "traceback": traceback.format_exc()}

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

# Helper: License calculations
def get_license_info(license_expires_at_str: str):
    now = datetime.now()
    try:
        expires_at = datetime.strptime(license_expires_at_str, '%Y-%m-%d %H:%M:%S')
    except Exception:
        expires_at = now

    diff = expires_at - now
    days_remaining = diff.days if diff.total_seconds() > 0 else 0
    is_expired = now >= expires_at

    # Warning alert calculation
    alert_message = None
    if is_expired:
        alert_message = "A sua licença expirou. Contacte a secretaria para renovação."
    elif days_remaining <= 10:
        alert_message = f"A sua licença expira dentro de {days_remaining} {'dia' if days_remaining == 1 else 'dias'}. Para renovar contacte a secretaria."

    # Format Portuguese date
    exp_formatted = expires_at.strftime('%d/%m/%Y')

    # Progress bar percentage (assuming standard 60-day cycle as base)
    pct = max(0, min(100, int((days_remaining / 60.0) * 100)))

    return {
        "is_expired": is_expired,
        "days_remaining": days_remaining,
        "expires_at_str": license_expires_at_str,
        "expires_at_formatted": exp_formatted,
        "alert_message": alert_message,
        "progress_percent": pct
    }

# Cryptography cipher for MFA secret encryption at rest
def get_mfa_cipher() -> Fernet:
    key_env = os.environ.get('CAT_MFA_ENCRYPTION_KEY')
    if key_env:
        return Fernet(key_env.encode('ascii') if isinstance(key_env, str) else key_env)
    derived = hashlib.sha256((SESSION_SECRET + ":mfa-encryption-key-2026").encode('utf-8')).digest()
    return Fernet(base64.urlsafe_b64encode(derived))

# Signed, expiring bearer tokens with session_version for instant revocation
def create_session(user_id: int, session_version: int = 1) -> str:
    expires = int(datetime.now(timezone.utc).timestamp()) + 12 * 60 * 60
    payload = f"{user_id}:{expires}:{session_version}:{secrets.token_hex(8)}"
    signature = hmac.new(SESSION_SECRET.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).digest()
    body = base64.urlsafe_b64encode(payload.encode('utf-8')).decode('ascii').rstrip('=')
    signed = base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')
    return body + '.' + signed

def read_session(token: str) -> Optional[Tuple[int, int]]:
    try:
        body, signed = token.split('.', 1)
        payload = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)).decode('utf-8')
        received = base64.urlsafe_b64decode(signed + '=' * (-len(signed) % 4))
        expected = hmac.new(SESSION_SECRET.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).digest()
        if not hmac.compare_digest(received, expected):
            return None
        parts = payload.split(':')
        if len(parts) < 3:
            return None
        user_id = int(parts[0])
        expires = int(parts[1])
        if expires <= int(datetime.now(timezone.utc).timestamp()):
            return None
        session_version = int(parts[2]) if len(parts) >= 4 else 1
        return user_id, session_version
    except (ValueError, TypeError, UnicodeDecodeError):
        return None

# Temporary tokens for MFA setup / verification (5 min validity)
def create_mfa_temp_token(user_id: int, purpose: str = "mfa-verify") -> str:
    expires = int(datetime.now(timezone.utc).timestamp()) + 5 * 60
    payload = f"mfa:{user_id}:{purpose}:{expires}:{secrets.token_hex(8)}"
    signature = hmac.new(SESSION_SECRET.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).digest()
    body = base64.urlsafe_b64encode(payload.encode('utf-8')).decode('ascii').rstrip('=')
    signed = base64.urlsafe_b64encode(signature).decode('ascii').rstrip('=')
    return body + '.' + signed

def read_mfa_temp_token(token: str, expected_purpose: str = "mfa-verify") -> Optional[int]:
    try:
        body, signed = token.split('.', 1)
        payload = base64.urlsafe_b64decode(body + '=' * (-len(body) % 4)).decode('utf-8')
        received = base64.urlsafe_b64decode(signed + '=' * (-len(signed) % 4))
        expected = hmac.new(SESSION_SECRET.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).digest()
        if not hmac.compare_digest(received, expected):
            return None
        parts = payload.split(':')
        if len(parts) < 5 or parts[0] != 'mfa' or parts[2] != expected_purpose:
            return None
        user_id = int(parts[1])
        expires = int(parts[3])
        if expires <= int(datetime.now(timezone.utc).timestamp()):
            return None
        return user_id
    except Exception:
        return None

def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"

def log_security_event(user_id: Optional[int], event_type: str, details: str, ip_address: Optional[str] = None):
    try:
        conn = get_connection()
        c = conn.cursor()
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        c.execute("""
            INSERT INTO security_audit_logs (user_id, event_type, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?)
        """, (user_id, event_type, details, ip_address or '', now_str))
        conn.commit()
        conn.close()
    except Exception:
        pass

def check_account_locked(user_row: dict):
    if user_row.get('locked_until'):
        try:
            locked_dt = datetime.strptime(user_row['locked_until'], '%Y-%m-%d %H:%M:%S')
            if datetime.now() < locked_dt:
                diff = int((locked_dt - datetime.now()).total_seconds() / 60) + 1
                raise HTTPException(status_code=429, detail=f"Conta temporariamente bloqueada por tentativas excessivas. Tente novamente dentro de {diff} minutos.")
        except HTTPException:
            raise
        except Exception:
            pass

def record_failed_attempt(user_id: int, ip_address: Optional[str] = None):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT failed_login_attempts FROM users WHERE id = ?", (user_id,))
    row = c.fetchone()
    if row:
        attempts = (row['failed_login_attempts'] or 0) + 1
        locked_until = None
        if attempts >= 5:
            now = datetime.now()
            locked_until = (now + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
            log_security_event(user_id, 'account_locked', f'Conta bloqueada por 15 min após {attempts} tentativas falhadas.', ip_address)
        c.execute("UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?", (attempts, locked_until, user_id))
        conn.commit()
    conn.close()

def record_successful_login(user_id: int, ip_address: Optional[str] = None):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = ? WHERE id = ?", (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user_id))
    conn.commit()
    conn.close()

def generate_recovery_codes() -> Tuple[List[str], List[str]]:
    plain_codes = []
    hashes = []
    for _ in range(8):
        part1 = secrets.token_hex(2).upper()
        part2 = secrets.token_hex(2).upper()
        code = f"CAT-{part1}-{part2}"
        plain_codes.append(code)
        normalized = code.replace('-', '').upper()
        hashes.append(hashlib.sha256(normalized.encode('utf-8')).hexdigest())
    return plain_codes, hashes

def get_current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(status_code=401, detail="Não autenticado.")
    token = authorization[7:].strip()
    session_data = read_session(token)
    if not session_data:
        raise HTTPException(status_code=401, detail="Sessão inválida ou expirada.")

    user_id, token_version = session_data
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Utilizador não encontrado.")
    if user['session_version'] != token_version:
        raise HTTPException(status_code=401, detail="Sessão terminada ou revogada.")
    if not user['is_active']:
        raise HTTPException(status_code=403, detail="A sua conta encontra-se desativada. Contacte a administração.")
    return dict(user)

def get_admin_user(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'ADMIN' or str(current_user.get('email', '')).lower() != 'candidoshacal@gmail.com':
        raise HTTPException(status_code=403, detail="Acesso reservado ao Administrador.")
    return current_user

# Pydantic Schemas
class RegisterRequest(BaseModel):
    nome_completo: str
    numero_aluno: str
    email: str
    telemovel: str
    password: str
    confirmar_password: str
    communications_consent: bool = False

class LoginRequest(BaseModel):
    login: str  # email OR numero_aluno
    password: str

class MFASetupRequest(BaseModel):
    temp_token: Optional[str] = None

class MFAConfirmRequest(BaseModel):
    temp_token: str
    code: str

class MFAVerifyRequest(BaseModel):
    temp_token: str
    code: str

class MFARegenerateRequest(BaseModel):
    password: str

class UpdateProfileRequest(BaseModel):
    email: str
    telemovel: str

class CommunicationsConsentRequest(BaseModel):
    consent: bool

class UpdatePasswordRequest(BaseModel):
    current_password: str
    new_password: str

class RecoverPasswordRequest(BaseModel):
    email: str

class ResetPasswordConfirmRequest(BaseModel):
    token: str
    new_password: str

class StartTestRequest(BaseModel):
    categoria: str # A, B, C, D
    test_type: str # aleatorio, tematico, nao_vistas, erradas, mais_erradas, exame
    tema: Optional[str] = None
    temas: Optional[List[str]] = None
    num_questions: int = 30

class SubmitTestRequest(BaseModel):
    answers: Dict[str, str] # question_id (as str) -> selected_letter
    duration_seconds: int

class RenewLicenseRequest(BaseModel):
    months_or_years: str # "2m", "6m", "1y"

class UpdateCategoriesRequest(BaseModel):
    categories: List[str]

class AdminResetPasswordRequest(BaseModel):
    new_password: str

class AdminQuestionRequest(BaseModel):
    categoria: str
    tema: str
    prompt: str
    options: List[Dict[str, Any]]
    correct_letter: str
    image_path: Optional[str] = None


# ----------------- AUTH ENDPOINTS -----------------

@app.post("/api/auth/register")
def register(req: RegisterRequest):
    if not req.nome_completo.strip() or not req.numero_aluno.strip() or not req.email.strip() or not req.telemovel.strip():
        raise HTTPException(status_code=400, detail="Todos os campos são obrigatórios.")

    if req.password != req.confirmar_password:
        raise HTTPException(status_code=400, detail="As passwords não coincidem.")

    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="A password deve ter pelo menos 6 caracteres.")

    conn = get_connection()
    c = conn.cursor()

    # Check unique email
    c.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?)", (req.email.strip(),))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Este email já se encontra registado.")

    # Check unique numero_aluno
    c.execute("SELECT id FROM users WHERE LOWER(numero_aluno) = LOWER(?)", (req.numero_aluno.strip(),))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Este Número de Aluno já se encontra registado.")

    now = datetime.now()
    # 60 days license (2 months)
    expires_at = (now + timedelta(days=60)).strftime('%Y-%m-%d %H:%M:%S')

    c.execute("""
    INSERT INTO users (role, nome_completo, numero_aluno, email, telemovel, password_hash, created_at, marketing_consent, marketing_consent_at, license_expires_at, allowed_categories, is_active)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
    RETURNING id
    """, (
        'ALUNO',
        req.nome_completo.strip(),
        req.numero_aluno.strip().upper(),
        req.email.strip().lower(),
        req.telemovel.strip(),
        hash_password(req.password),
        now.strftime('%Y-%m-%d %H:%M:%S'),
        1 if req.communications_consent else 0,
        now.strftime('%Y-%m-%d %H:%M:%S') if req.communications_consent else None,
        expires_at,
        '' # No test access until the administrator grants a category
    ))
    user_id = c.fetchone()[0] if USE_POSTGRES else c.lastrowid
    conn.commit()

    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = dict(c.fetchone())
    conn.close()

    token = create_session(user_id)
    lic = get_license_info(user['license_expires_at'])

    return {
        "token": token,
        "user": {
            "id": user['id'],
            "role": user['role'],
            "nome_completo": user['nome_completo'],
            "numero_aluno": user['numero_aluno'],
            "email": user['email'],
            "telemovel": user['telemovel'],
            "allowed_categories": [cat.strip() for cat in user['allowed_categories'].split(',') if cat.strip()],
            "license": lic
        }
    }

@app.post("/api/auth/login")
def login(req: LoginRequest, request: Request):
    login_val = req.login.strip().lower()
    client_ip = get_client_ip(request)
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT * FROM users WHERE LOWER(email) = ? OR LOWER(numero_aluno) = ?
    """, (login_val, login_val))
    user = c.fetchone()
    conn.close()

    if not user:
        raise HTTPException(status_code=401, detail="Email / Número de Aluno ou password incorretos.")

    user = dict(user)
    check_account_locked(user)

    if not verify_password(req.password, user['password_hash']):
        record_failed_attempt(user['id'], client_ip)
        log_security_event(user['id'], 'login_failed', 'Credenciais inválidas.', client_ip)
        raise HTTPException(status_code=401, detail="Email / Número de Aluno ou password incorretos.")

    if not str(user['password_hash']).startswith('pbkdf2_sha256$'):
        conn = get_connection()
        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(req.password), user['id']))
        conn.commit()
        conn.close()

    if not user['is_active']:
        raise HTTPException(status_code=403, detail="A sua conta encontra-se desativada. Contacte a administração.")

    # Optional admin MFA flow. It is disabled by default because the deployment
    # does not provide an email-based MFA delivery channel.
    if user['role'] == 'ADMIN' and REQUIRE_ADMIN_MFA:
        if not user['totp_enabled']:
            temp_token = create_mfa_temp_token(user['id'], 'mfa-setup')
            log_security_event(user['id'], 'admin_login_mfa_setup_pending', 'Credenciais corretas; aguarda configuração de TOTP.', client_ip)
            return {
                "mfa_required": True,
                "mfa_setup_required": True,
                "temp_token": temp_token,
                "message": "Configure a aplicação autenticadora para continuar."
            }
        else:
            temp_token = create_mfa_temp_token(user['id'], 'mfa-verify')
            log_security_event(user['id'], 'admin_login_mfa_pending', 'Credenciais corretas; aguarda código TOTP.', client_ip)
            return {
                "mfa_required": True,
                "mfa_setup_required": False,
                "temp_token": temp_token,
                "message": "Introduza o código do seu autenticador ou código de recuperação."
            }

    # Student login
    record_successful_login(user['id'], client_ip)
    log_security_event(user['id'], 'login_success', 'Início de sessão efetuado com sucesso.', client_ip)
    token = create_session(user['id'], user['session_version'] if 'session_version' in user.keys() else 1)
    lic = get_license_info(user['license_expires_at'])

    return {
        "token": token,
        "user": {
            "id": user['id'],
            "role": user['role'],
            "nome_completo": user['nome_completo'],
            "numero_aluno": user['numero_aluno'],
            "email": user['email'],
            "telemovel": user['telemovel'],
            "allowed_categories": [cat.strip() for cat in user['allowed_categories'].split(',') if cat.strip()],
            "license": lic
        }
    }

@app.post("/api/auth/mfa/setup")
def mfa_setup(req: MFASetupRequest, request: Request, authorization: Optional[str] = Header(None)):
    user_id = None
    if req.temp_token:
        user_id = read_mfa_temp_token(req.temp_token, 'mfa-setup')
    if not user_id and authorization and authorization.lower().startswith('bearer '):
        sess = read_session(authorization[7:].strip())
        if sess:
            user_id = sess[0]

    if not user_id:
        raise HTTPException(status_code=401, detail="Token de configuração inválido ou expirado.")

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    if not user or user['role'] != 'ADMIN':
        conn.close()
        raise HTTPException(status_code=403, detail="Acesso reservado ao Administrador.")

    secret = pyotp.random_base32()
    cipher = get_mfa_cipher()
    secret_enc = cipher.encrypt(secret.encode('utf-8')).decode('ascii')
    plain_recovery, recovery_hashes = generate_recovery_codes()

    c.execute("""
        UPDATE users
        SET totp_temp_secret_enc = ?, totp_recovery_hashes = ?
        WHERE id = ?
    """, (secret_enc, json.dumps(recovery_hashes), user_id))
    conn.commit()
    conn.close()

    totp_obj = pyotp.TOTP(secret)
    provisioning_uri = totp_obj.provisioning_uri(name=user['email'], issuer_name="Carta Auto Testes")
    log_security_event(user_id, 'mfa_setup_started', 'Configuração de MFA iniciada.', get_client_ip(request))

    return {
        "secret": secret,
        "otpauth_uri": provisioning_uri,
        "recovery_codes": plain_recovery,
        "message": "Guarde os códigos de recuperação. Insira o código atual do autenticador para confirmar."
    }

@app.post("/api/auth/mfa/confirm")
def mfa_confirm(req: MFAConfirmRequest, request: Request):
    user_id = read_mfa_temp_token(req.temp_token, 'mfa-setup')
    if not user_id:
        raise HTTPException(status_code=401, detail="Token temporário inválido ou expirado.")

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    if not user or user['role'] != 'ADMIN':
        conn.close()
        raise HTTPException(status_code=403, detail="Acesso reservado ao Administrador.")

    user = dict(user)
    if not user['totp_temp_secret_enc']:
        conn.close()
        raise HTTPException(status_code=400, detail="Configuração de MFA não iniciada.")

    cipher = get_mfa_cipher()
    try:
        secret = cipher.decrypt(user['totp_temp_secret_enc'].encode('ascii')).decode('utf-8')
    except Exception:
        conn.close()
        raise HTTPException(status_code=500, detail="Erro ao decifrar chave MFA.")

    totp_obj = pyotp.TOTP(secret)
    clean_code = req.code.strip().replace(' ', '')
    client_ip = get_client_ip(request)

    now_ts = int(datetime.now(timezone.utc).timestamp())
    current_counter = now_ts // 30
    matched_step = None
    for step_offset in [0, -1, 1]:
        test_step = current_counter + step_offset
        if hmac.compare_digest(totp_obj.at(test_step * 30), clean_code):
            matched_step = test_step
            break

    if matched_step is None:
        record_failed_attempt(user_id, client_ip)
        log_security_event(user_id, 'mfa_confirm_failed', 'Código incorreto ao confirmar ativação MFA.', client_ip)
        conn.close()
        raise HTTPException(status_code=400, detail="Código de autenticação incorreto. Verifique a hora do dispositivo.")

    c.execute("""
        UPDATE users
        SET totp_enabled = 1,
            totp_secret_enc = totp_temp_secret_enc,
            totp_temp_secret_enc = NULL,
            totp_last_counter = ?,
            failed_login_attempts = 0,
            locked_until = NULL
        WHERE id = ?
    """, (matched_step, user_id))
    conn.commit()
    conn.close()

    record_successful_login(user_id, client_ip)
    log_security_event(user_id, 'mfa_enabled', 'MFA TOTP ativado com sucesso.', client_ip)

    token = create_session(user_id, user['session_version'] if 'session_version' in user.keys() else 1)
    lic = get_license_info(user['license_expires_at'])
    return {
        "message": "Autenticação de dois fatores ativada com sucesso.",
        "token": token,
        "user": {
            "id": user['id'],
            "role": user['role'],
            "nome_completo": user['nome_completo'],
            "numero_aluno": user['numero_aluno'],
            "email": user['email'],
            "telemovel": user['telemovel'],
            "allowed_categories": [cat.strip() for cat in user['allowed_categories'].split(',') if cat.strip()],
            "license": lic
        }
    }

@app.post("/api/auth/mfa/verify")
def mfa_verify(req: MFAVerifyRequest, request: Request):
    user_id = read_mfa_temp_token(req.temp_token, 'mfa-verify')
    if not user_id:
        raise HTTPException(status_code=401, detail="Token temporário inválido ou expirado. Inicie sessão novamente.")

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    if not user or user['role'] != 'ADMIN':
        conn.close()
        raise HTTPException(status_code=403, detail="Acesso reservado ao Administrador.")

    user = dict(user)
    client_ip = get_client_ip(request)
    check_account_locked(user)

    if not user['totp_enabled'] or not user['totp_secret_enc']:
        conn.close()
        raise HTTPException(status_code=400, detail="MFA não se encontra ativado para esta conta.")

    clean_code = req.code.strip().replace(' ', '').upper()

    if clean_code.isdigit() and len(clean_code) == 6:
        cipher = get_mfa_cipher()
        try:
            secret = cipher.decrypt(user['totp_secret_enc'].encode('ascii')).decode('utf-8')
        except Exception:
            conn.close()
            raise HTTPException(status_code=500, detail="Erro interno ao decifrar chave MFA.")

        totp_obj = pyotp.TOTP(secret)
        now_ts = int(datetime.now(timezone.utc).timestamp())
        current_step = now_ts // 30

        matched_step = None
        for step_offset in [0, -1, 1]:
            test_step = current_step + step_offset
            if hmac.compare_digest(totp_obj.at(test_step * 30), clean_code):
                matched_step = test_step
                break

        if matched_step is None:
            record_failed_attempt(user_id, client_ip)
            log_security_event(user_id, 'mfa_verify_failed', 'Código TOTP incorreto.', client_ip)
            conn.close()
            raise HTTPException(status_code=401, detail="Código de autenticação incorreto.")

        last_counter = user['totp_last_counter'] or 0
        if matched_step <= last_counter:
            record_failed_attempt(user_id, client_ip)
            log_security_event(user_id, 'mfa_replay_rejected', f'Código TOTP reutilizado/expirado (step {matched_step} <= {last_counter}).', client_ip)
            conn.close()
            raise HTTPException(status_code=400, detail="Este código já foi utilizado ou expirou. Aguarde pelo próximo código no autenticador.")

        c.execute("UPDATE users SET totp_last_counter = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (matched_step, user_id))
        conn.commit()
        conn.close()

        record_successful_login(user_id, client_ip)
        log_security_event(user_id, 'mfa_login_success', 'Login autenticado via TOTP.', client_ip)
        token = create_session(user_id, user['session_version'] if 'session_version' in user.keys() else 1)
        lic = get_license_info(user['license_expires_at'])
        return {
            "token": token,
            "user": {
                "id": user['id'],
                "role": user['role'],
                "nome_completo": user['nome_completo'],
                "numero_aluno": user['numero_aluno'],
                "email": user['email'],
                "telemovel": user['telemovel'],
                "allowed_categories": [cat.strip() for cat in user['allowed_categories'].split(',') if cat.strip()],
                "license": lic
            }
        }

    # Recovery code check
    norm_code = clean_code.replace('-', '').upper()
    code_hash = hashlib.sha256(norm_code.encode('utf-8')).hexdigest()
    hashes = json.loads(user['totp_recovery_hashes'] or '[]')

    matched_recovery_indexes = [i for i, saved_hash in enumerate(hashes) if hmac.compare_digest(code_hash, saved_hash)]
    if matched_recovery_indexes:
        hashes.pop(matched_recovery_indexes[0])
        c.execute("""
            UPDATE users
            SET totp_recovery_hashes = ?, failed_login_attempts = 0, locked_until = NULL
            WHERE id = ?
        """, (json.dumps(hashes), user_id))
        conn.commit()
        conn.close()

        record_successful_login(user_id, client_ip)
        log_security_event(user_id, 'mfa_recovery_used', f'Código de recuperação utilizado. Restam {len(hashes)} códigos.', client_ip)
        token = create_session(user_id, user['session_version'] if 'session_version' in user.keys() else 1)
        lic = get_license_info(user['license_expires_at'])
        return {
            "token": token,
            "used_recovery_code": True,
            "remaining_recovery_codes": len(hashes),
            "warning": f"Utilizou um código de recuperação descartável. Restam {len(hashes)} códigos disponíveis.",
            "user": {
                "id": user['id'],
                "role": user['role'],
                "nome_completo": user['nome_completo'],
                "numero_aluno": user['numero_aluno'],
                "email": user['email'],
                "telemovel": user['telemovel'],
                "allowed_categories": [cat.strip() for cat in user['allowed_categories'].split(',') if cat.strip()],
                "license": lic
            }
        }

    conn.close()
    record_failed_attempt(user_id, client_ip)
    log_security_event(user_id, 'mfa_recovery_failed', 'Tentativa com código de recuperação inválido.', client_ip)
    raise HTTPException(status_code=401, detail="Código de verificação ou de recuperação inválido.")

@app.post("/api/auth/mfa/regenerate-recovery-codes")
def regenerate_recovery_codes(req: MFARegenerateRequest, request: Request, admin: dict = Depends(get_admin_user)):
    if not verify_password(req.password, admin['password_hash']):
        log_security_event(admin['id'], 'mfa_regenerate_failed_password', 'Password incorreta ao tentar regenerar códigos.', get_client_ip(request))
        raise HTTPException(status_code=400, detail="Password de confirmação incorreta.")

    plain_recovery, recovery_hashes = generate_recovery_codes()
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET totp_recovery_hashes = ? WHERE id = ?", (json.dumps(recovery_hashes), admin['id']))
    conn.commit()
    conn.close()

    log_security_event(admin['id'], 'mfa_recovery_codes_regenerated', 'Novos códigos de recuperação gerados.', get_client_ip(request))
    return {
        "recovery_codes": plain_recovery,
        "message": "Novos códigos de recuperação gerados com sucesso. Guarde-os num local seguro."
    }

@app.post("/api/auth/logout")
def logout(user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET session_version = session_version + 1 WHERE id = ?", (user['id'],))
    conn.commit()
    conn.close()
    return {"message": "Sessão terminada com sucesso."}

@app.get("/api/auth/me")
def get_me(user: dict = Depends(get_current_user)):
    lic = get_license_info(user['license_expires_at'])
    return {
        "id": user['id'],
        "role": user['role'],
        "nome_completo": user['nome_completo'],
        "numero_aluno": user['numero_aluno'],
        "email": user['email'],
        "telemovel": user['telemovel'],
        "communications_consent": bool(user.get('marketing_consent', 0)),
        "allowed_categories": [cat.strip() for cat in user['allowed_categories'].split(',') if cat.strip()],
        "license": lic
    }

@app.put("/api/auth/profile")
def update_profile(req: UpdateProfileRequest, user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()
    # Check email duplicate
    c.execute("SELECT id FROM users WHERE LOWER(email) = LOWER(?) AND id != ?", (req.email.strip(), user['id']))
    if c.fetchone():
        conn.close()
        raise HTTPException(status_code=400, detail="Este email já está em uso por outro utilizador.")

    c.execute("""
    UPDATE users SET email = ?, telemovel = ? WHERE id = ?
    """, (req.email.strip().lower(), req.telemovel.strip(), user['id']))
    conn.commit()
    conn.close()
    return {"message": "Perfil atualizado com sucesso."}

@app.put("/api/auth/communications")
def update_communications(req: CommunicationsConsentRequest, user: dict = Depends(get_current_user)):
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET marketing_consent = ?, marketing_consent_at = ? WHERE id = ?", (1 if req.consent else 0, now_str if req.consent else None, user['id']))
    conn.commit()
    conn.close()
    return {"message": "Preferência de comunicações atualizada.", "communications_consent": req.consent}

@app.put("/api/auth/password")
def update_password(req: UpdatePasswordRequest, user: dict = Depends(get_current_user)):
    if not verify_password(req.current_password, user['password_hash']):
        raise HTTPException(status_code=400, detail="Password atual incorreta.")

    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="A nova password deve ter pelo menos 6 caracteres.")

    conn = get_connection()
    c = conn.cursor()
    new_version = (user['session_version'] or 1) + 1
    c.execute("UPDATE users SET password_hash = ?, session_version = ? WHERE id = ?", (hash_password(req.new_password), new_version, user['id']))
    conn.commit()
    conn.close()

    new_token = create_session(user['id'], new_version)
    return {"message": "Password alterada com sucesso. Sessões anteriores revogadas.", "token": new_token}

@app.post("/api/auth/recover-password")
def recover_password(req: RecoverPasswordRequest, request: Request):
    client_ip = get_client_ip(request)
    email_clean = req.email.strip().lower()

    conn = get_connection()
    c = conn.cursor()
    now = datetime.now()
    since = (now - timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute("SELECT COUNT(*) FROM password_reset_tokens WHERE created_at >= ?", (since,))
    if c.fetchone()[0] >= 30:
        conn.close()
        raise HTTPException(status_code=429, detail="Demasiados pedidos de recuperação. Tente mais tarde.")

    c.execute("SELECT * FROM users WHERE LOWER(email) = ?", (email_clean,))
    user = c.fetchone()

    raw_token = None
    if user:
        raw_token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
        expires_at = (now + timedelta(minutes=15)).strftime('%Y-%m-%d %H:%M:%S')
        now_str = now.strftime('%Y-%m-%d %H:%M:%S')

        c.execute("""
            INSERT INTO password_reset_tokens (user_id, token_hash, expires_at, used, created_at)
            VALUES (?, ?, ?, 0, ?)
        """, (user['id'], token_hash, expires_at, now_str))
        conn.commit()
        log_security_event(user['id'], 'password_reset_requested', 'Pedido de recuperação de password.', client_ip)

        if APP_ENV == 'production':
            smtp_host = os.environ.get('SMTP_HOST')
            smtp_user = os.environ.get('SMTP_USER')
            smtp_password = os.environ.get('SMTP_PASSWORD')
            smtp_from = os.environ.get('SMTP_FROM')
            smtp_port = int(os.environ.get('SMTP_PORT', '465'))
            if all([smtp_host, smtp_from]):
                domain = os.environ.get('DOMAIN', 'cartaautotestes.pt')
                reset_url = f"https://{domain}/#reset={raw_token}"
                message = EmailMessage()
                message['Subject'] = "Recuperação de acesso — Carta Auto Testes"
                message['From'] = smtp_from
                message['To'] = user['email']
                message.set_content(f"Olá {user['nome_completo']},\n\nRecebemos um pedido para repor a password.\nAceda à ligação para definir uma nova password (válida por 15 min):\n{reset_url}\n\nCódigo: {raw_token}")
                try:
                    if smtp_port == 465:
                        with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=20) as smtp:
                            if smtp_user:
                                smtp.login(smtp_user, smtp_password or '')
                            smtp.send_message(message)
                    else:
                        with smtplib.SMTP(smtp_host, smtp_port, timeout=20) as smtp:
                            smtp.starttls()
                            if smtp_user:
                                smtp.login(smtp_user, smtp_password or '')
                            smtp.send_message(message)
                except Exception:
                    pass

    conn.close()
    resp = {"message": "Se o email estiver registado, receberá instruções para recuperar o acesso."}
    if APP_ENV != 'production' and raw_token:
        resp["debug_reset_token"] = raw_token
    return resp

@app.post("/api/auth/reset-password")
def reset_password(req: ResetPasswordConfirmRequest, request: Request):
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="A nova password deve ter pelo menos 6 caracteres.")

    clean_token = req.token.strip()
    token_hash = hashlib.sha256(clean_token.encode('utf-8')).hexdigest()
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM password_reset_tokens WHERE token_hash = ? AND used = 0", (token_hash,))
    rec = c.fetchone()

    if not rec:
        conn.close()
        raise HTTPException(status_code=400, detail="Código de recuperação inválido ou já utilizado.")

    if rec['expires_at'] < now_str:
        conn.close()
        raise HTTPException(status_code=400, detail="O código de recuperação expirou. Solicite um novo.")

    user_id = rec['user_id']
    c.execute("UPDATE password_reset_tokens SET used = 1 WHERE id = ?", (rec['id'],))
    c.execute("""
        UPDATE users
        SET password_hash = ?, session_version = session_version + 1, failed_login_attempts = 0, locked_until = NULL
        WHERE id = ?
    """, (hash_password(req.new_password), user_id))
    conn.commit()
    conn.close()

    log_security_event(user_id, 'password_reset_completed', 'Password redefinida com sucesso.', get_client_ip(request))
    return {"message": "Password redefinida com sucesso. Pode iniciar sessão."}


# ----------------- SERVER-SIDE FAVORITES -----------------

@app.get("/api/favorites")
def get_favorites(user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        SELECT q.id, q.original_id, q.categoria, q.tema, q.prompt, q.options, q.correct_letter, q.image_path,
               f.created_at as favorited_at
        FROM student_favorites f
        JOIN questions q ON q.id = f.question_id
        WHERE f.user_id = ?
        ORDER BY f.created_at DESC
    """, (user['id'],))
    items = []
    for r in c.fetchall():
        item = dict(r)
        item['options'] = json.loads(item['options'])
        items.append(item)
    conn.close()
    return items

@app.get("/api/favorites/ids")
def get_favorite_ids(user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT question_id FROM student_favorites WHERE user_id = ?", (user['id'],))
    ids = [r[0] for r in c.fetchall()]
    conn.close()
    return {"favorite_ids": ids}

@app.post("/api/favorites/{question_id}")
def add_favorite(question_id: int, user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM questions WHERE id = ?", (question_id,))
    if not c.fetchone():
        conn.close()
        raise HTTPException(status_code=404, detail="Pergunta não encontrada.")

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("""
        INSERT OR IGNORE INTO student_favorites (user_id, question_id, created_at)
        VALUES (?, ?, ?)
    """, (user['id'], question_id, now_str))
    conn.commit()
    conn.close()
    return {"message": "Pergunta adicionada aos favoritos.", "favorited": True, "question_id": question_id}

@app.delete("/api/favorites/{question_id}")
def remove_favorite(question_id: int, user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM student_favorites WHERE user_id = ? AND question_id = ?", (user['id'], question_id))
    conn.commit()
    conn.close()
    return {"message": "Pergunta removida dos favoritos.", "favorited": False, "question_id": question_id}

# ----------------- CATEGORIES & THEMES -----------------

@app.get("/api/categories")
def get_categories(user: dict = Depends(get_current_user)):
    allowed = [cat.strip() for cat in user['allowed_categories'].split(',') if cat.strip()]
    if user['role'] == 'ADMIN':
        allowed = ['A', 'B', 'C', 'D']

    category_meta = {
        'A': {'name': 'Categoria A', 'desc': 'Motociclos e Ciclomotores', 'icon': 'bike'},
        'B': {'name': 'Categoria B', 'desc': 'Automóveis Ligeiros', 'icon': 'car'},
        'C': {'name': 'Categoria C', 'desc': 'Pesados de Mercadorias', 'icon': 'truck'},
        'D': {'name': 'Categoria D', 'desc': 'Pesados de Passageiros (Autocarros)', 'icon': 'bus'}
    }

    conn = get_connection()
    c = conn.cursor()

    result = []
    for cat_code in ['A', 'B', 'C', 'D']:
        if cat_code not in allowed:
            continue
        meta = category_meta[cat_code]
        c.execute("SELECT COUNT(*) FROM questions WHERE categoria = ?", (cat_code,))
        total_q = c.fetchone()[0]

        if cat_code == 'A':
            c.execute("""
                SELECT tema, COUNT(*) as cnt, categoria FROM questions
                WHERE categoria IN ('A', 'B')
                GROUP BY categoria, tema
                ORDER BY categoria ASC, tema ASC
            """)
            themes = []
            for row in c.fetchall():
                prefix = "[Comum B] " if row['categoria'] == 'B' else "[Específico A] "
                themes.append({
                    "tema": row['tema'],
                    "display_name": f"{prefix}{row['tema']}",
                    "count": row['cnt'],
                    "categoria": row['categoria']
                })
        else:
            c.execute("SELECT tema, COUNT(*) as cnt FROM questions WHERE categoria = ? GROUP BY tema ORDER BY tema", (cat_code,))
            themes = [{"tema": row['tema'], "display_name": row['tema'], "count": row['cnt'], "categoria": cat_code} for row in c.fetchall()]

        result.append({
            "code": cat_code,
            "name": meta['name'],
            "desc": meta['desc'],
            "icon": meta['icon'],
            "total_questions": total_q,
            "themes": themes
        })

    conn.close()
    return result

# ----------------- TEST ENGINE -----------------

@app.post("/api/tests/start")
def start_test(req: StartTestRequest, user: dict = Depends(get_current_user)):
    # 1. License Check
    if user['role'] != 'ADMIN':
        lic = get_license_info(user['license_expires_at'])
        if lic['is_expired']:
            raise HTTPException(
                status_code=403,
                detail="A sua licença expirou. Contacte a secretaria para renovação."
            )

    # 2. Category Access Check
    allowed = [cat.strip() for cat in user['allowed_categories'].split(',') if cat.strip()]
    if user['role'] != 'ADMIN' and req.categoria.upper() not in allowed:
        raise HTTPException(
            status_code=403,
            detail=f"Não possui autorização para a Categoria {req.categoria.upper()}."
        )

    cat = req.categoria.upper()
    conn = get_connection()
    c = conn.cursor()

    # Official theory-exam sizes and passing thresholds (RHLC Article 43/47).
    exam_config = {'A': (40, 4), 'B': (30, 3), 'C': (20, 2), 'D': (20, 2)}
    if cat not in exam_config:
        conn.close()
        raise HTTPException(status_code=400, detail="Categoria inválida.")
    num_q, official_errors = exam_config[cat]
    # Category A can be 10 questions for candidates already holding B/B1.
    if cat == 'A' and req.num_questions == 10:
        num_q, official_errors = 10, 1
    selected_themes = [t.strip() for t in (req.temas or []) if t.strip()]
    if req.tema and req.tema.strip() and req.tema.strip() not in selected_themes:
        selected_themes.append(req.tema.strip())
    if req.test_type == 'tematico' and not selected_themes:
        conn.close()
        raise HTTPException(status_code=400, detail="Selecione pelo menos um tema para o teste temático.")

    # Select questions using the same category pool, balanced across topics.
    # "Erradas" means the most recent answer was wrong; "Novas" excludes seen questions.
    source_categories = ['A', 'B'] if (cat == 'A' and (num_q == 40 or req.test_type == 'tematico')) else [cat]
    category_placeholders = ','.join('?' for _ in source_categories)
    c.execute(f"""
        SELECT q.id, q.original_id, q.categoria, q.tema, q.prompt, q.options, q.image_path,
               q.times_failed AS platform_fails,
               COALESCE(s.times_seen, 0) AS student_seen,
               COALESCE(s.times_failed, 0) AS student_fails,
               COALESCE(s.last_correct, 1) AS last_correct,
               COALESCE(s.last_seen_at, '') AS last_seen_at
        FROM questions q
        LEFT JOIN student_question_stats s ON s.question_id = q.id AND s.user_id = ?
        WHERE q.categoria IN ({category_placeholders})
    """, [user['id']] + source_categories)
    candidates = [dict(row) for row in c.fetchall()]
    if req.test_type == 'tematico':
        candidates = [q for q in candidates if q['tema'] in selected_themes]
    elif req.test_type == 'nao_vistas':
        candidates = [q for q in candidates if q['student_seen'] == 0]
    elif req.test_type == 'erradas':
        candidates = [q for q in candidates if q['student_seen'] > 0 and q['last_correct'] == 0]

    if req.test_type == 'erradas':
        candidates.sort(key=lambda q: q['last_seen_at'], reverse=True)
    elif req.test_type == 'mais_erradas':
        candidates.sort(key=lambda q: (q['student_seen'] > 0, -q['platform_fails'], random.random()))
    else:
        random.shuffle(candidates)
        candidates.sort(key=lambda q: q['student_seen'] > 0)

    def balanced_pick(pool: List[dict], amount: int) -> List[dict]:
        by_theme: Dict[str, List[dict]] = {}
        for question in pool:
            by_theme.setdefault(question['tema'] or 'Outros', []).append(question)
        theme_order = list(by_theme.keys())
        random.shuffle(theme_order)
        picked = []
        while len(picked) < amount and any(by_theme.values()):
            for topic in theme_order:
                if by_theme[topic] and len(picked) < amount:
                    picked.append(by_theme[topic].pop(0))
        return picked

    if cat == 'A' and num_q == 40 and req.test_type != 'tematico':
        # A+B exam: 30 common questions from B and 10 motorcycle-specific questions from A.
        a_questions = balanced_pick([q for q in candidates if q['categoria'] == 'A'], 10)
        b_questions = balanced_pick([q for q in candidates if q['categoria'] == 'B'], 30)
        selected_questions = []
        for i in range(max(len(a_questions), len(b_questions))):
            if i < len(b_questions):
                selected_questions.append(b_questions[i])
            if i < len(a_questions):
                selected_questions.append(a_questions[i])
    else:
        selected_questions = balanced_pick(candidates, num_q)
    actual_count = len(selected_questions)
    if actual_count == 0:
        conn.close()
        if req.test_type == 'nao_vistas':
            raise HTTPException(status_code=404, detail="Já respondeu a todas as perguntas disponíveis nesta categoria.")
        if req.test_type == 'erradas':
            raise HTTPException(status_code=404, detail="Ainda não tem perguntas erradas para treinar.")
        raise HTTPException(status_code=404, detail="Não foram encontradas perguntas para esta seleção.")

    actual_max_errors = official_errors if actual_count == num_q else max(1, round(official_errors * actual_count / num_q))
    official_minutes = 40 if cat == 'A' and num_q == 40 else 10 if cat == 'A' else 30 if cat == 'B' else 25
    actual_time_limit = round(actual_count * official_minutes * 60 / num_q)
    test_theme = ', '.join(selected_themes) if selected_themes else None
    selected_ids = [q['id'] for q in selected_questions]

    # Insert test record with question_ids
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("""
    INSERT INTO tests (user_id, categoria, test_type, tema, total_questions, max_errors_allowed, correct_count, error_count, passed, duration_seconds, created_at, question_ids)
    VALUES (?, ?, ?, ?, ?, ?, 0, 0, 0, 0, ?, ?)
    RETURNING id
    """, (
        user['id'],
        cat,
        req.test_type,
        test_theme,
        actual_count,
        actual_max_errors,
        now_str,
        json.dumps(selected_ids)
    ))
    test_id = c.fetchone()[0] if USE_POSTGRES else c.lastrowid
    conn.commit()
    conn.close()

    # Format questions (do not leak correct letter!)
    formatted_questions = []
    for q in selected_questions:
        opts_raw = json.loads(q['options'])
        clean_opts = [{'letter': o['letter'], 'text': o['text']} for o in opts_raw]
        formatted_questions.append({
            'id': q['id'],
            'original_id': q['original_id'],
            'categoria': q['categoria'],
            'tema': q['tema'],
            'prompt': q['prompt'],
            'image_path': q.get('image_path'),
            'options': clean_opts
        })

    return {
        "test_id": test_id,
        "categoria": cat,
        "test_type": req.test_type,
        "tema": req.tema,
        "total_questions": actual_count,
        "max_errors_allowed": actual_max_errors,
        "time_limit_seconds": actual_time_limit,
        "questions": formatted_questions
    }

@app.post("/api/tests/{test_id}/submit")
def submit_test(test_id: int, req: SubmitTestRequest, user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM tests WHERE id = ? AND user_id = ?", (test_id, user['id']))
    test_rec = c.fetchone()
    if not test_rec:
        conn.close()
        raise HTTPException(status_code=404, detail="Teste não encontrado.")

    test_rec = dict(test_rec)
    saved_question_ids = json.loads(test_rec['question_ids']) if test_rec.get('question_ids') else list(map(int, req.answers.keys()))

    correct_count = 0
    error_count = 0
    review_items = []
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    for qid in saved_question_ids:
        selected_letter = req.answers.get(str(qid)) or req.answers.get(qid)
        if selected_letter:
            selected_letter = str(selected_letter).strip().upper()

        c.execute("SELECT * FROM questions WHERE id = ?", (qid,))
        q_row = c.fetchone()
        if not q_row:
            continue
        q_row = dict(q_row)

        correct_letter = q_row['correct_letter']
        is_corr = 1 if (selected_letter and selected_letter == correct_letter.upper()) else 0

        if is_corr:
            correct_count += 1
        else:
            error_count += 1

        # Record test answer (unanswered questions recorded as selected_option = None)
        c.execute("""
        INSERT INTO test_answers (test_id, user_id, question_id, selected_option, correct_option, is_correct)
        VALUES (?, ?, ?, ?, ?, ?)
        """, (test_id, user['id'], qid, selected_letter, correct_letter, is_corr))

        # Update global question stats
        c.execute("""
        UPDATE questions SET times_asked = times_asked + 1, times_failed = times_failed + ? WHERE id = ?
        """, (0 if is_corr else 1, qid))

        # Update student question stats
        c.execute("""
        INSERT INTO student_question_stats (user_id, question_id, times_seen, times_failed, last_seen_at, last_correct)
        VALUES (?, ?, 1, ?, ?, ?)
        ON CONFLICT(user_id, question_id) DO UPDATE SET
            times_seen = student_question_stats.times_seen + 1,
            times_failed = student_question_stats.times_failed + excluded.times_failed,
            last_seen_at = excluded.last_seen_at,
            last_correct = excluded.last_correct
        """, (user['id'], qid, 0 if is_corr else 1, now_str, 1 if is_corr else 0))

        options_parsed = json.loads(q_row['options'])
        review_items.append({
            'question_id': qid,
            'original_id': q_row['original_id'],
            'categoria': q_row['categoria'],
            'tema': q_row['tema'],
            'prompt': q_row['prompt'],
            'image_path': q_row.get('image_path'),
            'options': options_parsed,
            'selected_option': selected_letter,
            'correct_option': correct_letter,
            'is_correct': bool(is_corr)
        })

    total_q = test_rec['total_questions']
    max_errors = test_rec['max_errors_allowed']
    passed = 1 if error_count <= max_errors else 0

    c.execute("""
    UPDATE tests
    SET correct_count = ?, error_count = ?, passed = ?, duration_seconds = ?
    WHERE id = ?
    """, (correct_count, error_count, passed, req.duration_seconds, test_id))

    conn.commit()
    conn.close()

    return {
        "test_id": test_id,
        "passed": bool(passed),
        "status_label": "APROVADO" if passed else "REPROVADO",
        "correct_count": correct_count,
        "error_count": error_count,
        "total_questions": total_q,
        "max_errors_allowed": max_errors,
        "duration_seconds": req.duration_seconds,
        "review": review_items
    }

# ----------------- TEST HISTORY & REVIEW -----------------

@app.get("/api/tests/my-tests")
def get_my_tests(user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
    SELECT id, categoria, test_type, tema, total_questions, max_errors_allowed, correct_count, error_count, passed, duration_seconds, created_at
    FROM tests
    WHERE user_id = ?
    ORDER BY id DESC
    """, (user['id'],))
    tests = [dict(row) for row in c.fetchall()]
    conn.close()
    return tests

@app.get("/api/tests/{test_id}/review")
def review_test(test_id: int, user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM tests WHERE id = ? AND (user_id = ? OR ? = 'ADMIN')", (test_id, user['id'], user['role']))
    test_rec = c.fetchone()
    if not test_rec:
        conn.close()
        raise HTTPException(status_code=404, detail="Teste não encontrado.")

    c.execute("""
    SELECT ta.selected_option, ta.correct_option, ta.is_correct,
           q.id as question_id, q.original_id, q.categoria, q.tema, q.prompt, q.options, q.image_path
    FROM test_answers ta
    JOIN questions q ON q.id = ta.question_id
    WHERE ta.test_id = ?
    ORDER BY ta.id ASC
    """, (test_id,))
    answers = []
    for row in c.fetchall():
        answers.append({
            'question_id': row['question_id'],
            'original_id': row['original_id'],
            'categoria': row['categoria'],
            'tema': row['tema'],
            'prompt': row['prompt'],
            'image_path': dict(row).get('image_path'),
            'options': json.loads(row['options']),
            'selected_option': row['selected_option'],
            'correct_option': row['correct_option'],
            'is_correct': bool(row['is_correct'])
        })

    conn.close()
    return {
        "test": dict(test_rec),
        "answers": answers
    }

# ----------------- FAILED QUESTIONS & STATS -----------------

@app.get("/api/stats/my-failed-questions")
def get_my_failed_questions(categoria: Optional[str] = None, user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()

    query = """
    SELECT q.id, q.original_id, q.categoria, q.tema, q.prompt, q.options, q.correct_letter, q.image_path,
           s.times_failed, s.times_seen, s.last_seen_at
    FROM student_question_stats s
    JOIN questions q ON q.id = s.question_id
    WHERE s.user_id = ? AND s.times_failed > 0
    """
    params = [user['id']]
    if categoria:
        query += " AND q.categoria = ?"
        params.append(categoria.upper())

    query += " ORDER BY s.times_failed DESC, s.last_seen_at DESC"
    c.execute(query, params)
    rows = []
    for r in c.fetchall():
        rows.append({
            'id': r['id'],
            'original_id': r['original_id'],
            'categoria': r['categoria'],
            'tema': r['tema'],
            'prompt': r['prompt'],
            'image_path': r['image_path'],
            'options': json.loads(r['options']),
            'correct_letter': r['correct_letter'],
            'times_failed': r['times_failed'],
            'times_seen': r['times_seen'],
            'last_seen_at': r['last_seen_at']
        })

    conn.close()
    return rows

@app.get("/api/stats/student-summary")
def get_student_summary(user: dict = Depends(get_current_user)):
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) AS total_tests, SUM(passed) AS total_passed, SUM(correct_count) AS total_correct, SUM(error_count) AS total_errors, SUM(total_questions) AS total_q FROM tests WHERE user_id = ?", (user['id'],))
    totals = c.fetchone()
    total_tests, total_passed, total_correct, total_errors, total_q = (totals[i] for i in range(5))
    total_tests = total_tests or 0
    total_passed = total_passed or 0
    total_correct = total_correct or 0
    total_errors = total_errors or 0
    total_q = total_q or 0
    approval_rate = round((total_passed / total_tests * 100), 1) if total_tests > 0 else 0
    average_score = round((total_correct / total_q * 100), 1) if total_q > 0 else 0

    c.execute("SELECT MAX(ROUND((CAST(correct_count AS NUMERIC) / NULLIF(total_questions, 0)) * 100, 1)) FROM tests WHERE user_id = ?", (user['id'],))
    best_row = c.fetchone()
    best_score = best_row[0] if best_row and best_row[0] is not None else 0

    c.execute("SELECT COUNT(*) FROM student_question_stats WHERE user_id = ? AND times_failed > 0", (user['id'],))
    failed_unique = c.fetchone()[0] or 0

    c.execute("""
    SELECT id, categoria, test_type, total_questions, correct_count, error_count, passed, duration_seconds, created_at
    FROM tests WHERE user_id = ? ORDER BY id DESC LIMIT 10
    """, (user['id'],))
    recent_tests = [dict(r) for r in c.fetchall()]

    c.execute("""
    SELECT categoria, COUNT(*) as count, SUM(passed) as passed,
           ROUND(AVG((CAST(correct_count AS NUMERIC) / NULLIF(total_questions, 0)) * 100), 1) as avg_percent
    FROM tests WHERE user_id = ? GROUP BY categoria
    """, (user['id'],))
    cat_perf = [dict(r) for r in c.fetchall()]

    c.execute("""
    SELECT q.tema, COUNT(*) as total_asked, SUM(ta.is_correct) as total_correct
    FROM test_answers ta
    JOIN questions q ON q.id = ta.question_id
    WHERE ta.user_id = ?
    GROUP BY q.tema
    ORDER BY total_asked DESC LIMIT 10
    """, (user['id'],))
    theme_perf = []
    for r in c.fetchall():
        asked = r['total_asked'] or 0
        corr = r['total_correct'] or 0
        pct = round(corr / asked * 100, 1) if asked > 0 else 0
        theme_perf.append({"tema": r['tema'], "total_asked": asked, "total_correct": corr, "accuracy_percent": pct})

    conn.close()
    lic = get_license_info(user['license_expires_at'])

    return {
        "license": lic,
        "total_tests": total_tests,
        "total_passed": total_passed,
        "approval_rate": approval_rate,
        "average_score": average_score,
        "best_score": best_score,
        "total_correct": total_correct,
        "total_errors": total_errors,
        "unique_failed_questions": failed_unique,
        "recent_tests": recent_tests,
        "category_performance": cat_perf,
        "theme_performance": theme_perf
    }

# ----------------- ADMIN ENDPOINTS -----------------

@app.get("/api/admin/overview")
def admin_overview(admin: dict = Depends(get_admin_user)):
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT COUNT(*) FROM users WHERE role = 'ALUNO'")
    total_students = c.fetchone()[0] or 0

    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("SELECT COUNT(*) FROM users WHERE role = 'ALUNO' AND license_expires_at >= ?", (now_str,))
    active_licenses = c.fetchone()[0] or 0
    expired_licenses = total_students - active_licenses

    renew_deadline = (datetime.now() + timedelta(days=10)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute("SELECT COUNT(*) FROM users WHERE role = 'ALUNO' AND license_expires_at <= ?", (renew_deadline,))
    pending_renewals = c.fetchone()[0] or 0

    c.execute("SELECT COUNT(*) AS total_tests, SUM(passed) AS total_passed FROM tests")
    totals = c.fetchone()
    total_tests, total_passed = totals[0], totals[1]
    total_tests = total_tests or 0
    total_passed = total_passed or 0
    approval_rate = round((total_passed / total_tests * 100), 1) if total_tests > 0 else 0

    today_prefix = datetime.now().strftime('%Y-%m-%d')
    c.execute("SELECT COUNT(*) FROM tests WHERE created_at LIKE ?", (f"{today_prefix}%",))
    tests_today = c.fetchone()[0] or 0

    c.execute("SELECT categoria, COUNT(*) as count FROM tests GROUP BY categoria ORDER BY count DESC")
    most_used_cats = [{"categoria": r[0], "count": r[1]} for r in c.fetchall()]

    c.execute("""
    SELECT id, original_id, categoria, tema, prompt, times_asked, times_failed, image_path
    FROM questions WHERE times_failed > 0
    ORDER BY times_failed DESC LIMIT 10
    """)
    most_failed = [dict(r) for r in c.fetchall()]

    conn.close()
    return {
        "total_students": total_students,
        "active_licenses": active_licenses,
        "expired_licenses": expired_licenses,
        "pending_renewals": pending_renewals,
        "total_tests": total_tests,
        "tests_today": tests_today,
        "total_passed": total_passed,
        "global_approval_rate": approval_rate,
        "most_used_categories": most_used_cats,
        "most_failed_questions": most_failed
    }

@app.get("/api/admin/students")
def admin_get_students(
    search: Optional[str] = None,
    status: Optional[str] = None,
    admin: dict = Depends(get_admin_user)
):
    conn = get_connection()
    c = conn.cursor()

    query = """
        SELECT u.id, u.nome_completo, u.numero_aluno, u.email, u.telemovel,
           u.created_at, u.last_login_at, u.marketing_consent, u.license_expires_at, u.allowed_categories, u.is_active,
           COUNT(t.id) as total_tests,
           SUM(CASE WHEN t.passed = 1 THEN 1 ELSE 0 END) as passed_tests
    FROM users u
    LEFT JOIN tests t ON t.user_id = u.id
    WHERE u.role = 'ALUNO'
    """
    params = []

    if search:
        s = f"%{search.strip().lower()}%"
        query += " AND (LOWER(u.nome_completo) LIKE ? OR LOWER(u.numero_aluno) LIKE ? OR LOWER(u.email) LIKE ? OR LOWER(u.telemovel) LIKE ?)"
        params.extend([s, s, s, s])

    query += " GROUP BY u.id ORDER BY u.id DESC"
    c.execute(query, params)

    students = []
    for r in c.fetchall():
        st_dict = dict(r)
        lic = get_license_info(st_dict['license_expires_at'])
        if status == 'active' and lic['is_expired']:
            continue
        if status == 'expired' and not lic['is_expired']:
            continue

        st_dict['license'] = lic
        st_dict['allowed_categories'] = [cat.strip() for cat in st_dict['allowed_categories'].split(',') if cat.strip()]
        total_t = st_dict['total_tests'] or 0
        passed_t = st_dict['passed_tests'] or 0
        st_dict['approval_rate'] = round((passed_t / total_t * 100), 1) if total_t > 0 else 0
        students.append(st_dict)

    conn.close()
    return students

@app.get("/api/admin/students/{user_id}")
def admin_get_student_detail(user_id: int, admin: dict = Depends(get_admin_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ? AND role = 'ALUNO'", (user_id,))
    st = c.fetchone()
    if not st:
        conn.close()
        raise HTTPException(status_code=404, detail="Aluno não encontrado.")

    student = dict(st)
    lic = get_license_info(student['license_expires_at'])
    student['license'] = lic
    student['allowed_categories'] = [cat.strip() for cat in student['allowed_categories'].split(',') if cat.strip()]

    c.execute("SELECT COUNT(*) AS total_tests, SUM(passed) AS total_passed, SUM(correct_count) AS total_correct, SUM(error_count) AS total_errors FROM tests WHERE user_id = ?", (user_id,))
    totals = c.fetchone()
    total_tests, total_passed, total_correct, total_errors = (totals[i] for i in range(4))
    total_tests = total_tests or 0
    total_passed = total_passed or 0
    approval_rate = round((total_passed / total_tests * 100), 1) if total_tests > 0 else 0

    c.execute("""
        SELECT id, categoria, test_type, tema, total_questions, max_errors_allowed, correct_count, error_count, passed, duration_seconds, created_at
        FROM tests WHERE user_id = ? ORDER BY id DESC LIMIT 50
    """, (user_id,))
    tests = [dict(r) for r in c.fetchall()]

    conn.close()
    student.pop('password_hash', None)
    student.pop('totp_secret_enc', None)
    student.pop('totp_temp_secret_enc', None)
    student.pop('totp_recovery_hashes', None)

    return {
        "student": student,
        "stats": {
            "total_tests": total_tests,
            "total_passed": total_passed,
            "approval_rate": approval_rate,
            "total_correct": total_correct or 0,
            "total_errors": total_errors or 0
        },
        "tests": tests
    }

@app.delete("/api/admin/students/{user_id}")
def admin_delete_student(user_id: int, admin: dict = Depends(get_admin_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, role, nome_completo FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    if not user:
        conn.close()
        raise HTTPException(status_code=404, detail="Utilizador não encontrado.")
    if user['role'] == 'ADMIN' or str(user['email']).lower() == 'candidoshacal@gmail.com':
        conn.close()
        raise HTTPException(status_code=400, detail="Não é permitido eliminar contas de Administrador.")

    c.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return {"message": f"Aluno '{user['nome_completo']}' eliminado com sucesso."}

@app.post("/api/admin/students/{user_id}/renew")
def admin_renew_license(user_id: int, req: RenewLicenseRequest, admin: dict = Depends(get_admin_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ? AND role = 'ALUNO'", (user_id,))
    st = c.fetchone()
    if not st:
        conn.close()
        raise HTTPException(status_code=404, detail="Aluno não encontrado.")

    days_to_add = 60
    if req.months_or_years == '6m':
        days_to_add = 180
    elif req.months_or_years == '1y':
        days_to_add = 365

    now = datetime.now()
    try:
        curr_expires = datetime.strptime(st['license_expires_at'], '%Y-%m-%d %H:%M:%S')
    except Exception:
        curr_expires = now

    base_date = now if curr_expires < now else curr_expires
    new_expires = base_date + timedelta(days=days_to_add)
    new_expires_str = new_expires.strftime('%Y-%m-%d %H:%M:%S')

    c.execute("UPDATE users SET license_expires_at = ?, is_active = 1 WHERE id = ?", (new_expires_str, user_id))
    conn.commit()
    conn.close()

    return {
        "message": f"Licença renovada por {days_to_add} dias.",
        "new_expiration": new_expires_str,
        "license": get_license_info(new_expires_str)
    }

@app.put("/api/admin/students/{user_id}/categories")
def admin_update_categories(user_id: int, req: UpdateCategoriesRequest, admin: dict = Depends(get_admin_user)):
    valid_cats = {'A', 'B', 'C', 'D'}
    chosen = [c.upper() for c in req.categories if c.upper() in valid_cats]
    cats_str = ','.join(sorted(chosen))
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET allowed_categories = ? WHERE id = ? AND role = 'ALUNO'", (cats_str, user_id))
    conn.commit()
    conn.close()

    return {"message": "Categorias atualizadas com sucesso.", "allowed_categories": chosen}

@app.put("/api/admin/students/{user_id}/toggle-active")
def admin_toggle_active(user_id: int, admin: dict = Depends(get_admin_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT is_active, email FROM users WHERE id = ? AND role = 'ALUNO'", (user_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Aluno não encontrado.")

    if str(row['email']).lower() == 'candidoshacal@gmail.com':
        conn.close()
        raise HTTPException(status_code=400, detail="A conta principal não pode ser bloqueada.")
    new_val = 0 if row['is_active'] == 1 else 1
    c.execute("UPDATE users SET is_active = ?, session_version = session_version + 1 WHERE id = ?", (new_val, user_id))
    conn.commit()
    conn.close()
    return {"message": f"Estado atualizado para {'Ativo' if new_val == 1 else 'Desativado'}.", "is_active": new_val}

@app.post("/api/admin/students/{user_id}/reset-password")
def admin_reset_password(user_id: int, req: AdminResetPasswordRequest, admin: dict = Depends(get_admin_user)):
    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="A password deve ter pelo menos 6 caracteres.")
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET password_hash = ?, session_version = session_version + 1 WHERE id = ? AND role = 'ALUNO'", (hash_password(req.new_password), user_id))
    conn.commit()
    conn.close()
    return {"message": "Password do aluno alterada com sucesso."}

# ----------------- ADMIN QUESTION MANAGEMENT -----------------

@app.get("/api/admin/questions")
def admin_list_questions(categoria: Optional[str] = None, q: Optional[str] = None, limit: int = 100, offset: int = 0, admin: dict = Depends(get_admin_user)):
    limit = max(1, min(limit, 250))
    conn = get_connection()
    c = conn.cursor()
    sql = "SELECT id, original_id, categoria, tema, prompt, options, correct_letter, image_path FROM questions WHERE 1=1"
    params = []
    if categoria and categoria.upper() in {'A','B','C','D'}:
        sql += " AND categoria = ?"
        params.append(categoria.upper())
    if q and q.strip():
        sql += " AND (prompt LIKE ? OR tema LIKE ? OR CAST(original_id AS TEXT) LIKE ?)"
        term = f"%{q.strip()}%"
        params.extend([term, term, term])
    c.execute("SELECT COUNT(*) FROM (" + sql + ")", params)
    total = c.fetchone()[0]
    c.execute(sql + " ORDER BY categoria, original_id, id LIMIT ? OFFSET ?", params + [limit, max(0, offset)])
    rows = []
    for r in c.fetchall():
        item = dict(r)
        item['options'] = json.loads(item['options'])
        rows.append(item)
    conn.close()
    return {"items": rows, "total": total, "limit": limit, "offset": max(0, offset)}

@app.get("/api/admin/questions/{question_id}")
def admin_get_question(question_id: int, admin: dict = Depends(get_admin_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, original_id, categoria, tema, prompt, options, correct_letter, image_path FROM questions WHERE id=?", (question_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Pergunta não encontrada.")
    result = dict(row)
    result['options'] = json.loads(result['options'])
    return result

@app.post("/api/admin/questions/upload-image")
async def admin_upload_question_image(file: UploadFile = File(...), admin: dict = Depends(get_admin_user)):
    ext = os.path.splitext(file.filename)[1].lower()
    allowed = {'.png', '.jpg', '.jpeg', '.webp', '.svg'}
    if ext not in allowed:
        raise HTTPException(status_code=400, detail="Formato de imagem não suportado.")
    content = await file.read()
    if len(content) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="A imagem excede 5 MB.")

    img_dir = os.path.join(STATIC_DIR, 'assets', 'questions')
    os.makedirs(img_dir, exist_ok=True)
    filename = f"q_{secrets.token_hex(8)}{ext}"
    dest_path = os.path.join(img_dir, filename)
    with open(dest_path, 'wb') as f:
        f.write(content)

    return {"image_path": f"/static/assets/questions/{filename}", "message": "Imagem carregada com sucesso."}

@app.post("/api/admin/questions")
def admin_create_question(req: AdminQuestionRequest, admin: dict = Depends(get_admin_user)):
    cat = req.categoria.upper()
    letter = req.correct_letter.upper()
    if cat not in {'A','B','C','D'} or not req.prompt.strip() or not req.tema.strip():
        raise HTTPException(status_code=400, detail="Categoria, tema e pergunta são obrigatórios.")
    letters = [str(o.get('letter','')).upper() for o in req.options]
    if len(req.options) < 2 or letter not in letters:
        raise HTTPException(status_code=400, detail="Indique pelo menos duas opções e uma resposta correta válida.")
    options = [{"letter": str(o.get('letter','')).upper(), "text": str(o.get('text','')).strip(), "is_correct": str(o.get('letter','')).upper() == letter} for o in req.options]
    if any(not o['text'] for o in options) or len(set(letters)) != len(letters):
        raise HTTPException(status_code=400, detail="As opções têm de ser únicas e não vazias.")

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO questions (categoria, tema, prompt, options, correct_letter, image_path)
        VALUES (?, ?, ?, ?, ?, ?)
        RETURNING id
    """, (cat, req.tema.strip(), req.prompt.strip(), json.dumps(options, ensure_ascii=False), letter, req.image_path))
    qid = c.fetchone()[0] if USE_POSTGRES else c.lastrowid
    conn.commit()
    conn.close()
    return {"id": qid, "message": "Pergunta adicionada."}

@app.put("/api/admin/questions/{question_id}")
def admin_update_question(question_id: int, req: AdminQuestionRequest, admin: dict = Depends(get_admin_user)):
    cat = req.categoria.upper()
    letter = req.correct_letter.upper()
    letters = [str(o.get('letter','')).upper() for o in req.options]
    if cat not in {'A','B','C','D'} or not req.prompt.strip() or not req.tema.strip() or len(req.options) < 2 or letter not in letters:
        raise HTTPException(status_code=400, detail="Verifique categoria, tema, pergunta e opções.")
    options = [{"letter": str(o.get('letter','')).upper(), "text": str(o.get('text','')).strip(), "is_correct": str(o.get('letter','')).upper() == letter} for o in req.options]
    if any(not o['text'] for o in options) or len(set(letters)) != len(letters):
        raise HTTPException(status_code=400, detail="As opções têm de ser únicas e não vazias.")

    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        UPDATE questions SET categoria=?, tema=?, prompt=?, options=?, correct_letter=?, image_path=? WHERE id=?
    """, (cat, req.tema.strip(), req.prompt.strip(), json.dumps(options, ensure_ascii=False), letter, req.image_path, question_id))
    if c.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Pergunta não encontrada.")
    conn.commit()
    conn.close()
    return {"message": "Pergunta atualizada."}

@app.delete("/api/admin/questions/{question_id}")
def admin_delete_question(question_id: int, admin: dict = Depends(get_admin_user)):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM test_answers WHERE question_id=?", (question_id,))
    if c.fetchone()[0]:
        conn.close()
        raise HTTPException(status_code=409, detail="Esta pergunta consta no histórico dos alunos e não pode ser eliminada.")
    c.execute("DELETE FROM student_question_stats WHERE question_id=?", (question_id,))
    c.execute("DELETE FROM questions WHERE id=?", (question_id,))
    if c.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=404, detail="Pergunta não encontrada.")
    conn.commit()
    conn.close()
    return {"message": "Pergunta eliminada."}

# ----------------- STATIC WEB APPLICATION -----------------

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
os.makedirs(STATIC_DIR, exist_ok=True)

# Mount static files
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/{full_path:path}")
def serve_spa(full_path: str):
    # Serve index.html for all non-API paths
    index_file = os.path.join(STATIC_DIR, 'index.html')
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return JSONResponse({"status": "Carta Auto Testes API Online", "docs": "/docs"})

if __name__ == '__main__':
    import uvicorn
    init_db()
    print("Iniciando Carta Auto Testes na porta 8000...")
    run_host = os.environ.get('HOST', '127.0.0.1')
    run_port = int(os.environ.get('PORT', '8000'))
    uvicorn.run("server:app", host=run_host, port=run_port, reload=False)
