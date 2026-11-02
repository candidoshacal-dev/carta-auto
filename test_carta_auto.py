import os
import tempfile
import shutil
import json
import atexit
import pytest
import pyotp
from datetime import datetime, timedelta
from pathlib import Path

# Set temporary DB path before importing app/database
PROJECT_DIR = Path(__file__).resolve().parent
TEMP_ROOT = PROJECT_DIR / ".test-tmp"
TEMP_ROOT.mkdir(exist_ok=True)
TEMP_DIR = tempfile.mkdtemp(prefix="carta-auto-", dir=TEMP_ROOT)
atexit.register(shutil.rmtree, TEMP_DIR, ignore_errors=True)
os.environ['CAT_DB_PATH'] = os.path.join(TEMP_DIR, 'test_carta.db')
os.environ['CAT_ENV'] = 'production'
os.environ['SESSION_SECRET'] = 'test-only-session-secret-security-1234567890abcdef1234567890'
os.environ['CAT_ADMIN_EMAIL'] = 'candidoshacal@gmail.com'
os.environ['CAT_ADMIN_PASSWORD'] = 'test-only-admin-password-123456!'

from fastapi.testclient import TestClient
from database import init_db, get_connection, hash_password
from server import app

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_database():
    db_path = os.environ.get('CAT_DB_PATH')
    seed_p = str(PROJECT_DIR / 'seed' / 'carta_auto_testes_seed.db')
    if os.path.exists(seed_p) and db_path:
        shutil.copy2(seed_p, db_path)
    init_db()
    yield

def test_01_registration_and_login():
    # Register student
    reg_res = client.post("/api/auth/register", json={
        "nome_completo": "Estudante Teste",
        "numero_aluno": "EST001",
        "email": "estudante@teste.pt",
        "telemovel": "911223344",
        "password": "password123",
        "confirmar_password": "password123"
    })
    assert reg_res.status_code == 200, reg_res.text
    data = reg_res.json()
    assert "token" in data
    assert data["user"]["email"] == "estudante@teste.pt"
    assert data["user"]["role"] == "ALUNO"

    # Login by student number
    login_res = client.post("/api/auth/login", json={
        "login": "EST001",
        "password": "password123"
    })
    assert login_res.status_code == 200, login_res.text
    assert "token" in login_res.json()

def test_02_admin_mfa_flow():
    # Test-only admin is created from the isolated production-like environment.
    login_res = client.post("/api/auth/login", json={
        "login": os.environ['CAT_ADMIN_EMAIL'],
        "password": os.environ['CAT_ADMIN_PASSWORD']
    })
    assert login_res.status_code == 200, login_res.text
    data = login_res.json()
    assert data.get("mfa_required") is True
    assert data.get("mfa_setup_required") is True
    assert "token" not in data
    temp_token = data["temp_token"]

    # Without MFA setup, accessing admin overview should be denied / unauthorized
    admin_ov = client.get("/api/admin/overview")
    assert admin_ov.status_code == 401

    # Setup MFA
    setup_res = client.post("/api/auth/mfa/setup", json={"temp_token": temp_token})
    assert setup_res.status_code == 200, setup_res.text
    setup_data = setup_res.json()
    secret = setup_data["secret"]
    recovery_codes = setup_data["recovery_codes"]
    assert secret
    assert len(recovery_codes) == 8

    # Confirm MFA with valid TOTP code
    import pyotp
    totp = pyotp.TOTP(secret)
    code = totp.now()
    current_step = int(datetime.now().timestamp()) // 30
    valid_window = {totp.at((current_step + offset) * 30) for offset in (-1, 0, 1)}
    invalid_code = next(f"{candidate:06d}" for candidate in range(1_000_000) if f"{candidate:06d}" not in valid_window)
    invalid_confirm = client.post("/api/auth/mfa/confirm", json={"temp_token": temp_token, "code": invalid_code})
    assert invalid_confirm.status_code == 400

    confirm_res = client.post("/api/auth/mfa/confirm", json={
        "temp_token": temp_token,
        "code": code
    })
    assert confirm_res.status_code == 200, confirm_res.text
    confirm_data = confirm_res.json()
    assert "token" in confirm_data
    admin_token = confirm_data["token"]

    # Access admin overview with admin token
    ov_res = client.get("/api/admin/overview", headers={"Authorization": f"Bearer {admin_token}"})
    assert ov_res.status_code == 200, ov_res.text
    ov_data = ov_res.json()
    assert "total_students" in ov_data
    assert "tests_today" in ov_data
    assert "pending_renewals" in ov_data

    # Test logout revokes token
    logout_res = client.post("/api/auth/logout", headers={"Authorization": f"Bearer {admin_token}"})
    assert logout_res.status_code == 200

    # Old admin token should now fail
    ov_fail = client.get("/api/admin/overview", headers={"Authorization": f"Bearer {admin_token}"})
    assert ov_fail.status_code == 401

    # TOTP replay must be rejected; a recovery code is single-use.
    second_login = client.post("/api/auth/login", json={
        "login": os.environ['CAT_ADMIN_EMAIL'],
        "password": os.environ['CAT_ADMIN_PASSWORD']
    }).json()
    assert second_login.get("mfa_required") is True
    replay = client.post("/api/auth/mfa/verify", json={"temp_token": second_login["temp_token"], "code": code})
    assert replay.status_code == 400
    recovery = client.post("/api/auth/mfa/verify", json={
        "temp_token": second_login["temp_token"],
        "code": recovery_codes[0]
    })
    assert recovery.status_code == 200
    assert recovery.json()["used_recovery_code"] is True
    third_login = client.post("/api/auth/login", json={
        "login": os.environ['CAT_ADMIN_EMAIL'],
        "password": os.environ['CAT_ADMIN_PASSWORD']
    }).json()
    reused_recovery = client.post("/api/auth/mfa/verify", json={
        "temp_token": third_login["temp_token"],
        "code": recovery_codes[0]
    })
    assert reused_recovery.status_code == 401

def test_03_student_test_engine_and_review():
    # Register and login student
    reg = client.post("/api/auth/register", json={
        "nome_completo": "Ana Aluna",
        "numero_aluno": "ALU999",
        "email": "ana@teste.pt",
        "telemovel": "922334455",
        "password": "pass1234",
        "confirmar_password": "pass1234"
    }).json()
    token = reg["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Get categories
    cats = client.get("/api/categories", headers=headers).json()
    assert len(cats) > 0

    # Start Category B test (30 questions)
    start_res = client.post("/api/tests/start", headers=headers, json={
        "categoria": "B",
        "test_type": "aleatorio",
        "num_questions": 30
    })
    assert start_res.status_code == 200, start_res.text
    test_data = start_res.json()
    test_id = test_data["test_id"]
    questions = test_data["questions"]
    assert len(questions) > 0

    # Submit answers (answer first 28 correctly if possible, leave 2 unanswered to test unanswered error counting)
    answers = {}
    for i, q in enumerate(questions):
        if i < 28:
            # pick correct letter or option A
            answers[str(q["id"])] = q["options"][0]["letter"]

    submit_res = client.post(f"/api/tests/{test_id}/submit", headers=headers, json={
        "answers": answers,
        "duration_seconds": 600
    })
    assert submit_res.status_code == 200, submit_res.text
    sub_data = submit_res.json()
    assert "passed" in sub_data
    assert sub_data["total_questions"] == 30
    assert len(sub_data["review"]) == 30

    # Verify review endpoint includes all questions (answered and unanswered)
    review_res = client.get(f"/api/tests/{test_id}/review", headers=headers)
    assert review_res.status_code == 200, review_res.text
    rev_data = review_res.json()
    assert len(rev_data["answers"]) == 30

    # Verify student summary and stats
    summary_res = client.get("/api/stats/student-summary", headers=headers)
    assert summary_res.status_code == 200, summary_res.text
    sum_data = summary_res.json()
    assert sum_data["total_tests"] == 1
    assert "average_score" in sum_data
    assert "best_score" in sum_data
    assert "category_performance" in sum_data
    assert "theme_performance" in sum_data

def test_04_favorites_server_side():
    reg = client.post("/api/auth/register", json={
        "nome_completo": "Carlos Favoritos",
        "numero_aluno": "CAR001",
        "email": "carlos@teste.pt",
        "telemovel": "933445566",
        "password": "pass1234",
        "confirmar_password": "pass1234"
    }).json()
    token = reg["token"]
    headers = {"Authorization": f"Bearer {token}"}

    # Get a question ID from database directly
    conn = get_connection()
    q_id = conn.execute("SELECT id FROM questions LIMIT 1").fetchone()[0]
    conn.close()

    # Add favorite
    add_fav = client.post(f"/api/favorites/{q_id}", headers=headers)
    assert add_fav.status_code == 200
    assert add_fav.json()["favorited"] is True

    # Get favorite IDs
    fav_ids = client.get("/api/favorites/ids", headers=headers).json()
    assert q_id in fav_ids["favorite_ids"]

    # Get favorites list
    fav_list = client.get("/api/favorites", headers=headers).json()
    assert len(fav_list) == 1
    assert fav_list[0]["id"] == q_id

    # Remove favorite
    rem_fav = client.delete(f"/api/favorites/{q_id}", headers=headers)
    assert rem_fav.status_code == 200
    assert rem_fav.json()["favorited"] is False

def test_05_password_reset_flow(monkeypatch):
    import server
    monkeypatch.setattr(server, 'APP_ENV', 'development')
    # Register user
    client.post("/api/auth/register", json={
        "nome_completo": "Reset User",
        "numero_aluno": "RES001",
        "email": "reset@teste.pt",
        "telemovel": "944556677",
        "password": "oldpassword",
        "confirmar_password": "oldpassword"
    })

    # Request recovery
    rec_res = client.post("/api/auth/recover-password", json={"email": "reset@teste.pt"})
    assert rec_res.status_code == 200
    rec_data = rec_res.json()
    assert "debug_reset_token" in rec_data
    token = rec_data["debug_reset_token"]

    # Reset password with token
    reset_res = client.post("/api/auth/reset-password", json={
        "token": token,
        "new_password": "newpassword123"
    })
    assert reset_res.status_code == 200, reset_res.text

    # Login with new password
    login_res = client.post("/api/auth/login", json={
        "login": "reset@teste.pt",
        "password": "newpassword123"
    })
    assert login_res.status_code == 200

def test_06_admin_student_management():
    # Set up MFA in the isolated database to test authenticated admin actions.
    conn = get_connection()
    admin_id = conn.execute("SELECT id FROM users WHERE role = 'ADMIN'").fetchone()[0]
    secret = pyotp.random_base32()
    cipher = get_mfa_cipher() if 'get_mfa_cipher' in globals() else None
    from server import get_mfa_cipher
    secret_enc = get_mfa_cipher().encrypt(secret.encode('utf-8')).decode('ascii')
    conn.execute("UPDATE users SET totp_enabled = 1, totp_secret_enc = ? WHERE id = ?", (secret_enc, admin_id))
    conn.commit()
    conn.close()

    # Login admin with valid TOTP
    login_res = client.post("/api/auth/login", json={
        "login": os.environ['CAT_ADMIN_EMAIL'],
        "password": os.environ['CAT_ADMIN_PASSWORD']
    }).json()
    temp_token = login_res["temp_token"]
    totp = pyotp.TOTP(secret)
    code = totp.now()

    verify_res = client.post("/api/auth/mfa/verify", json={
        "temp_token": temp_token,
        "code": code
    }).json()
    admin_token = verify_res["token"]
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # List students
    students = client.get("/api/admin/students", headers=admin_headers).json()
    assert isinstance(students, list)

    # Pick first student if any, or register one
    reg = client.post("/api/auth/register", json={
        "nome_completo": "Aluno Gestao",
        "numero_aluno": "GES001",
        "email": "gestao@teste.pt",
        "telemovel": "955667788",
        "password": "password123",
        "confirmar_password": "password123"
    }).json()
    student_id = reg["user"]["id"]

    # Get student detail
    detail = client.get(f"/api/admin/students/{student_id}", headers=admin_headers)
    assert detail.status_code == 200
    assert detail.json()["student"]["numero_aluno"] == "GES001"

    # Renew license
    renew = client.post(f"/api/admin/students/{student_id}/renew", headers=admin_headers, json={"months_or_years": "6m"})
    assert renew.status_code == 200

    # Delete student
    del_res = client.delete(f"/api/admin/students/{student_id}", headers=admin_headers)
    assert del_res.status_code == 200

def test_07_frontend_assets_and_mfa_screen():
    page = client.get("/")
    assert page.status_code == 200
    assert '/static/styles.css' in page.text
    assert '/static/app.js' in page.text

    app_js = client.get('/static/app.js')
    assert app_js.status_code == 200
    assert 'function authMfa()' in app_js.text
    assert 'data-a="theme"' in app_js.text

    styles = client.get('/static/styles.css')
    assert styles.status_code == 200
    assert '.theme-dark .topbar,.theme-dark .sidebar{background:var(--paper)' in styles.text
    assert '.sidebar{display:none;position:fixed' in styles.text

    logo = client.get('/static/assets/logonovocartaauto_hero.png')
    assert logo.status_code == 200

