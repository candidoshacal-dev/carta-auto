import sqlite3
import json
import os
import hashlib
import re
import secrets
from datetime import datetime, timedelta

DB_PATH = os.environ.get('CAT_DB_PATH', os.path.join(os.path.dirname(os.path.abspath(__file__)), 'carta_auto_testes.db'))

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn

PASSWORD_ITERATIONS = 310_000

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), bytes.fromhex(salt), PASSWORD_ITERATIONS)
    return 'pbkdf2_sha256$' + str(PASSWORD_ITERATIONS) + '$' + salt + '$' + digest.hex()

def verify_password(plain_password: str, hashed: str) -> bool:
    try:
        if hashed.startswith('pbkdf2_sha256$'):
            _, rounds, salt, expected = hashed.split('$', 3)
            actual = hashlib.pbkdf2_hmac('sha256', plain_password.encode('utf-8'), bytes.fromhex(salt), int(rounds)).hex()
            return secrets.compare_digest(actual, expected)
        legacy = hashlib.sha256((plain_password + 'carta_auto_testes_salt_2026').encode('utf-8')).hexdigest()
        return secrets.compare_digest(legacy, hashed)
    except (ValueError, TypeError):
        return False

def init_db():
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        role TEXT NOT NULL DEFAULT 'ALUNO',
        nome_completo TEXT NOT NULL,
        numero_aluno TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        telemovel TEXT NOT NULL,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL,
        license_expires_at TEXT NOT NULL,
        allowed_categories TEXT NOT NULL DEFAULT 'B',
        is_active INTEGER NOT NULL DEFAULT 1
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        original_id INTEGER,
        categoria TEXT NOT NULL,
        tema TEXT NOT NULL,
        prompt TEXT NOT NULL,
        options TEXT NOT NULL,
        correct_letter TEXT NOT NULL,
        times_asked INTEGER NOT NULL DEFAULT 0,
        times_failed INTEGER NOT NULL DEFAULT 0
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS tests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        categoria TEXT NOT NULL,
        test_type TEXT NOT NULL,
        tema TEXT,
        total_questions INTEGER NOT NULL,
        max_errors_allowed INTEGER NOT NULL,
        correct_count INTEGER NOT NULL,
        error_count INTEGER NOT NULL,
        passed INTEGER NOT NULL,
        duration_seconds INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS test_answers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        test_id INTEGER NOT NULL,
        user_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        selected_option TEXT,
        correct_option TEXT NOT NULL,
        is_correct INTEGER NOT NULL,
        FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE,
        FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS student_question_stats (
        user_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        times_seen INTEGER NOT NULL DEFAULT 0,
        times_failed INTEGER NOT NULL DEFAULT 0,
        last_seen_at TEXT NOT NULL,
        last_correct INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (user_id, question_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
    )
    """)

    # Tables: favorites, password resets and security audit
    c.execute("""
    CREATE TABLE IF NOT EXISTS student_favorites (
        user_id INTEGER NOT NULL,
        question_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (user_id, question_id),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        expires_at TEXT NOT NULL,
        used INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS security_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        event_type TEXT NOT NULL,
        ip_address TEXT,
        details TEXT,
        created_at TEXT NOT NULL
    )
    """)

    # Migrate existing databases: student_question_stats
    c.execute("PRAGMA table_info(student_question_stats)")
    stats_columns = {row[1] for row in c.fetchall()}
    if 'last_correct' not in stats_columns:
        c.execute("ALTER TABLE student_question_stats ADD COLUMN last_correct INTEGER NOT NULL DEFAULT 1")
    c.execute("""
        UPDATE student_question_stats
        SET last_correct = COALESCE((
            SELECT ta.is_correct FROM test_answers ta
            WHERE ta.user_id = student_question_stats.user_id
              AND ta.question_id = student_question_stats.question_id
            ORDER BY ta.id DESC LIMIT 1
        ), 1)
    """)

    # Migrate users: session version, TOTP MFA, brute-force lockout
    c.execute("PRAGMA table_info(users)")
    users_columns = {row[1] for row in c.fetchall()}
    user_migrates = [
        ('session_version', 'INTEGER NOT NULL DEFAULT 1'),
        ('totp_secret_enc', 'TEXT'),
        ('totp_enabled', 'INTEGER NOT NULL DEFAULT 0'),
        ('totp_recovery_hashes', 'TEXT'),
        ('totp_temp_secret_enc', 'TEXT'),
        ('totp_last_counter', 'INTEGER NOT NULL DEFAULT 0'),
        ('failed_login_attempts', 'INTEGER NOT NULL DEFAULT 0'),
        ('locked_until', 'TEXT'),
    ]
    for col_name, col_def in user_migrates:
        if col_name not in users_columns:
            c.execute(f"ALTER TABLE users ADD COLUMN {col_name} {col_def}")

    # Migrate questions: image_path
    c.execute("PRAGMA table_info(questions)")
    q_columns = {row[1] for row in c.fetchall()}
    if 'image_path' not in q_columns:
        c.execute("ALTER TABLE questions ADD COLUMN image_path TEXT")

    # Migrate tests: question_ids
    c.execute("PRAGMA table_info(tests)")
    test_columns = {row[1] for row in c.fetchall()}
    if 'question_ids' not in test_columns:
        c.execute("ALTER TABLE tests ADD COLUMN question_ids TEXT")

    # Create a local development admin, or require an explicit production password.
    c.execute("SELECT id FROM users WHERE role = 'ADMIN' ORDER BY id LIMIT 1")
    admin_row = c.fetchone()
    configured_admin_password = os.environ.get('CAT_ADMIN_PASSWORD')
    production = os.environ.get('CAT_ENV', 'development').lower() == 'production'
    if production and (not configured_admin_password or len(configured_admin_password) < 14):
        conn.close()
        raise RuntimeError("Defina CAT_ADMIN_PASSWORD com pelo menos 14 caracteres em produção.")
    if not admin_row:
        now = datetime.now()
        admin_expires = (now + timedelta(days=3650)).strftime('%Y-%m-%d %H:%M:%S')
        admin_email = os.environ.get('CAT_ADMIN_EMAIL', 'candidoshacal@gmail.com').strip().lower()
        admin_password = configured_admin_password or 'admin123'
        c.execute("""
        INSERT INTO users (role, nome_completo, numero_aluno, email, telemovel, password_hash, created_at, license_expires_at, allowed_categories, is_active)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        """, (
            'ADMIN', 'Administrador Carta Auto', 'ADMIN01', admin_email, '912345678',
            hash_password(admin_password), now.strftime('%Y-%m-%d %H:%M:%S'),
            admin_expires, 'A,B,C,D'
        ))
    elif production and configured_admin_password:
        admin_email = os.environ.get('CAT_ADMIN_EMAIL', '').strip().lower()
        if admin_email:
            c.execute("UPDATE users SET password_hash = ?, email = ? WHERE id = ?", (hash_password(configured_admin_password), admin_email, admin_row['id']))
        else:
            c.execute("UPDATE users SET password_hash = ? WHERE id = ?", (hash_password(configured_admin_password), admin_row['id']))

    conn.commit()
    conn.close()

def reset_admin_mfa(email: str) -> bool:
    """Out-of-band administrative recovery: resets MFA for an admin account."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, email FROM users WHERE LOWER(email) = LOWER(?) AND role = 'ADMIN'", (email.strip(),))
    row = c.fetchone()
    if not row:
        conn.close()
        return False
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute("""
        UPDATE users
        SET totp_enabled = 0, totp_secret_enc = NULL, totp_temp_secret_enc = NULL,
            totp_recovery_hashes = NULL, totp_last_counter = 0, session_version = session_version + 1,
            failed_login_attempts = 0, locked_until = NULL
        WHERE id = ?
    """, (row['id'],))
    c.execute("""
        INSERT INTO security_audit_logs (user_id, event_type, details, created_at)
        VALUES (?, 'mfa_reset_cli', 'MFA reinicializado via CLI administrativa fora de banda.', ?)
    """, (row['id'], now_str))
    conn.commit()
    conn.close()
    return True

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 2 and sys.argv[1] == '--reset-mfa':
        target_email = sys.argv[2]
        if reset_admin_mfa(target_email):
            print(f"MFA reinicializado com sucesso para o administrador: {target_email}")
        else:
            print(f"Administrador não encontrado: {target_email}")
            sys.exit(1)
    else:
        init_db()
        print("Database schema initialized successfully.")
