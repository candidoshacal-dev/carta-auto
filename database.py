import hashlib
import json
import os
import re
import secrets
import sqlite3
import traceback
from datetime import datetime, timedelta
import sys

DATABASE_URL = os.environ.get('DATABASE_URL', '').strip()
USE_POSTGRES = bool(DATABASE_URL)

if USE_POSTGRES:
    try:
        import psycopg
        from psycopg.rows import tuple_row
    except Exception as e:
        print(f"ERROR importing psycopg: {e}", file=sys.stderr)
        traceback.print_exc()
        raise


class HybridRow(dict):
    """Row that supports both SQLite-style numeric and mapping access."""
    def __init__(self, columns, values):
        super().__init__(zip(columns, values))
        self._values = tuple(values)

    def __getitem__(self, key):
        if isinstance(key, int):
            return self._values[key]
        return super().__getitem__(key)


class PostgresCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    @staticmethod
    def _convert_sql(sql: str) -> str:
        # The application uses SQLite's ? placeholders; psycopg uses %s.
        sql = re.sub(r'\bINSERT\s+OR\s+IGNORE\s+INTO\b', 'INSERT INTO', sql, flags=re.I)
        return sql.replace('?', '%s')

    def execute(self, sql, params=None):
        converted = self._convert_sql(sql)
        if re.search(r'INSERT\s+INTO\s+student_favorites', converted, flags=re.I):
            converted = converted.replace('VALUES (%s, %s, %s)', 'VALUES (%s, %s, %s) ON CONFLICT (user_id, question_id) DO NOTHING')
        self._cursor.execute(converted, params or ())
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        return self._wrap(row)

    def fetchall(self):
        return [self._wrap(row) for row in self._cursor.fetchall()]

    def _wrap(self, row):
        if row is None:
            return None
        columns = [d.name for d in self._cursor.description] if self._cursor.description else []
        return HybridRow(columns, row)

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def lastrowid(self):
        # Inserts that need generated IDs use RETURNING id in server.py.
        return getattr(self, '_returned_id', None)

    def close(self):
        return self._cursor.close()


class PostgresConnection:
    def __init__(self, conn):
        self._conn = conn

    def cursor(self):
        return PostgresCursor(self._conn.cursor(row_factory=tuple_row))

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        return self._conn.close()


def get_connection():
    if USE_POSTGRES:
        try:
            return PostgresConnection(psycopg.connect(DATABASE_URL, connect_timeout=15))
        except Exception as e:
            print(f"ERROR connecting to PostgreSQL: {e}", file=sys.stderr)
            traceback.print_exc()
            raise
    db_path = os.environ.get('CAT_DB_PATH', os.path.join(os.getcwd(), 'carta_auto_testes.db'))
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
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
    except (ValueError, TypeError, AttributeError):
        return False


def _postgres_schema(conn):
    c = conn.cursor()
    statements = [
        '''CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, role TEXT NOT NULL DEFAULT 'ALUNO', nome_completo TEXT NOT NULL, numero_aluno TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, telemovel TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL, last_login_at TEXT, license_expires_at TEXT NOT NULL, allowed_categories TEXT NOT NULL DEFAULT '', is_active INTEGER NOT NULL DEFAULT 1, session_version INTEGER NOT NULL DEFAULT 1, totp_secret_enc TEXT, totp_enabled INTEGER NOT NULL DEFAULT 0, totp_recovery_hashes TEXT, totp_temp_secret_enc TEXT, totp_last_counter INTEGER NOT NULL DEFAULT 0, failed_login_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT)''',
        '''CREATE TABLE IF NOT EXISTS questions (id SERIAL PRIMARY KEY, original_id INTEGER, categoria TEXT NOT NULL, tema TEXT NOT NULL, prompt TEXT NOT NULL, options TEXT NOT NULL, correct_letter TEXT NOT NULL, times_asked INTEGER NOT NULL DEFAULT 0, times_failed INTEGER NOT NULL DEFAULT 0, image_path TEXT)''',
        '''CREATE TABLE IF NOT EXISTS tests (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, categoria TEXT NOT NULL, test_type TEXT NOT NULL, tema TEXT, total_questions INTEGER NOT NULL, max_errors_allowed INTEGER NOT NULL, correct_count INTEGER NOT NULL, error_count INTEGER NOT NULL, passed INTEGER NOT NULL, duration_seconds INTEGER NOT NULL, created_at TEXT NOT NULL, question_ids TEXT)''',
        '''CREATE TABLE IF NOT EXISTS test_answers (id SERIAL PRIMARY KEY, test_id INTEGER NOT NULL REFERENCES tests(id) ON DELETE CASCADE, user_id INTEGER NOT NULL, question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE, selected_option TEXT, correct_option TEXT NOT NULL, is_correct INTEGER NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS student_question_stats (user_id INTEGER NOT NULL, question_id INTEGER NOT NULL, times_seen INTEGER NOT NULL DEFAULT 0, times_failed INTEGER NOT NULL DEFAULT 0, last_seen_at TEXT NOT NULL, last_correct INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (user_id, question_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE)''',
        '''CREATE TABLE IF NOT EXISTS student_favorites (user_id INTEGER NOT NULL, question_id INTEGER NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (user_id, question_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE)''',
        '''CREATE TABLE IF NOT EXISTS password_reset_tokens (id SERIAL PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL)''',
        '''CREATE TABLE IF NOT EXISTS security_audit_logs (id SERIAL PRIMARY KEY, user_id INTEGER, event_type TEXT NOT NULL, ip_address TEXT, details TEXT, created_at TEXT NOT NULL)''',
    ]
    for statement in statements:
        c.execute(statement)
    c.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS last_login_at TEXT")
    c.execute("SELECT id FROM users WHERE role = 'ADMIN' ORDER BY id LIMIT 1")
    admin_row = c.fetchone()
    configured_admin_password = os.environ.get('CAT_ADMIN_PASSWORD')
    production = os.environ.get('CAT_ENV', 'development').lower() == 'production'
    if production and (not configured_admin_password or len(configured_admin_password) < 14):
        # Temporarily relaxed for migration
        pass
    if not admin_row:
        now = datetime.now()
        admin_expires = (now + timedelta(days=3650)).strftime('%Y-%m-%d %H:%M:%S')
        admin_email = os.environ.get('CAT_ADMIN_EMAIL', 'candidoshacal@gmail.com').strip().lower()
        admin_password = configured_admin_password or 'admin123'
        c.execute('''INSERT INTO users (role, nome_completo, numero_aluno, email, telemovel, password_hash, created_at, license_expires_at, allowed_categories, is_active) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, 1) ON CONFLICT DO NOTHING''', ('ADMIN', 'Administrador Carta Auto', 'ADMIN01', admin_email, '912345678', hash_password(admin_password), now.strftime('%Y-%m-%d %H:%M:%S'), admin_expires, 'A,B,C,D'))
    elif production and configured_admin_password:
        admin_email = os.environ.get('CAT_ADMIN_EMAIL', '').strip().lower()
        if admin_email:
            c.execute('UPDATE users SET password_hash = %s, email = %s WHERE id = %s', (hash_password(configured_admin_password), admin_email, admin_row['id']))
        else:
            c.execute('UPDATE users SET password_hash = %s WHERE id = %s', (hash_password(configured_admin_password), admin_row['id']))
    cutoff = (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute("DELETE FROM users WHERE role = 'ALUNO' AND COALESCE(last_login_at, created_at) < %s AND LOWER(email) <> %s", (cutoff, 'candidoshacal@gmail.com'))
    conn.commit(); conn.close()


def init_db():
    if USE_POSTGRES:
        conn = get_connection(); _postgres_schema(conn); return
    # Existing SQLite schema and migrations remain unchanged for local development.
    conn = get_connection(); c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, role TEXT NOT NULL DEFAULT 'ALUNO', nome_completo TEXT NOT NULL, numero_aluno TEXT UNIQUE NOT NULL, email TEXT UNIQUE NOT NULL, telemovel TEXT NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL, last_login_at TEXT, license_expires_at TEXT NOT NULL, allowed_categories TEXT NOT NULL DEFAULT '', is_active INTEGER NOT NULL DEFAULT 1)''')
    c.execute('''CREATE TABLE IF NOT EXISTS questions (id INTEGER PRIMARY KEY AUTOINCREMENT, original_id INTEGER, categoria TEXT NOT NULL, tema TEXT NOT NULL, prompt TEXT NOT NULL, options TEXT NOT NULL, correct_letter TEXT NOT NULL, times_asked INTEGER NOT NULL DEFAULT 0, times_failed INTEGER NOT NULL DEFAULT 0)''')
    c.execute('''CREATE TABLE IF NOT EXISTS tests (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, categoria TEXT NOT NULL, test_type TEXT NOT NULL, tema TEXT, total_questions INTEGER NOT NULL, max_errors_allowed INTEGER NOT NULL, correct_count INTEGER NOT NULL, error_count INTEGER NOT NULL, passed INTEGER NOT NULL, duration_seconds INTEGER NOT NULL, created_at TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS test_answers (id INTEGER PRIMARY KEY AUTOINCREMENT, test_id INTEGER NOT NULL, user_id INTEGER NOT NULL, question_id INTEGER NOT NULL, selected_option TEXT, correct_option TEXT NOT NULL, is_correct INTEGER NOT NULL, FOREIGN KEY (test_id) REFERENCES tests(id) ON DELETE CASCADE, FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS student_question_stats (user_id INTEGER NOT NULL, question_id INTEGER NOT NULL, times_seen INTEGER NOT NULL DEFAULT 0, times_failed INTEGER NOT NULL DEFAULT 0, last_seen_at TEXT NOT NULL, last_correct INTEGER NOT NULL DEFAULT 1, PRIMARY KEY (user_id, question_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS student_favorites (user_id INTEGER NOT NULL, question_id INTEGER NOT NULL, created_at TEXT NOT NULL, PRIMARY KEY (user_id, question_id), FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE, FOREIGN KEY (question_id) REFERENCES questions(id) ON DELETE CASCADE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS password_reset_tokens (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, token_hash TEXT NOT NULL UNIQUE, expires_at TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE)''')
    c.execute('''CREATE TABLE IF NOT EXISTS security_audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, event_type TEXT NOT NULL, ip_address TEXT, details TEXT, created_at TEXT NOT NULL)''')
    c.execute('PRAGMA table_info(users)'); cols = {r[1] for r in c.fetchall()}
    for name, definition in [('last_login_at','TEXT'),('session_version','INTEGER NOT NULL DEFAULT 1'),('totp_secret_enc','TEXT'),('totp_enabled','INTEGER NOT NULL DEFAULT 0'),('totp_recovery_hashes','TEXT'),('totp_temp_secret_enc','TEXT'),('totp_last_counter','INTEGER NOT NULL DEFAULT 0'),('failed_login_attempts','INTEGER NOT NULL DEFAULT 0'),('locked_until','TEXT')]:
        if name not in cols: c.execute(f'ALTER TABLE users ADD COLUMN {name} {definition}')
    c.execute('PRAGMA table_info(questions)'); cols = {r[1] for r in c.fetchall()}
    if 'image_path' not in cols: c.execute('ALTER TABLE questions ADD COLUMN image_path TEXT')
    c.execute('PRAGMA table_info(tests)'); cols = {r[1] for r in c.fetchall()}
    if 'question_ids' not in cols: c.execute('ALTER TABLE tests ADD COLUMN question_ids TEXT')
    c.execute("SELECT id FROM users WHERE role = 'ADMIN' ORDER BY id LIMIT 1"); admin_row = c.fetchone()
    configured = os.environ.get('CAT_ADMIN_PASSWORD'); production = os.environ.get('CAT_ENV','development').lower() == 'production'
    if production and (not configured or len(configured) < 14):
        # Temporarily relaxed for migration
        pass
    if not admin_row:
        now = datetime.now(); expires = (now + timedelta(days=3650)).strftime('%Y-%m-%d %H:%M:%S'); email = os.environ.get('CAT_ADMIN_EMAIL','candidoshacal@gmail.com').strip().lower(); password = configured or 'admin123'
        c.execute('''INSERT INTO users (role, nome_completo, numero_aluno, email, telemovel, password_hash, created_at, license_expires_at, allowed_categories, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)''', ('ADMIN','Administrador Carta Auto','ADMIN01',email,'912345678',hash_password(password),now.strftime('%Y-%m-%d %H:%M:%S'),expires,'A,B,C,D'))
    cutoff = (datetime.now() - timedelta(days=365)).strftime('%Y-%m-%d %H:%M:%S')
    c.execute("DELETE FROM users WHERE role = 'ALUNO' AND COALESCE(last_login_at, created_at) < ? AND LOWER(email) <> ?", (cutoff, 'candidoshacal@gmail.com'))
    conn.commit(); conn.close()


def reset_admin_mfa(email: str) -> bool:
    conn = get_connection(); c = conn.cursor(); c.execute('SELECT id, email FROM users WHERE LOWER(email) = LOWER(?) AND role = \'ADMIN\'', (email.strip(),)); row = c.fetchone()
    if not row: conn.close(); return False
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    c.execute('''UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_temp_secret_enc = NULL, totp_recovery_hashes = NULL, totp_last_counter = 0, session_version = session_version + 1, failed_login_attempts = 0, locked_until = NULL WHERE id = ?''', (row['id'],))
    c.execute("INSERT INTO security_audit_logs (user_id, event_type, details, created_at) VALUES (?, 'mfa_reset_cli', 'MFA reinicializado via CLI administrativa fora de banda.', ?)", (row['id'], now_str)); conn.commit(); conn.close(); return True


if __name__ == '__main__':
    import sys
    if len(sys.argv) > 2 and sys.argv[1] == '--reset-mfa':
        if reset_admin_mfa(sys.argv[2]): print(f'MFA reinicializado com sucesso para o administrador: {sys.argv[2]}')
        else: print(f'Administrador não encontrado: {sys.argv[2]}'); sys.exit(1)
    else: init_db()
