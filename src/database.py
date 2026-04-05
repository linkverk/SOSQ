"""
database.py – SQLite database, encryption (AES + Fernet) and password hashing.

Encryption strategy
───────────────────
• AES-256 ECB  → deterministic, for fields needing WHERE lookups (usernames, zip codes).
• Fernet       → non-deterministic, for all other sensitive fields.
• PBKDF2-SHA256 + random salt → password hashing.

Libraries: cryptography (Fernet + hazmat for AES), hashlib, os, sqlite3.
"""

import os
import sqlite3
import base64
import hashlib
from pathlib import Path

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ── paths & credentials ──────────────────────────────────────────────────
DATA_DIR = Path(__file__).parent / "data"
DB_PATH = DATA_DIR / "declaratieapp.db"
AES_KEY_PATH = DATA_DIR / "aes_key.bin"
FERNET_KEY_PATH = DATA_DIR / "fernet_key.bin"

SUPER_ADMIN_USERNAME = "super_admin"
SUPER_ADMIN_PASSWORD = "Admin_123?"


# ── key management ───────────────────────────────────────────────────────
def _load_or_create_key(path, generator):
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if path.exists():
        return path.read_bytes()
    key = generator()
    path.write_bytes(key)
    return key


aes_key = _load_or_create_key(AES_KEY_PATH, lambda: os.urandom(32))
_fernet_key = _load_or_create_key(FERNET_KEY_PATH, Fernet.generate_key)
fernet_cipher = Fernet(_fernet_key)


# ── PKCS7 padding (AES block size = 16) ─────────────────────────────────
def _pad(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    return data[:-pad_len]


# ── AES username encryption (deterministic, ECB) ────────────────────────
def encrypt_username(username):
    if not username:
        return ""
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(_pad(username.encode())) + encryptor.finalize()
    return base64.b64encode(encrypted).decode()


def decrypt_username(encrypted):
    if not encrypted:
        return ""
    cipher = Cipher(algorithms.AES(aes_key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(base64.b64decode(encrypted)) + decryptor.finalize()
    return _unpad(decrypted).decode()


# ── Fernet field encryption (non-deterministic) ─────────────────────────
def encrypt_field(plaintext):
    if not plaintext:
        return ""
    return fernet_cipher.encrypt(plaintext.encode()).decode()


def decrypt_field(encrypted):
    if not encrypted:
        return ""
    return fernet_cipher.decrypt(encrypted.encode()).decode()


# ── password hashing (PBKDF2-SHA256 + random salt) ──────────────────────
_HASH_ITERATIONS = 260_000  # OWASP recommended minimum for PBKDF2-SHA256


def hash_password(password, username=None):
    """Hash password with PBKDF2-SHA256 and a random 32-byte salt."""
    salt = os.urandom(32)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _HASH_ITERATIONS)
    return base64.b64encode(salt).decode() + "$" + base64.b64encode(pw_hash).decode()


def verify_password(password, username, stored_hash):
    """Verify password against stored PBKDF2 hash."""
    try:
        salt_b64, hash_b64 = stored_hash.split("$", 1)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(hash_b64)
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, _HASH_ITERATIONS)
        return actual == expected
    except Exception:
        return False


# ── connection ───────────────────────────────────────────────────────────
def get_connection():
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


# ── schema ───────────────────────────────────────────────────────────────
def create_tables():
    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            username              TEXT NOT NULL UNIQUE,
            password_hash         TEXT NOT NULL,
            role                  TEXT NOT NULL,
            first_name            TEXT NOT NULL,
            last_name             TEXT NOT NULL,
            employee_id           TEXT,
            must_change_password  INTEGER DEFAULT 0,
            created_at            TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS employees (
            id                        INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id               TEXT NOT NULL UNIQUE,
            first_name                TEXT NOT NULL,
            last_name                 TEXT NOT NULL,
            birthday                  TEXT NOT NULL,
            gender                    TEXT NOT NULL,
            street_name               TEXT NOT NULL,
            house_number              TEXT NOT NULL,
            zip_code                  TEXT NOT NULL,
            city                      TEXT NOT NULL,
            email                     TEXT NOT NULL,
            mobile_phone              TEXT NOT NULL,
            identity_document_type    TEXT NOT NULL,
            identity_document_number  TEXT NOT NULL,
            bsn_number                TEXT NOT NULL,
            registration_date         TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS claims (
            id                INTEGER PRIMARY KEY AUTOINCREMENT,
            claim_date        TEXT NOT NULL,
            project_number    TEXT NOT NULL,
            employee_id       TEXT NOT NULL,
            claim_type        TEXT NOT NULL,
            travel_distance   TEXT,
            from_zip          TEXT,
            from_housenumber  TEXT,
            to_zip            TEXT,
            to_housenumber    TEXT,
            approved          TEXT NOT NULL DEFAULT 'Pending',
            approved_by       TEXT,
            salary_batch      TEXT,
            created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (employee_id) REFERENCES employees(employee_id)
        )
    """)

    conn.commit()
    conn.close()


def init_super_admin():
    conn = get_connection()
    c = conn.cursor()
    enc = encrypt_username(SUPER_ADMIN_USERNAME)
    c.execute("SELECT id FROM users WHERE username = ?", (enc,))
    if c.fetchone() is None:
        c.execute(
            "INSERT INTO users (username, password_hash, role, first_name, last_name) "
            "VALUES (?, ?, ?, ?, ?)",
            (enc, hash_password(SUPER_ADMIN_PASSWORD), "super_admin", "Super", "Administrator"),
        )
        conn.commit()
        print(f"  Super Admin created  (user: {SUPER_ADMIN_USERNAME} / pass: {SUPER_ADMIN_PASSWORD})")
    conn.close()


def init_database():
    print("=" * 60)
    print("  DECLARATIEAPP – Database Initialization")
    print("=" * 60)
    create_tables()
    init_super_admin()
    print(f"  DB : {DB_PATH}")
    print("=" * 60)