"""
backup.py – Backup/restore and one-time restore-code management.

Backups are ZIP files containing the database, encryption keys, and logs.
Managers need a one-use restore code (issued by Super Admin) to restore.
"""

import zipfile
import secrets
import string
from pathlib import Path
from datetime import datetime

from database import get_connection, encrypt_field, decrypt_field
from auth import get_current_user, check_permission
from activity_log import log_activity

BACKUP_DIR = Path(__file__).parent / "backups"
DATA_DIR = Path(__file__).parent / "data"

_BACKUP_FILES = ["declaratieapp.db", "aes_key.bin", "fernet_key.bin", "system.log"]


# ── backup ───────────────────────────────────────────────────────────────
def create_backup():
    """Create a ZIP backup. Returns (ok, msg, filename)."""
    if not (check_permission("create_backup") or check_permission("restore_backup")):
        return False, "Access denied.", None

    cur = get_current_user()
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"backup_{ts}.zip"

    try:
        with zipfile.ZipFile(BACKUP_DIR / fname, "w", zipfile.ZIP_DEFLATED) as zf:
            for name in _BACKUP_FILES:
                path = DATA_DIR / name
                if path.exists():
                    zf.write(path, name)
        if cur:
            log_activity(cur["username"], "Backup created", f"File: {fname}")
        return True, f"Backup created: {fname}", fname
    except Exception as e:
        return False, f"Backup error: {e}", None


def list_backups():
    if not BACKUP_DIR.exists():
        return []
    backups = []
    for f in BACKUP_DIR.glob("backup_*.zip"):
        st = f.stat()
        backups.append({
            "filename": f.name,
            "size": st.st_size,
            "created": datetime.fromtimestamp(st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
        })
    backups.sort(key=lambda b: b["created"], reverse=True)
    return backups


# ── restore ──────────────────────────────────────────────────────────────
def restore_backup(backup_filename, restore_code=None):
    """Restore from backup. Manager needs a valid restore code. Returns (ok, msg)."""
    cur = get_current_user()
    if not cur:
        return False, "Not logged in."

    is_super = check_permission("generate_restore_code")
    is_manager = check_permission("restore_backup") and not is_super
    if not is_super and not is_manager:
        return False, "Access denied."

    if is_manager:
        if not restore_code:
            return False, "Managers require a restore code."
        valid, code_backup = _validate_restore_code(restore_code)
        if not valid:
            log_activity(cur["username"], "Restore failed", "Invalid code", suspicious=True)
            return False, "Invalid or expired restore code."
        if code_backup != backup_filename:
            return False, f"Code is valid for '{code_backup}', not '{backup_filename}'."

    path = BACKUP_DIR / backup_filename
    if not path.exists():
        return False, f"Backup '{backup_filename}' not found."

    try:
        if is_manager and restore_code:
            _mark_code_used(restore_code)

        with zipfile.ZipFile(path, "r") as zf:
            for name in zf.namelist():
                zf.extract(name, DATA_DIR)

        log_activity(cur["username"], "Backup restored", f"File: {backup_filename}")
        return True, f"Restored from: {backup_filename}"
    except Exception as e:
        return False, f"Restore error: {e}"


# ── restore codes ────────────────────────────────────────────────────────
def _ensure_restore_codes_table():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS restore_codes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT NOT NULL UNIQUE,
            backup_filename TEXT NOT NULL,
            target_username TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    return conn


def generate_restore_code(backup_filename, target_username):
    """Generate a one-use restore code for a Manager. Returns (ok, msg, code)."""
    if not check_permission("generate_restore_code"):
        return False, "Only Super Admin can generate restore codes.", None

    cur = get_current_user()
    path = BACKUP_DIR / backup_filename
    if not path.exists():
        return False, f"Backup '{backup_filename}' not found.", None

    code = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(12))
    conn = _ensure_restore_codes_table()
    conn.execute(
        "INSERT INTO restore_codes (code, backup_filename, target_username) VALUES (?, ?, ?)",
        (encrypt_field(code), encrypt_field(backup_filename), encrypt_field(target_username)),
    )
    conn.commit()
    conn.close()

    if cur:
        log_activity(cur["username"], "Restore code generated",
                     f"For: {target_username}, Backup: {backup_filename}")
    return True, "Restore code generated.", code


def revoke_restore_code(restore_code):
    """Revoke an unused restore code. Returns (ok, msg)."""
    if not check_permission("revoke_restore_code"):
        return False, "Only Super Admin can revoke restore codes."
    cur = get_current_user()

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='restore_codes'")
    if not c.fetchone():
        conn.close()
        return False, "No restore codes exist."

    c.execute("SELECT id, code, backup_filename, target_username FROM restore_codes WHERE used = 0")
    for rid, enc_code, enc_backup, enc_target in c.fetchall():
        if decrypt_field(enc_code) == restore_code:
            c.execute("DELETE FROM restore_codes WHERE id = ?", (rid,))
            conn.commit()
            conn.close()
            if cur:
                log_activity(cur["username"], "Restore code revoked",
                             f"For: {decrypt_field(enc_target)}, Backup: {decrypt_field(enc_backup)}")
            return True, "Restore code revoked."
    conn.close()
    return False, "Restore code not found."


def list_restore_codes():
    if not check_permission("generate_restore_code"):
        return []
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='restore_codes'")
    if not c.fetchone():
        conn.close()
        return []
    c.execute("SELECT code, backup_filename, target_username, created_at "
              "FROM restore_codes WHERE used = 0 ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [
        {"code": decrypt_field(r[0]), "backup_filename": decrypt_field(r[1]),
         "target_username": decrypt_field(r[2]), "created_at": r[3]}
        for r in rows
    ]


# ── internal helpers ─────────────────────────────────────────────────────
def _validate_restore_code(code):
    """Check if code is valid and unused. Returns (ok, backup_filename)."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='restore_codes'")
    if not c.fetchone():
        conn.close()
        return False, None
    c.execute("SELECT backup_filename, code FROM restore_codes WHERE used = 0")
    for enc_backup, enc_code in c.fetchall():
        if decrypt_field(enc_code) == code:
            conn.close()
            return True, decrypt_field(enc_backup)
    conn.close()
    return False, None


def _mark_code_used(code):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, code FROM restore_codes WHERE used = 0")
    for rid, enc_code in c.fetchall():
        if decrypt_field(enc_code) == code:
            c.execute("UPDATE restore_codes SET used = 1 WHERE id = ?", (rid,))
            break
    conn.commit()
    conn.close()