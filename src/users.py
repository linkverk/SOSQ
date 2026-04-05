"""
users.py – User account management (create, delete, reset password, update profile).
"""

import secrets
import string

from database import get_connection, encrypt_username, decrypt_username, hash_password
from validation import validate_username, validate_name, ValidationError
from auth import get_current_user, check_permission, get_role_name
from activity_log import log_activity


# ── helpers ──────────────────────────────────────────────────────────────
def _generate_temporary_password():
    """Generate a 12-char password meeting all complexity requirements."""
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("~!@#$%&_-+="),
    ]
    pool = string.ascii_letters + string.digits + "~!@#$%&_-+="
    required += [secrets.choice(pool) for _ in range(8)]
    secrets.SystemRandom().shuffle(required)
    return "".join(required)


# ── creation ─────────────────────────────────────────────────────────────
def create_manager(username, first_name, last_name, password=None):
    """Create a Manager account (Super Admin only). Returns (ok, msg, temp_pw)."""
    if not check_permission("add_manager"):
        return False, "Access denied. Only Super Admin can create Managers.", None
    return _create_user(username, first_name, last_name, "manager", password)


def create_employee_account(username, first_name, last_name, employee_id=None, password=None):
    """Create an Employee account (Super Admin or Manager). Returns (ok, msg, temp_pw)."""
    if not check_permission("add_employee"):
        return False, "Access denied. Cannot create Employees.", None
    return _create_user(username, first_name, last_name, "employee", password, employee_id)


def _create_user(username, first_name, last_name, role, password=None, employee_id=None):
    cur = get_current_user()
    try:
        username = validate_username(username)
        first_name = validate_name(first_name, "First name")
        last_name = validate_name(last_name, "Last name")
    except ValidationError as e:
        return False, f"Validation error: {e}", None

    temp_pw = None
    if password is None:
        temp_pw = _generate_temporary_password()
        password = temp_pw

    conn = get_connection()
    c = conn.cursor()
    enc = encrypt_username(username)
    c.execute("SELECT id FROM users WHERE username = ?", (enc,))
    if c.fetchone():
        conn.close()
        return False, f"Username '{username}' already exists.", None

    c.execute(
        "INSERT INTO users (username, password_hash, role, first_name, last_name, "
        "employee_id, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (enc, hash_password(password), role, first_name, last_name, employee_id, 1),
    )
    conn.commit()
    conn.close()

    if cur:
        log_activity(cur["username"], f"New {role} created",
                     f"username: {username}, name: {first_name} {last_name}")
    return True, f"{get_role_name(role)} '{username}' created.", temp_pw


# ── deletion ─────────────────────────────────────────────────────────────
def delete_user(username):
    """Delete a user account (role-based). Returns (ok, msg)."""
    cur = get_current_user()
    if not cur:
        return False, "Not logged in."

    try:
        username = validate_username(username)
    except ValidationError as e:
        return False, f"Invalid username: {e}"

    if username == "super_admin":
        return False, "Cannot delete Super Administrator."

    is_self = username == cur["username"]
    if is_self and cur["role"] in ("super_admin", "employee"):
        return False, f"{get_role_name(cur['role'])} cannot delete their own account."

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, role, first_name, last_name FROM users WHERE username = ?",
              (encrypt_username(username),))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, f"User '{username}' not found."

    uid, target_role = row[0], row[1]

    if target_role == "manager" and not check_permission("delete_manager"):
        conn.close()
        return False, "Only Super Admin can delete Managers."
    if target_role == "employee" and not check_permission("delete_employee"):
        conn.close()
        return False, "Insufficient permissions to delete Employees."

    c.execute("DELETE FROM users WHERE id = ?", (uid,))
    conn.commit()
    conn.close()
    log_activity(cur["username"], "User deleted",
                 f"'{username}' ({get_role_name(target_role)})")
    return True, f"User '{username}' deleted."


# ── password reset ───────────────────────────────────────────────────────
def reset_user_password(username):
    """Reset password to a temporary one. Returns (ok, msg, temp_pw)."""
    cur = get_current_user()
    if not cur:
        return False, "Not logged in.", None

    try:
        username = validate_username(username)
    except ValidationError as e:
        return False, f"Invalid username: {e}", None

    if username == "super_admin":
        return False, "Cannot reset Super Admin password (hard-coded).", None

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, role FROM users WHERE username = ?",
              (encrypt_username(username),))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, f"User '{username}' not found.", None

    uid, target_role = row
    if target_role == "manager" and not check_permission("reset_manager_password"):
        conn.close()
        return False, "Only Super Admin can reset Manager passwords.", None
    if target_role == "employee" and not check_permission("reset_employee_password"):
        conn.close()
        return False, "Insufficient permissions.", None

    temp_pw = _generate_temporary_password()
    c.execute("UPDATE users SET password_hash = ?, must_change_password = 1 WHERE id = ?",
              (hash_password(temp_pw), uid))
    conn.commit()
    conn.close()
    log_activity(cur["username"], "Password reset", f"user: {username}")
    return True, f"Password reset for '{username}'.", temp_pw


# ── profile update ───────────────────────────────────────────────────────
def update_user_profile(username, first_name=None, last_name=None):
    """Update first/last name. Returns (ok, msg)."""
    cur = get_current_user()
    if not cur:
        return False, "Not logged in."
    if first_name is None and last_name is None:
        return False, "Nothing to update."

    try:
        username = validate_username(username)
        if first_name:
            first_name = validate_name(first_name, "First name")
        if last_name:
            last_name = validate_name(last_name, "Last name")
    except ValidationError as e:
        return False, f"Validation error: {e}"

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, role FROM users WHERE username = ?",
              (encrypt_username(username),))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, f"User '{username}' not found."

    uid, target_role = row
    is_self = username == cur["username"]

    if not is_self:
        if target_role == "manager" and not check_permission("update_manager"):
            conn.close()
            return False, "Only Super Admin can update Manager profiles."
        if target_role == "employee" and not check_permission("update_employee"):
            conn.close()
            return False, "Insufficient permissions."

    fields, params = [], []
    if first_name:
        fields.append("first_name = ?"); params.append(first_name)
    if last_name:
        fields.append("last_name = ?"); params.append(last_name)
    params.append(uid)

    c.execute(f"UPDATE users SET {', '.join(fields)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()
    log_activity(cur["username"], "Profile updated", f"user: {username}")
    return True, f"Profile updated for '{username}'."


# ── listing ──────────────────────────────────────────────────────────────
def list_all_users():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT username, role, first_name, last_name, created_at "
              "FROM users ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [
        {"username": decrypt_username(r[0]), "role": r[1],
         "role_name": get_role_name(r[1]), "first_name": r[2],
         "last_name": r[3], "created_at": r[4]}
        for r in rows
    ]