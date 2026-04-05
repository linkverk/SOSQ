"""
auth.py – Authentication, session management and role-based access control.

Roles: super_admin, manager, employee.
Session is in-memory only (resets on restart).
"""

from database import (
    get_connection, encrypt_username, decrypt_username,
    hash_password, verify_password,
)
from validation import validate_username, validate_password, ValidationError
from activity_log import log_activity

# ── session state ────────────────────────────────────────────────────────
_session = {
    "logged_in": False, "user_id": None, "username": None,
    "role": None, "role_name": None, "first_name": None,
    "last_name": None, "employee_id": None, "must_change_password": False,
}

ROLE_NAMES = {
    "super_admin": "Super Administrator",
    "manager": "Manager",
    "employee": "Employee",
}

# ── permission matrix ────────────────────────────────────────────────────
PERMISSIONS = {
    "super_admin": {
        "modify_claim", "approve_claim", "assign_salary_batch", "view_claims",
        "view_employees", "add_employee", "update_employee", "delete_employee",
        "reset_employee_password",
        "add_manager", "update_manager", "delete_manager", "reset_manager_password",
        "view_logs", "create_backup", "restore_backup",
        "generate_restore_code", "revoke_restore_code",
        "update_own_password",
    },
    "manager": {
        "modify_claim", "approve_claim", "assign_salary_batch", "view_claims",
        "view_employees", "add_employee", "update_employee", "delete_employee",
        "reset_employee_password",
        "view_logs", "create_backup", "restore_backup",
        "update_own_password", "update_own_account", "delete_own_account",
    },
    "employee": {
        "view_claims", "add_claim", "update_own_claim",
        "update_own_password",
    },
}


# ── public API ───────────────────────────────────────────────────────────
def get_current_user():
    return _session.copy() if _session["logged_in"] else None


def is_logged_in():
    return _session["logged_in"]


def get_role_name(role):
    return ROLE_NAMES.get(role, role)


def check_permission(perm):
    if not _session["logged_in"]:
        return False
    return perm in PERMISSIONS.get(_session["role"], set())


def require_permission(perm):
    if not _session["logged_in"]:
        return False, "You must be logged in."
    if not check_permission(perm):
        return False, f"Access denied. Role '{_session['role']}' lacks permission: {perm}"
    return True, None


# ── login / logout ───────────────────────────────────────────────────────
def login(username, password):
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, username, password_hash, role, first_name, last_name, "
        "must_change_password, employee_id FROM users WHERE username = ?",
        (encrypt_username(username),),
    )
    user = c.fetchone()
    conn.close()

    if not user:
        log_activity("unknown", "Unsuccessful login",
                     f"username '{username}' not found", suspicious=True)
        return False, "Invalid username or password"

    uid, enc_un, pw_hash, role, fn, ln, mcp, eid = user
    un = decrypt_username(enc_un)

    if not verify_password(password, un, pw_hash):
        log_activity("unknown", "Unsuccessful login",
                     f"wrong password for '{un}'", suspicious=True)
        return False, "Invalid username or password"

    _session.update(
        logged_in=True, user_id=uid, username=un, role=role,
        role_name=get_role_name(role), first_name=fn, last_name=ln,
        must_change_password=bool(mcp), employee_id=eid,
    )
    log_activity(un, "Logged in")
    return True, f"Welcome {fn} {ln}!"


def logout():
    if not _session["logged_in"]:
        return False, "No user logged in."
    un = _session["username"]
    log_activity(un, "Logged out")
    _session.update(
        logged_in=False, user_id=None, username=None, role=None,
        role_name=None, first_name=None, last_name=None,
        must_change_password=False, employee_id=None,
    )
    return True, f"User {un} logged out."


# ── password change ──────────────────────────────────────────────────────
def update_password(old_password, new_password):
    if not _session["logged_in"]:
        return False, "Not logged in."

    uid, un = _session["user_id"], _session["username"]
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE id = ?", (uid,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, "User not found."

    if not verify_password(old_password, un, row[0]):
        conn.close()
        log_activity(un, "Password change failed", "incorrect current password", suspicious=True)
        return False, "Incorrect current password."

    try:
        new_password = validate_password(new_password)
    except ValidationError as e:
        conn.close()
        return False, f"Invalid new password: {e}"

    if old_password == new_password:
        conn.close()
        return False, "New password must differ from current password."

    c.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
              (hash_password(new_password, un), uid))
    conn.commit()
    conn.close()
    _session["must_change_password"] = False
    log_activity(un, "Password updated")
    return True, "Password updated successfully."


# ── user lookup helpers ──────────────────────────────────────────────────
def get_user_by_username(username):
    try:
        username = validate_username(username)
    except ValidationError:
        return None

    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "SELECT id, username, role, first_name, last_name, created_at "
        "FROM users WHERE username = ?",
        (encrypt_username(username),),
    )
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0], "username": decrypt_username(row[1]),
        "role": row[2], "role_name": get_role_name(row[2]),
        "first_name": row[3], "last_name": row[4], "created_at": row[5],
    }


def list_users_by_role(role=None):
    conn = get_connection()
    c = conn.cursor()
    if role:
        c.execute("SELECT id, username, role, first_name, last_name, created_at "
                   "FROM users WHERE role = ? ORDER BY created_at DESC", (role,))
    else:
        c.execute("SELECT id, username, role, first_name, last_name, created_at "
                   "FROM users ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()
    return [
        {"id": r[0], "username": decrypt_username(r[1]), "role": r[2],
         "role_name": get_role_name(r[2]), "first_name": r[3],
         "last_name": r[4], "created_at": r[5]}
        for r in rows
    ]