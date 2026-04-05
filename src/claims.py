"""
claims.py – Claim management (travel and home-office expense claims).

Employees create/update/delete their own claims.
Managers and Super Admin approve/reject and assign salary batches.
"""

from database import (
    get_connection, encrypt_username, decrypt_username,
    encrypt_field, decrypt_field,
)
from validation import (
    ValidationError,
    validate_claim_date, validate_project_number, validate_travel_distance,
    validate_salary_batch, validate_zipcode, validate_house_number,
)
from auth import get_current_user, check_permission
from activity_log import log_activity


# ── helpers ──────────────────────────────────────────────────────────────
def _decrypt_row(row):
    return {
        "id": row[0],
        "claim_date": decrypt_field(row[1]),
        "project_number": decrypt_field(row[2]),
        "employee_id": row[3],
        "claim_type": decrypt_field(row[4]),
        "travel_distance": decrypt_field(row[5]) if row[5] else None,
        "from_zip": decrypt_username(row[6]) if row[6] else None,
        "from_housenumber": decrypt_field(row[7]) if row[7] else None,
        "to_zip": decrypt_username(row[8]) if row[8] else None,
        "to_housenumber": decrypt_field(row[9]) if row[9] else None,
        "approved": row[10],
        "approved_by": row[11],
        "salary_batch": decrypt_field(row[12]) if row[12] else None,
        "created_at": row[13],
    }


def _has_salary_batch(claim_id):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT salary_batch FROM claims WHERE id = ?", (claim_id,))
    row = c.fetchone()
    conn.close()
    return row is not None and row[0] not in (None, "")


def _validate_claim_type(claim_type):
    if claim_type in ("Travel", "Home Office"):
        return claim_type
    raise ValidationError("Claim type must be 'Travel' or 'Home Office'.")


# ── field encryption + validation map ────────────────────────────────────
_FIELD_VALIDATORS = {
    "claim_date": validate_claim_date,
    "project_number": validate_project_number,
    "claim_type": _validate_claim_type,
    "travel_distance": validate_travel_distance,
    "from_zip": validate_zipcode,
    "from_housenumber": validate_house_number,
    "to_zip": validate_zipcode,
    "to_housenumber": validate_house_number,
}

_ZIP_FIELDS = {"from_zip", "to_zip"}


def _encrypt_claim_field(field, value):
    if field in _ZIP_FIELDS:
        return encrypt_username(value)
    return encrypt_field(value)


# ── create ───────────────────────────────────────────────────────────────
def add_claim(claim_date, project_number, claim_type,
              travel_distance=None, from_zip=None, from_housenumber=None,
              to_zip=None, to_housenumber=None):
    """Create a new claim for the logged-in employee. Returns (ok, msg)."""
    if not check_permission("add_claim"):
        return False, "Access denied."
    cur = get_current_user()
    if not cur:
        return False, "Not logged in."

    try:
        claim_date = validate_claim_date(claim_date)
        project_number = validate_project_number(project_number)
        claim_type = _validate_claim_type(claim_type)
        if claim_type == "Travel":
            if not all([travel_distance, from_zip, from_housenumber, to_zip, to_housenumber]):
                return False, "Travel claims require all travel fields."
            travel_distance = validate_travel_distance(travel_distance)
            from_zip = validate_zipcode(from_zip)
            from_housenumber = validate_house_number(from_housenumber)
            to_zip = validate_zipcode(to_zip)
            to_housenumber = validate_house_number(to_housenumber)
    except ValidationError as e:
        return False, f"Validation error: {e}"

    conn = get_connection()
    c = conn.cursor()
    employee_id = cur.get("employee_id") or str(cur["user_id"])

    c.execute(
        "INSERT INTO claims (claim_date, project_number, employee_id, claim_type, "
        "travel_distance, from_zip, from_housenumber, to_zip, to_housenumber) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (encrypt_field(claim_date), encrypt_field(project_number), employee_id,
         encrypt_field(claim_type),
         encrypt_field(travel_distance) if travel_distance else None,
         encrypt_username(from_zip) if from_zip else None,
         encrypt_field(from_housenumber) if from_housenumber else None,
         encrypt_username(to_zip) if to_zip else None,
         encrypt_field(to_housenumber) if to_housenumber else None),
    )
    cid = c.lastrowid
    conn.commit()
    conn.close()
    log_activity(cur["username"], "Claim added",
                 f"ID: {cid}, Type: {claim_type}, Date: {claim_date}")
    return True, f"Claim added (ID: {cid})."


# ── update ───────────────────────────────────────────────────────────────
def update_claim(claim_id, **updates):
    """Update a claim with role-based field restrictions. Returns (ok, msg)."""
    cur = get_current_user()
    if not cur:
        return False, "Not logged in."
    if not updates:
        return False, "Nothing to update."

    role = cur["role"]
    manager_fields = {"project_number", "travel_distance"}
    employee_fields = {"claim_date", "project_number", "claim_type",
                       "travel_distance", "from_zip", "from_housenumber",
                       "to_zip", "to_housenumber"}

    if role in ("super_admin", "manager"):
        if not check_permission("modify_claim"):
            return False, "Access denied."
        allowed = manager_fields
    elif role == "employee":
        if not check_permission("update_own_claim"):
            return False, "Access denied."
        allowed = employee_fields
    else:
        return False, "Unknown role."

    for f in updates:
        if f not in allowed:
            return False, f"You cannot update field: '{f}'."

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM claims WHERE id = ?", (claim_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, f"Claim {claim_id} not found."

    claim = _decrypt_row(row)

    if role == "employee":
        own_id = cur.get("employee_id") or str(cur["user_id"])
        if claim["employee_id"] != own_id and claim["employee_id"] != str(cur["user_id"]):
            conn.close()
            return False, "You can only edit your own claims."
        if _has_salary_batch(claim_id):
            conn.close()
            return False, "Cannot update: claim is linked to a salary batch."

    fields, params = [], []
    for field, value in updates.items():
        try:
            value = _FIELD_VALIDATORS[field](value)
        except ValidationError as e:
            conn.close()
            return False, f"Validation error for {field}: {e}"
        fields.append(f"{field} = ?")
        params.append(_encrypt_claim_field(field, value))
    params.append(claim_id)

    c.execute(f"UPDATE claims SET {', '.join(fields)} WHERE id = ?", tuple(params))
    conn.commit()
    conn.close()
    log_activity(cur["username"], "Claim updated",
                 f"ID: {claim_id}, fields: {', '.join(updates)}")
    return True, f"Claim {claim_id} updated."


# ── delete ───────────────────────────────────────────────────────────────
def delete_claim(claim_id):
    """Delete own claim (Employee, if not linked to salary batch). Returns (ok, msg)."""
    cur = get_current_user()
    if not cur:
        return False, "Not logged in."
    if not check_permission("update_own_claim"):
        return False, "Access denied."

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM claims WHERE id = ?", (claim_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, f"Claim {claim_id} not found."

    claim = _decrypt_row(row)

    if cur["role"] == "employee":
        own_id = cur.get("employee_id") or str(cur["user_id"])
        if claim["employee_id"] != own_id and claim["employee_id"] != str(cur["user_id"]):
            conn.close()
            return False, "You can only delete your own claims."

    if _has_salary_batch(claim_id):
        conn.close()
        return False, "Cannot delete: claim is linked to a salary batch."

    c.execute("DELETE FROM claims WHERE id = ?", (claim_id,))
    conn.commit()
    conn.close()
    log_activity(cur["username"], "Claim deleted", f"ID: {claim_id}")
    return True, f"Claim {claim_id} deleted."


# ── approval ─────────────────────────────────────────────────────────────
def approve_claim(claim_id, salary_batch):
    """Approve a claim and set salary batch. Returns (ok, msg)."""
    if not check_permission("approve_claim"):
        return False, "Access denied."
    cur = get_current_user()
    try:
        salary_batch = validate_salary_batch(salary_batch)
    except ValidationError as e:
        return False, f"Validation error: {e}"

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM claims WHERE id = ?", (claim_id,))
    if not c.fetchone():
        conn.close()
        return False, f"Claim {claim_id} not found."

    c.execute("UPDATE claims SET approved = 'Approved', approved_by = ?, salary_batch = ? "
              "WHERE id = ?", (cur["username"], encrypt_field(salary_batch), claim_id))
    conn.commit()
    conn.close()
    log_activity(cur["username"], "Claim approved",
                 f"ID: {claim_id}, batch: {salary_batch}")
    return True, f"Claim {claim_id} approved (batch: {salary_batch})."


def reject_claim(claim_id):
    """Reject a claim. Returns (ok, msg)."""
    if not check_permission("approve_claim"):
        return False, "Access denied."
    cur = get_current_user()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM claims WHERE id = ?", (claim_id,))
    if not c.fetchone():
        conn.close()
        return False, f"Claim {claim_id} not found."

    c.execute("UPDATE claims SET approved = 'Rejected', approved_by = ? WHERE id = ?",
              (cur["username"], claim_id))
    conn.commit()
    conn.close()
    log_activity(cur["username"], "Claim rejected", f"ID: {claim_id}")
    return True, f"Claim {claim_id} rejected."


def assign_salary_batch(claim_id, salary_batch):
    """Assign or update salary batch. Returns (ok, msg)."""
    if not check_permission("assign_salary_batch"):
        return False, "Access denied."
    cur = get_current_user()
    try:
        salary_batch = validate_salary_batch(salary_batch)
    except ValidationError as e:
        return False, f"Validation error: {e}"

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM claims WHERE id = ?", (claim_id,))
    if not c.fetchone():
        conn.close()
        return False, f"Claim {claim_id} not found."

    c.execute("UPDATE claims SET salary_batch = ? WHERE id = ?",
              (encrypt_field(salary_batch), claim_id))
    conn.commit()
    conn.close()
    log_activity(cur["username"], "Salary batch assigned",
                 f"ID: {claim_id}, batch: {salary_batch}")
    return True, f"Salary batch '{salary_batch}' assigned to claim {claim_id}."


# ── search & retrieval ───────────────────────────────────────────────────
def search_claims(search_key):
    """Partial-key search across claim fields."""
    if not check_permission("view_claims") or not search_key or len(search_key) < 2:
        return []
    cur = get_current_user()

    conn = get_connection()
    c = conn.cursor()
    if cur and cur["role"] == "employee":
        eid = cur.get("employee_id") or str(cur["user_id"])
        c.execute("SELECT * FROM claims WHERE employee_id = ? ORDER BY created_at DESC", (eid,))
    else:
        c.execute("SELECT * FROM claims ORDER BY created_at DESC")
    rows = c.fetchall()
    conn.close()

    results, key = [], search_key
    for row in rows:
        try:
            cl = _decrypt_row(row)
            searchable = [
                str(cl["id"]), cl["employee_id"],
                cl["claim_date"] or "", cl["project_number"] or "",
                cl["claim_type"] or "", cl["from_zip"] or "",
                cl["to_zip"] or "", cl["approved"] or "",
                cl["salary_batch"] or "",
            ]
            if any(key in s for s in searchable):
                results.append(cl)
        except Exception:
            continue
    return results


def get_claim_by_id(claim_id):
    if not check_permission("view_claims"):
        return None
    cur = get_current_user()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM claims WHERE id = ?", (claim_id,))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    claim = _decrypt_row(row)
    if cur and cur["role"] == "employee":
        own_id = cur.get("employee_id") or str(cur["user_id"])
        if claim["employee_id"] != own_id:
            return None
    return claim


def list_claims_by_employee(employee_id):
    if not check_permission("view_claims"):
        return []
    cur = get_current_user()
    if cur and cur["role"] == "employee":
        own_id = cur.get("employee_id") or str(cur["user_id"])
        if employee_id != own_id:
            return []

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM claims WHERE employee_id = ? ORDER BY created_at DESC",
              (employee_id,))
    rows = c.fetchall()
    conn.close()
    results = []
    for row in rows:
        try:
            results.append(_decrypt_row(row))
        except Exception:
            continue
    return results