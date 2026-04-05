"""
employees.py – Employee profile management (CRUD + search).

Sensitive fields are Fernet-encrypted; searchable fields use AES.
"""

import secrets
import string

from database import (
    get_connection, encrypt_username, decrypt_username,
    encrypt_field, decrypt_field,
)
from validation import (
    ValidationError,
    validate_name, validate_birthday, validate_gender,
    validate_house_number, validate_zipcode, validate_city,
    validate_email, validate_phone,
    validate_identity_document_type, validate_identity_document_number,
    validate_bsn_number,
)
from auth import get_current_user, check_permission
from activity_log import log_activity


# ── helpers ──────────────────────────────────────────────────────────────
def _generate_employee_id():
    """Generate a unique employee ID (EMP + 6 digits)."""
    conn = get_connection()
    c = conn.cursor()
    while True:
        eid = "EMP" + "".join(secrets.choice(string.digits) for _ in range(6))
        c.execute("SELECT id FROM employees WHERE employee_id = ?", (eid,))
        if not c.fetchone():
            conn.close()
            return eid


def _decrypt_row(row):
    """Decrypt a full employee row into a dict."""
    return {
        "id": row[0],
        "employee_id": row[1],
        "first_name": decrypt_username(row[2]),
        "last_name": decrypt_username(row[3]),
        "birthday": decrypt_field(row[4]),
        "gender": decrypt_field(row[5]),
        "street_name": decrypt_field(row[6]),
        "house_number": decrypt_field(row[7]),
        "zip_code": decrypt_username(row[8]),
        "city": decrypt_field(row[9]),
        "email": decrypt_field(row[10]),
        "mobile_phone": decrypt_field(row[11]),
        "identity_document_type": decrypt_field(row[12]),
        "identity_document_number": decrypt_field(row[13]),
        "bsn_number": decrypt_field(row[14]),
        "registration_date": row[15],
    }


# ── field-level encryption mapping ──────────────────────────────────────
_AES_FIELDS = {"first_name", "last_name", "zip_code"}

_VALIDATORS = {
    "first_name": lambda v: validate_name(v, "First name"),
    "last_name": lambda v: validate_name(v, "Last name"),
    "birthday": validate_birthday,
    "gender": validate_gender,
    "street_name": lambda v: validate_name(v, "Street name"),
    "house_number": validate_house_number,
    "zip_code": validate_zipcode,
    "city": validate_city,
    "email": validate_email,
    "mobile_phone": validate_phone,
    "identity_document_type": validate_identity_document_type,
    "identity_document_number": validate_identity_document_number,
    "bsn_number": validate_bsn_number,
}


def _encrypt_value(field, value):
    if field in _AES_FIELDS:
        return encrypt_username(value) if field != "zip_code" else value
    return encrypt_field(value)


# ── create ───────────────────────────────────────────────────────────────
def add_employee(first_name, last_name, birthday, gender, street_name,
                 house_number, zip_code, city, email, mobile_phone,
                 identity_document_type, identity_document_number,
                 bsn_number, employee_id=None):
    """Add a new employee profile. Returns (ok, msg)."""
    if not check_permission("add_employee"):
        return False, "Access denied."

    cur = get_current_user()
    raw = dict(first_name=first_name, last_name=last_name, birthday=birthday,
               gender=gender, street_name=street_name, house_number=house_number,
               zip_code=zip_code, city=city, email=email, mobile_phone=mobile_phone,
               identity_document_type=identity_document_type,
               identity_document_number=identity_document_number, bsn_number=bsn_number)

    try:
        for field in raw:
            raw[field] = _VALIDATORS[field](raw[field])
    except ValidationError as e:
        return False, f"Validation error: {e}"

    if employee_id is None:
        employee_id = _generate_employee_id()

    conn = get_connection()
    c = conn.cursor()
    c.execute(
        "INSERT INTO employees "
        "(employee_id, first_name, last_name, birthday, gender, street_name, "
        "house_number, zip_code, city, email, mobile_phone, "
        "identity_document_type, identity_document_number, bsn_number) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (employee_id,
         encrypt_username(raw["first_name"]),
         encrypt_username(raw["last_name"]),
         encrypt_field(raw["birthday"]),
         encrypt_field(raw["gender"]),
         encrypt_field(raw["street_name"]),
         encrypt_field(raw["house_number"]),
         encrypt_username(raw["zip_code"]),
         encrypt_field(raw["city"]),
         encrypt_field(raw["email"]),
         encrypt_field(raw["mobile_phone"]),
         encrypt_field(raw["identity_document_type"]),
         encrypt_field(raw["identity_document_number"]),
         encrypt_field(raw["bsn_number"])),
    )
    conn.commit()
    conn.close()

    if cur:
        log_activity(cur["username"], "Employee added",
                     f"ID: {employee_id}, Name: {raw['first_name']} {raw['last_name']}")
    return True, f"Employee '{raw['first_name']} {raw['last_name']}' added (ID: {employee_id})."


# ── update ───────────────────────────────────────────────────────────────
def update_employee(employee_id, **updates):
    """Update employee fields. Returns (ok, msg)."""
    if not check_permission("update_employee"):
        return False, "Access denied."
    if not updates:
        return False, "Nothing to update."

    cur = get_current_user()
    protected = {"employee_id", "registration_date"}
    for f in updates:
        if f in protected:
            return False, f"Field '{f}' cannot be modified."
        if f not in _VALIDATORS:
            return False, f"Invalid field: {f}"

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM employees WHERE employee_id = ?", (employee_id,))
    if not c.fetchone():
        conn.close()
        return False, f"Employee '{employee_id}' not found."

    fields, params = [], []
    for field, value in updates.items():
        try:
            value = _VALIDATORS[field](value)
        except ValidationError as e:
            conn.close()
            return False, f"Validation error for {field}: {e}"
        fields.append(f"{field} = ?")
        params.append(_encrypt_value(field, value))
    params.append(employee_id)

    c.execute(f"UPDATE employees SET {', '.join(fields)} WHERE employee_id = ?",
              tuple(params))
    conn.commit()
    conn.close()

    if cur:
        log_activity(cur["username"], "Employee updated",
                     f"ID: {employee_id}, fields: {', '.join(updates)}")
    return True, f"Employee '{employee_id}' updated."


# ── delete ───────────────────────────────────────────────────────────────
def delete_employee(employee_id):
    """Delete an employee profile. Returns (ok, msg)."""
    if not check_permission("delete_employee"):
        return False, "Access denied."

    cur = get_current_user()
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT first_name, last_name FROM employees WHERE employee_id = ?",
              (employee_id,))
    row = c.fetchone()
    if not row:
        conn.close()
        return False, f"Employee '{employee_id}' not found."

    name = f"{decrypt_username(row[0])} {decrypt_username(row[1])}"
    c.execute("DELETE FROM employees WHERE employee_id = ?", (employee_id,))
    conn.commit()
    conn.close()

    if cur:
        log_activity(cur["username"], "Employee deleted", f"ID: {employee_id}, Name: {name}")
    return True, f"Employee '{employee_id}' deleted."


# ── search & retrieval ───────────────────────────────────────────────────
def search_employees(search_key):
    """Partial-key search across employee fields."""
    if not check_permission("view_employees") or not search_key or len(search_key) < 2:
        return []

    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM employees ORDER BY registration_date DESC")
    rows = c.fetchall()
    conn.close()

    results, key = [], search_key
    for row in rows:
        try:
            emp = _decrypt_row(row)
            searchable = [
                emp["employee_id"], emp["first_name"], emp["last_name"],
                emp["zip_code"], emp["city"], emp["street_name"],
            ]
            if any(key in s for s in searchable):
                results.append(emp)
        except Exception:
            continue
    return results


def get_employee_by_id(employee_id):
    if not check_permission("view_employees"):
        return None
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM employees WHERE employee_id = ?", (employee_id,))
    row = c.fetchone()
    conn.close()
    return _decrypt_row(row) if row else None


def list_all_employees():
    if not check_permission("view_employees"):
        return []
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM employees ORDER BY registration_date DESC")
    rows = c.fetchall()
    conn.close()
    results = []
    for row in rows:
        try:
            results.append(_decrypt_row(row))
        except Exception:
            continue
    return results