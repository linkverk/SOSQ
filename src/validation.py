"""
validation.py – Whitelist-based input validation for DeclaratieApp.

Every public validate_*() function either returns the (cleaned) value
or raises ValidationError.  Boolean is_valid_*() helpers are available
for quick checks without exceptions.
"""

import re
from datetime import datetime, timedelta
from activity_log import log_activity

# ── constants ────────────────────────────────────────────────────────────
VALID_CITIES = [
    "Amsterdam", "Rotterdam", "Utrecht", "Den Haag", "Eindhoven",
    "Groningen", "Tilburg", "Almere", "Breda", "Nijmegen",
]


# ── exception ────────────────────────────────────────────────────────────
class ValidationError(Exception):
    """Raised when user input fails whitelist validation."""


# ── internal helpers ─────────────────────────────────────────────────────
def _check_null_bytes(value, field_name):
    """Detect null-byte injection and log it as suspicious."""

    if "\x00" in value or "%00" in value or "\\x00" in value:
        log_activity(
            "SYSTEM", "Null-byte attack detected",
            f"Field: {field_name}, Value: {repr(value[:50])}", suspicious=True,
        )
        raise ValidationError(f"{field_name} contains invalid null-byte character")


def _matches(value, field_name, pattern, flags=0):
    """Return True when *value* is a string that fully matches *pattern*."""
    if not isinstance(value, str):
        return False
    _check_null_bytes(value, field_name)
    return bool(re.fullmatch(pattern, value, flags))


# ── boolean checkers (used by input_handlers for quick UI checks) ────────
def is_valid_username(username, allow_super_admin=False):
    if username == "super_admin" and allow_super_admin:
        return True
    return _matches(username, "Username", r"[a-z_][a-z0-9_'.]{7,9}")


def is_valid_password(password):
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[~!@#$%&_\-+=`|\\(){}[\]:;'<>,.?/]).{12,50}$"
    return _matches(password, "Password", pattern)


def is_valid_email(email):
    if len(email) > 50:
        return False
    return _matches(email, "Email", r"^[a-z0-9._+-]+@[a-z0-9.-]+\.[a-z]{2,}$")



def is_valid_phone(phone):
    return _matches(phone, "Phone", r"(\+31-6-)?\d{8}")


def is_valid_zipcode(zipcode):
    return _matches(zipcode, "Zipcode", r"\d{4}[A-Z]{2}")


def is_valid_birthday(date_str):
    if not _matches(date_str, "Birthday", r"\d{4}-\d{2}-\d{2}"):
        return False
    try:
        dob = datetime.strptime(date_str, "%Y-%m-%d")
        today = datetime.now()
        return datetime(today.year - 150, today.month, today.day) <= dob <= today
    except ValueError:
        return False


def is_valid_claim_date(date_str):
    if not _matches(date_str, "Claim date", r"\d{4}-\d{2}-\d{2}"):
        return False
    try:
        claim = datetime.strptime(date_str, "%Y-%m-%d")
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        return (today - timedelta(days=62)) <= claim <= (today + timedelta(days=14))
    except ValueError:
        return False


def is_valid_house_number(number):
    return _matches(number, "House number", r"[1-9]\d{0,9}")


def is_valid_project_number(number):
    return _matches(number, "Project number", r"\d{2,10}")


def is_valid_identity_document_number(doc_number):
    return _matches(doc_number, "ID document number", r"[A-Z]{2}\d{7}|[A-Z]\d{8}")


def is_valid_bsn(bsn):
    return _matches(bsn, "BSN", r"\d{9}")


def is_valid_salary_batch(batch):
    return _matches(batch, "Salary batch", r"(?:20\d{2}|2100)-(?:0[1-9]|1[0-2])")


def is_valid_travel_distance(distance):
    return _matches(distance, "Travel distance", r"[1-9]\d{0,3}")


def is_valid_name(name, field_name):
    return _matches(name, field_name, r"[A-Za-z\s\-']{1,50}")


def is_valid_gender(gender):
    return _matches(gender, "Gender", r"Male|Female")


def is_valid_identity_document_type(doc_type):
    return _matches(doc_type, "Identity document type", r"Passport|ID-Card")


def is_valid_employee_id(eid):
    return _matches(eid, "Employee ID", r"EMP\d{6}")
    

def is_valid_id(id_str):
    return _matches(id_str, "ID", r"\d{1,10}")


# ── public validators (return cleaned value or raise) ────────────────────
def validate_username(username):
    if is_valid_username(username):
        return username
    raise ValidationError(
        "Username must be 8-10 chars, start with letter/underscore, "
        "contain only a-z 0-9 _ ' ."
    )


def validate_password(password):
    if is_valid_password(password):
        return password
    raise ValidationError(
        "Password must be 12-50 chars with at least 1 lowercase, "
        "1 uppercase, 1 digit, and 1 special character."
    )


def validate_email(email):
    if is_valid_email(email):
        return email
    raise ValidationError("Invalid email. Expected: user@domain.tld (max 50 chars).")


def validate_phone(phone):
    if is_valid_phone(phone):
        return phone if phone.startswith("+31") else f"+31-6-{phone}"
    raise ValidationError("Phone must be 8 digits (prefix +31-6- is added automatically).")


def validate_zipcode(zipcode):
    if is_valid_zipcode(zipcode):
        return zipcode
    raise ValidationError("Invalid zipcode. Expected format: 1234AB.")


def validate_birthday(date_str):
    if is_valid_birthday(date_str):
        return date_str
    raise ValidationError("Invalid birthday. Use YYYY-MM-DD (realistic date).")


def validate_city(city):
    if city in VALID_CITIES:
        return city
    raise ValidationError(f"City must be one of: {', '.join(VALID_CITIES)}")


def validate_claim_date(date_str):
    if is_valid_claim_date(date_str):
        return date_str
    raise ValidationError(
        "Claim date must be YYYY-MM-DD, max 2 months in the past or 14 days in the future."
    )


def validate_travel_distance(distance):
    if is_valid_travel_distance(distance):
        return distance
    raise ValidationError("Travel distance must be a whole number between 1 and 9999 km.")


def validate_salary_batch(batch):
    if is_valid_salary_batch(batch):
        return batch
    raise ValidationError("Invalid salary batch. Expected YYYY-MM (e.g. 2026-04).")


def validate_name(name, field_name="Name"):
    if is_valid_name(name, field_name):
        return name
    raise ValidationError(
        f"{field_name} must be 1-50 chars: letters, spaces, hyphens, apostrophes."
    )


def validate_house_number(number):
    if is_valid_house_number(number):
        return number
    raise ValidationError("House number must contain digits only.")


def validate_project_number(number):
    if is_valid_project_number(number):
        return number
    raise ValidationError("Project number must be 2-10 digits.")


def validate_gender(gender):
    if is_valid_gender(gender):
        return gender
    raise ValidationError("Gender must be 'Male' or 'Female'.")


def validate_identity_document_type(doc_type):
    if is_valid_identity_document_type(doc_type):
        return doc_type
    raise ValidationError("Identity document type must be 'Passport' or 'ID-Card'.")


def validate_identity_document_number(doc_number):
    if is_valid_identity_document_number(doc_number):
        return doc_number
    raise ValidationError(
        "Document number must be XXDDDDDDD or XDDDDDDDD "
        "(X = uppercase letter, D = digit)."
    )


def validate_bsn_number(bsn):
    if is_valid_bsn(bsn):
        return bsn
    raise ValidationError("BSN must be exactly 9 digits.")


def validate_employee_id(eid):
    if is_valid_employee_id(eid):
        return eid
    raise ValidationError("Invalid employee ID. Expected format: EMP followed by 6 digits (e.g. EMP123456).")


def validate_id(id_str):
    if is_valid_id(id_str):
        return id_str
    raise ValidationError("Invalid ID format. Must be a number higher than 0.")


def validate_nonempty(value, field_name="Input"):
    """Ensure value is a non-empty string."""
    if isinstance(value, str):
        _check_null_bytes(value, field_name)
    raise ValidationError(f"{field_name} cannot be empty.")