"""
activity_log.py – Encrypted activity logging (Fernet).

Log entries are stored as CSV inside a single Fernet-encrypted blob.
The file is unreadable outside the application.
"""

import csv
from datetime import datetime
from pathlib import Path
from cryptography.fernet import Fernet

DATA_DIR = Path(__file__).parent / "data"
LOG_FILE = DATA_DIR / "system.log"
FERNET_KEY_FILE = DATA_DIR / "fernet_key.bin"
LAST_CHECK_FILE = DATA_DIR / "last_log_check.txt"

_HEADER = "No.,Date,Time,Username,Activity,Additional Info,Suspicious\n"


# ── encryption helpers ───────────────────────────────────────────────────
def _cipher():
    if not FERNET_KEY_FILE.exists():
        raise FileNotFoundError("Fernet key not found – run database.py first.")
    return Fernet(FERNET_KEY_FILE.read_bytes())


def _encrypt(text):
    return _cipher().encrypt(text.encode())


def _decrypt(data):
    return _cipher().decrypt(data).decode()


# ── writing ──────────────────────────────────────────────────────────────
def log_activity(username, activity, additional_info="", suspicious=False):
    """Append one entry to the encrypted log file."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Read existing content (or start fresh)
    content = _HEADER
    if LOG_FILE.exists():
        try:
            content = _decrypt(LOG_FILE.read_bytes())
        except Exception:
            content = _HEADER

    # Determine next log number
    lines = content.strip().split("\n")
    log_number = 1
    if len(lines) > 1:
        try:
            log_number = int(lines[-1].split(",")[0].strip('"')) + 1
        except (ValueError, IndexError):
            log_number = len(lines)

    now = datetime.now()
    entry = [
        str(log_number),
        now.strftime("%d-%m-%Y"),
        now.strftime("%H:%M:%S"),
        username,
        activity,
        additional_info,
        "Yes" if suspicious else "No",
    ]

    content += ",".join(f'"{f}"' for f in entry) + "\n"
    LOG_FILE.write_bytes(_encrypt(content))


# ── reading ──────────────────────────────────────────────────────────────
def get_all_logs():
    """Return list of log dicts (decrypted)."""
    if not LOG_FILE.exists():
        return []
    try:
        text = _decrypt(LOG_FILE.read_bytes())
        reader = csv.DictReader(text.strip().split("\n"))
        return [
            {
                "no": int(row["No."]),
                "date": row["Date"],
                "time": row["Time"],
                "username": row["Username"],
                "activity": row["Activity"],
                "additional_info": row["Additional Info"],
                "suspicious": row["Suspicious"],
            }
            for row in reader
        ]
    except Exception:
        return []


def get_suspicious_logs():
    return [l for l in get_all_logs() if l["suspicious"] == "Yes"]


def get_unread_suspicious_count():
    """Count suspicious logs added since the last time an admin viewed them."""
    last = 0
    if LAST_CHECK_FILE.exists():
        try:
            last = int(LAST_CHECK_FILE.read_text().strip())
        except Exception:
            pass
    return sum(1 for l in get_suspicious_logs() if l["no"] > last)


def check_suspicious_activities():
    """Alias for get_unread_suspicious_count."""
    return get_unread_suspicious_count()


# ── management ───────────────────────────────────────────────────────────
def mark_logs_as_read():
    logs = get_all_logs()
    if logs:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        LAST_CHECK_FILE.write_text(str(max(l["no"] for l in logs)))


def clear_logs():
    try:
        if LOG_FILE.exists():
            LOG_FILE.unlink()
        if LAST_CHECK_FILE.exists():
            LAST_CHECK_FILE.unlink()
        return True, "All logs cleared."
    except Exception as e:
        return False, f"Error clearing logs: {e}"


def display_logs(logs, show_suspicious_only=False):
    """Print logs in a formatted table."""
    if show_suspicious_only:
        logs = [l for l in logs if l["suspicious"] == "Yes"]
    if not logs:
        print("No logs found.")
        return

    w = {"no": 5, "date": 12, "time": 10, "username": 15,
         "activity": 30, "additional_info": 55, "suspicious": 10}
    total = sum(w.values()) + (len(w) - 1) * 3

    print("\n" + "=" * total)
    print(f"{'No.':<{w['no']}} | {'Date':<{w['date']}} | {'Time':<{w['time']}} | "
          f"{'Username':<{w['username']}} | {'Activity':<{w['activity']}} | "
          f"{'Additional Info':<{w['additional_info']}} | {'Suspicious':<{w['suspicious']}}")
    print("=" * total)

    for l in logs:
        print(f"{l['no']:<{w['no']}} | {l['date']:<{w['date']}} | {l['time']:<{w['time']}} | "
              f"{l['username']:<{w['username']}} | {l['activity']:<{w['activity']}} | "
              f"{l['additional_info']:<{w['additional_info']}} | {l['suspicious']:<{w['suspicious']}}")

    print("=" * total)
    print(f"Total: {len(logs)}")
    sus = sum(1 for l in logs if l["suspicious"] == "Yes")
    if sus:
        print(f"  Suspicious: {sus}")