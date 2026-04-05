"""
um_members.py – Console UI for the DeclaratieApp Backend System.

Run this file to start the application.
"""

import os

from auth import login, logout, get_current_user, update_password
from users import (
    create_manager, create_employee_account, delete_user,
    list_all_users, reset_user_password, update_user_profile,
)
from employees import (
    add_employee, update_employee, delete_employee,
    search_employees, get_employee_by_id, list_all_employees, _generate_employee_id,
)
from claims import (
    add_claim, update_claim, delete_claim, search_claims, get_claim_by_id,
    approve_claim, reject_claim, assign_salary_batch, list_claims_by_employee,
)
from activity_log import get_all_logs, display_logs, check_suspicious_activities
from backup import (
    create_backup, restore_backup, generate_restore_code,
    revoke_restore_code, list_backups, list_restore_codes,
)
from validation import (
    ValidationError, VALID_CITIES,
    validate_email, validate_phone, validate_zipcode, validate_birthday,
    validate_username, validate_password, validate_city, validate_claim_date,
    validate_travel_distance, validate_salary_batch, validate_name,
    validate_house_number, validate_project_number, validate_nonempty,
    validate_identity_document_number, validate_bsn_number, _matches,
    validate_employee_id, validate_id
)
from input_handlers import (
    CancelInputException,
    prompt_with_validation, prompt_password_with_confirmation,
    prompt_menu_choice, prompt_confirmation, prompt_optional_field,
    prompt_choice_from_list, validate_password_input, validate_username_input,
    validate_number_input, validate_restore_code_input,
)


# ═════════════════════════════════════════════════════════════════════════
# UTILITIES
# ═════════════════════════════════════════════════════════════════════════
def clear():
    os.system("cls" if os.name == "nt" else "clear")


def header(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


def user_info():
    u = get_current_user()
    if u:
        print(f"\nLogged in as: {u['username']} ({u['role_name']})")


def pause():
    input("\nPress Enter to continue...")


def validate_unique_username(username):
    username = validate_username(username)
    if any(u["username"] == username for u in list_all_users()):
        raise ValidationError(f"Username '{username}' already exists")
    return username


# ═════════════════════════════════════════════════════════════════════════
# MAIN MENU
# ═════════════════════════════════════════════════════════════════════════
def show_main_menu():
    u = get_current_user()
    if not u:
        return False
    clear()
    header("DECLARATIEAPP BACKEND SYSTEM")
    user_info()

    sc = check_suspicious_activities()
    if sc > 0:
        print(f"\n  WARNING: {sc} suspicious activities detected! Check logs.")

    print("\nMAIN MENU:")
    if u["role"] == "super_admin":
        for i, t in enumerate(["Manage Managers", "Manage Employees", "Manage Claims",
                                "View System Logs", "Backup & Restore", "View My Profile",
                                "Logout"], 1):
            print(f"  {i}. {t}")
    elif u["role"] == "manager":
        for i, t in enumerate(["Manage Employees", "Manage Claims", "View System Logs",
                                "Backup & Restore", "View My Profile", "Update My Password",
                                "Update My Account", "Delete My Account", "Logout"], 1):
            print(f"  {i}. {t}")
    elif u["role"] == "employee":
        for i, t in enumerate(["My Claims", "View My Profile",
                                "Update My Password", "Logout"], 1):
            print(f"  {i}. {t}")
    print("\n" + "-" * 70)
    return True


# ═════════════════════════════════════════════════════════════════════════
# MANAGER MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════
def manage_managers_menu():
    while True:
        clear(); header("MANAGE MANAGERS"); user_info()
        for i, t in enumerate(["Create New Manager", "List All Managers",
                                "Reset Manager Password", "Update Manager Profile",
                                "Delete Manager", "Back"], 1):
            print(f"  {i}. {t}")
        try:
            ch = prompt_menu_choice("\nChoice (1-6): ", 1, 6)
        except CancelInputException:
            break
        {"1": create_manager_ui, "2": list_managers_ui, "3": reset_manager_pw_ui,
         "4": update_manager_ui, "5": delete_manager_ui}.get(ch, lambda: None)()
        if ch == "6":
            break


def create_manager_ui():
    clear(); header("CREATE NEW MANAGER"); user_info()
    print("\nUsername: 8-10 chars, start with letter or '_', a-z 0-9 _ ' .")
    try:
        un = prompt_with_validation("\nUsername: ", validate_unique_username)
        fn = prompt_with_validation("First name: ", lambda x: validate_name(x, "First name"))
        ln = prompt_with_validation("Last name: ", lambda x: validate_name(x, "Last name"))
        ok, msg, pw = create_manager(un, fn, ln)
        print(f"\n{msg}")
        if ok:
            print(f"Temporary password: {pw}")
            print("\n  IMPORTANT: User must change this on first login.")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def list_managers_ui():
    clear(); header("ALL MANAGERS"); user_info()
    users = [u for u in list_all_users() if u["role"] == "manager"]
    if not users:
        print("\nNo managers found.")
    else:
        print(f"\nTotal: {len(users)}")
        print("-" * 70)
        for u in users:
            print(f"  {u['username']:15s}  {u['first_name']} {u['last_name']}  ({u['created_at']})")
        print("-" * 70)
    pause()


def reset_manager_pw_ui():
    clear(); header("RESET MANAGER PASSWORD"); user_info()
    try:
        un = prompt_with_validation("\nManager username: ", validate_username)
        ok, msg, pw = reset_user_password(un)
        print(f"\n{msg}")
        if ok:
            print(f"New temporary password: {pw}")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def update_manager_ui():
    clear(); header("UPDATE MANAGER PROFILE"); user_info()
    try:
        un = prompt_with_validation("\nManager username: ", validate_username)
        mgr = next((u for u in list_all_users()
                     if u["username"] == un and u["role"] == "manager"), None)
        if not mgr:
            print(f"\n  Manager '{un}' not found."); pause(); return

        fn = prompt_optional_field("New first name", lambda x: validate_name(x, "First name"),
                                   mgr["first_name"])
        ln = prompt_optional_field("New last name", lambda x: validate_name(x, "Last name"),
                                   mgr["last_name"])
        updates = {}
        if fn: updates["first_name"] = fn
        if ln: updates["last_name"] = ln
        if updates:
            ok, msg = update_user_profile(un, **updates)
            print(f"\n{msg}")
        else:
            print("\nNo changes.")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def delete_manager_ui():
    clear(); header("DELETE MANAGER"); user_info()
    try:
        un = prompt_with_validation("\nManager username: ", validate_username)
        mgr = next((u for u in list_all_users()
                     if u["username"] == un and u["role"] == "manager"), None)
        if not mgr:
            print(f"\n  Manager '{un}' not found."); pause(); return
        print(f"\n  Found: {mgr['first_name']} {mgr['last_name']} ({mgr['created_at']})")
        if prompt_confirmation("\n  Delete this manager? (yes/no): "):
            ok, msg = delete_user(un)
            print(f"\n{msg}")
        else:
            print("\nCancelled.")
    except CancelInputException:
        print("\nCancelled.")
    pause()


# ═════════════════════════════════════════════════════════════════════════
# EMPLOYEE MANAGEMENT
# ═════════════════════════════════════════════════════════════════════════
def manage_employees_menu():
    while True:
        clear(); header("MANAGE EMPLOYEES"); user_info()
        for i, t in enumerate(["Add Employee", "Search Employees", "List All",
                                "Update Employee", "Delete Employee",
                                "Reset Employee Password", "Back"], 1):
            print(f"  {i}. {t}")
        try:
            ch = prompt_menu_choice("\nChoice (1-7): ", 1, 7)
        except CancelInputException:
            break
        {"1": add_employee_ui, "2": search_employees_ui, "3": list_employees_ui,
         "4": update_employee_ui, "5": delete_employee_ui,
         "6": reset_employee_pw_ui}.get(ch, lambda: None)()
        if ch == "7":
            break


def add_employee_ui():
    clear(); header("ADD NEW EMPLOYEE"); user_info()
    print("\nType 'exit' or 'cancel' to abort.\n")
    try:
        # Account
        print("--- Account ---")
        un = prompt_with_validation("Username (8-10 chars): ", validate_unique_username)

        # Personal
        print("\n--- Personal ---")
        fn = prompt_with_validation("First name: ", lambda x: validate_name(x, "First name"))
        ln = prompt_with_validation("Last name: ", lambda x: validate_name(x, "Last name"))
        bd = prompt_with_validation("Birthday (YYYY-MM-DD): ", validate_birthday)
        gn = prompt_choice_from_list("Gender:", ["Male", "Female"])

        # Address
        print("\n--- Address ---")
        st = prompt_with_validation("Street name: ", lambda x: validate_name(x, "Street name"))
        hn = prompt_with_validation("House number: ", validate_house_number)
        zc = prompt_with_validation("Zip code (1234AB): ", validate_zipcode)
        ct = prompt_choice_from_list("City:", VALID_CITIES)

        # Contact
        print("\n--- Contact ---")
        em = prompt_with_validation("Email: ", validate_email)
        ph = prompt_with_validation("Phone (8 digits, +31-6 added): ", validate_phone)

        # Identity
        print("\n--- Identity ---")
        idt = prompt_choice_from_list("Document type:", ["Passport", "ID-Card"])
        idn = prompt_with_validation("Document number (AB1234567 / A12345678): ",
                                     validate_identity_document_number)
        bsn = prompt_with_validation("BSN (9 digits): ", validate_bsn_number)

        # Create linked account + profile
        eid = _generate_employee_id()
        ok_acc, msg_acc, pw = create_employee_account(un, fn, ln, employee_id=eid)
        if not ok_acc:
            print(f"\n  {msg_acc}"); pause(); return

        ok_emp, msg_emp = add_employee(fn, ln, bd, gn, st, hn, zc, ct, em, ph,
                                       idt, idn, bsn, employee_id=eid)
        if ok_emp:
            print(f"\n  {msg_acc}\n  {msg_emp}")
            print(f"\n  Temporary password: {pw}")
            print("  User must change this on first login.")
        else:
            print(f"\n  Account created but profile failed: {msg_emp}")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def search_employees_ui():
    clear(); header("SEARCH EMPLOYEES"); user_info()
    print("\nSearch by name, ID, zip, city, street. Partial keys accepted.")
    try:
        key = prompt_with_validation("\nSearch (min 2 chars): ",
                                     lambda x: x if len(x) >= 2
                                     else (_ for _ in ()).throw(
                                         ValidationError("Min 2 characters")))
        results = search_employees(key)
        if not results:
            print(f"\nNo matches for '{key}'.")
        else:
            print(f"\nFound {len(results)}:")
            print("-" * 70)
            for e in results:
                print(f"  {e['employee_id']:12s}  {e['first_name']} {e['last_name']:20s}  "
                      f"{e['zip_code']} {e['city']}")
            print("-" * 70)
    except CancelInputException:
        print("\nCancelled.")
    pause()


def list_employees_ui():
    clear(); header("ALL EMPLOYEES"); user_info()
    emps = list_all_employees()
    if not emps:
        print("\nNo employees.")
    else:
        print(f"\nTotal: {len(emps)}")
        print("-" * 70)
        for e in emps:
            print(f"  ID: {e['employee_id']}  Name: {e['first_name']} {e['last_name']}")
            print(f"  Address: {e['street_name']} {e['house_number']}, {e['zip_code']} {e['city']}")
            print(f"  Email: {e['email']}  Phone: {e['mobile_phone']}")
            print(f"  Identity: {e['identity_document_type']} {e['identity_document_number']}")
            print(f"  Registered: {e['registration_date']}")
            print("-" * 70)
    pause()


def update_employee_ui():
    clear(); header("UPDATE EMPLOYEE"); user_info()
    try:
        eid = prompt_with_validation("\nEmployee ID: ", validate_employee_id)
        emp = get_employee_by_id(eid)
        if not emp:
            print(f"\n  Employee '{eid}' not found."); pause(); return

        print(f"\nUpdating: {emp['first_name']} {emp['last_name']}")
        print("Leave blank to keep current. Type 'exit' to abort.\n")

        fields = [
            ("first_name", lambda x: validate_name(x, "First name")),
            ("last_name", lambda x: validate_name(x, "Last name")),
            ("birthday", validate_birthday),
            ("street_name", lambda x: validate_name(x, "Street name")),
            ("house_number", validate_house_number),
            ("zip_code", validate_zipcode),
            ("city", validate_city),
            ("email", validate_email),
            ("mobile_phone", validate_phone),
            ("identity_document_number", validate_identity_document_number),
            ("bsn_number", validate_bsn_number),
        ]
        updates = {}
        for fname, validator in fields:
            val = prompt_optional_field(f"New {fname}", validator, emp.get(fname))
            if val:
                updates[fname] = val

        if not updates:
            print("\nNo changes.")
        elif prompt_confirmation("\nConfirm changes? (yes/no): "):
            ok, msg = update_employee(eid, **updates)
            print(f"\n{msg}")
        else:
            print("\nCancelled.")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def delete_employee_ui():
    clear(); header("DELETE EMPLOYEE"); user_info()
    try:
        eid = prompt_with_validation("\nEmployee ID: ", validate_employee_id)
        emp = get_employee_by_id(eid)
        if not emp:
            print(f"\n  Employee '{eid}' not found."); pause(); return
        print(f"\n  Found: {emp['first_name']} {emp['last_name']} ({emp['email']})")
        if prompt_confirmation("\n  Delete? (yes/no): "):
            ok, msg = delete_employee(eid)
            print(f"\n{msg}")
        else:
            print("\nCancelled.")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def reset_employee_pw_ui():
    clear(); header("RESET EMPLOYEE PASSWORD"); user_info()
    try:
        un = prompt_with_validation("\nEmployee username: ", validate_username)
        ok, msg, pw = reset_user_password(un)
        print(f"\n{msg}")
        if ok:
            print(f"Temporary password: {pw}")
    except CancelInputException:
        print("\nCancelled.")
    pause()


# ═════════════════════════════════════════════════════════════════════════
# CLAIMS (MANAGER / SUPER ADMIN)
# ═════════════════════════════════════════════════════════════════════════
def manage_claims_menu():
    while True:
        clear(); header("MANAGE CLAIMS"); user_info()
        for i, t in enumerate(["Search Claims", "View by Employee", "Approve Claim",
                                "Reject Claim", "Modify Claim",
                                "Assign Salary Batch", "Back"], 1):
            print(f"  {i}. {t}")
        try:
            ch = prompt_menu_choice("\nChoice (1-7): ", 1, 7)
        except CancelInputException:
            break
        {"1": search_claims_ui, "2": view_claims_by_employee_ui,
         "3": approve_claim_ui, "4": reject_claim_ui,
         "5": modify_claim_ui, "6": assign_salary_batch_ui}.get(ch, lambda: None)()
        if ch == "7":
            break


def _show_claims(claims):
    print("-" * 70)
    for c in claims:
        line = f"  ID:{c['id']}  Date:{c['claim_date']}  Type:{c['claim_type']}  "
        line += f"Employee:{c['employee_id']}  Project:{c['project_number']}"
        print(line)
        print(f"  Status:{c['approved']}  Batch:{c['salary_batch'] or '-'}")
        if c["claim_type"] == "Travel":
            print(f"  {c['travel_distance']}km  From:{c['from_zip']} {c['from_housenumber']}  "
                  f"To:{c['to_zip']} {c['to_housenumber']}")
        print("-" * 70)


def _show_claim_detail(c):
    print(f"  Claim ID     : {c['id']}")
    print(f"  Date         : {c['claim_date']}")
    print(f"  Employee     : {c['employee_id']}")
    print(f"  Project      : {c['project_number']}")
    print(f"  Type         : {c['claim_type']}")
    if c["claim_type"] == "Travel":
        print(f"  Distance     : {c['travel_distance']} km")
        print(f"  From         : {c['from_zip']} {c['from_housenumber']}")
        print(f"  To           : {c['to_zip']} {c['to_housenumber']}")
    print(f"  Status       : {c['approved']}")
    print(f"  Approved by  : {c['approved_by'] or '-'}")
    print(f"  Salary batch : {c['salary_batch'] or '-'}")
    print(f"  Created      : {c['created_at']}")


def search_claims_ui():
    clear(); header("SEARCH CLAIMS"); user_info()
    print("\nSearch by ID, employee, date, project, zip, status, batch. Partial keys OK.")
    try:
        key = prompt_with_validation("\nSearch (min 2 chars): ",
                                     lambda x: x if len(x) >= 2
                                     else (_ for _ in ()).throw(
                                         ValidationError("Min 2 characters")))
        results = search_claims(key)
        if not results:
            print(f"\nNo matches for '{key}'.")
        else:
            print(f"\nFound {len(results)}:")
            _show_claims(results)
    except CancelInputException:
        print("\nCancelled.")
    pause()


def view_claims_by_employee_ui():
    clear(); header("CLAIMS BY EMPLOYEE"); user_info()
    try:
        eid = prompt_with_validation("\nEmployee ID: ", validate_employee_id)
        results = list_claims_by_employee(eid)
        if not results:
            print(f"\nNo claims for '{eid}'.")
        else:
            print(f"\nFound {len(results)}:")
            _show_claims(results)
    except CancelInputException:
        print("\nCancelled.")
    pause()


def approve_claim_ui():
    clear(); header("APPROVE CLAIM"); user_info()
    try:
        cid = prompt_with_validation("\nClaim ID: ", validate_id)
        claim = get_claim_by_id(int(cid))
        if not claim:
            print(f"\n  Claim {cid} not found."); pause(); return
        _show_claim_detail(claim)
        batch = prompt_with_validation("\nSalary batch (YYYY-MM): ", validate_salary_batch)
        if prompt_confirmation(f"\nApprove claim {cid} for batch '{batch}'? (yes/no): "):
            ok, msg = approve_claim(int(cid), batch)
            print(f"\n{msg}")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def reject_claim_ui():
    clear(); header("REJECT CLAIM"); user_info()
    try:
        cid = prompt_with_validation("\nClaim ID: ", validate_id)
        claim = get_claim_by_id(int(cid))
        if not claim:
            print(f"\n  Claim {cid} not found."); pause(); return
        _show_claim_detail(claim)
        if prompt_confirmation(f"\nReject claim {cid}? (yes/no): "):
            ok, msg = reject_claim(int(cid))
            print(f"\n{msg}")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def modify_claim_ui():
    clear(); header("MODIFY CLAIM"); user_info()
    try:
        cid = prompt_with_validation("\nClaim ID: ", validate_id)
        claim = get_claim_by_id(int(cid))
        if not claim:
            print(f"\n  Claim {cid} not found."); pause(); return
        _show_claim_detail(claim)
        print("\nModifiable: project_number, travel_distance. Leave blank to skip.\n")
        pn = prompt_optional_field("Project number (2-10 digits)", validate_project_number,
                                   claim["project_number"])
        td = None
        if claim["claim_type"] == "Travel":
            td = prompt_optional_field("Travel distance (km)", validate_travel_distance,
                                       claim["travel_distance"])
        updates = {}
        if pn: updates["project_number"] = pn
        if td: updates["travel_distance"] = td
        if updates and prompt_confirmation("\nConfirm? (yes/no): "):
            ok, msg = update_claim(int(cid), **updates)
            print(f"\n{msg}")
        elif not updates:
            print("\nNo changes.")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def assign_salary_batch_ui():
    clear(); header("ASSIGN SALARY BATCH"); user_info()
    try:
        cid = prompt_with_validation("\nClaim ID: ", validate_id)
        claim = get_claim_by_id(int(cid))
        if not claim:
            print(f"\n  Claim {cid} not found."); pause(); return
        _show_claim_detail(claim)
        batch = prompt_with_validation("\nSalary batch (YYYY-MM): ", validate_salary_batch)
        if prompt_confirmation(f"\nAssign '{batch}' to claim {cid}? (yes/no): "):
            ok, msg = assign_salary_batch(int(cid), batch)
            print(f"\n{msg}")
    except CancelInputException:
        print("\nCancelled.")
    pause()


# ═════════════════════════════════════════════════════════════════════════
# EMPLOYEE CLAIMS
# ═════════════════════════════════════════════════════════════════════════
def employee_claims_menu():
    while True:
        clear(); header("MY CLAIMS"); user_info()
        for i, t in enumerate(["Add New Claim", "View My Claims",
                                "Update My Claim", "Delete My Claim", "Back"], 1):
            print(f"  {i}. {t}")
        try:
            ch = prompt_menu_choice("\nChoice (1-5): ", 1, 5)
        except CancelInputException:
            break
        {"1": add_claim_ui, "2": view_my_claims_ui,
         "3": update_my_claim_ui, "4": delete_my_claim_ui}.get(ch, lambda: None)()
        if ch == "5":
            break


def add_claim_ui():
    clear(); header("ADD NEW CLAIM"); user_info()
    try:
        cd = prompt_with_validation("\nClaim date (YYYY-MM-DD): ", validate_claim_date)
        pn = prompt_with_validation("Project number (2-10 digits): ", validate_project_number)
        ct = prompt_choice_from_list("Claim type:", ["Travel", "Home Office"])

        td = fz = fh = tz = th = None
        if ct == "Travel":
            print("\n--- Travel Info ---")
            td = prompt_with_validation("Distance (km): ", validate_travel_distance)
            fz = prompt_with_validation("From zip (1234AB): ", validate_zipcode)
            fh = prompt_with_validation("From house number: ", validate_house_number)
            tz = prompt_with_validation("To zip (1234AB): ", validate_zipcode)
            th = prompt_with_validation("To house number: ", validate_house_number)

        ok, msg = add_claim(cd, pn, ct, td, fz, fh, tz, th)
        print(f"\n{msg}")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def view_my_claims_ui():
    clear(); header("MY CLAIMS"); user_info()
    u = get_current_user()
    if not u or not u.get("employee_id"):
        print("\n  No employee profile linked."); pause(); return
    results = list_claims_by_employee(u["employee_id"])
    if not results:
        print("\nNo claims.")
    else:
        print(f"\nTotal: {len(results)}")
        _show_claims(results)
    pause()


def update_my_claim_ui():
    clear(); header("UPDATE MY CLAIM"); user_info()
    try:
        cid = prompt_with_validation("\nClaim ID: ", validate_id)
        claim = get_claim_by_id(int(cid))
        if not claim:
            print(f"\n  Claim {cid} not found."); pause(); return
        _show_claim_detail(claim)
        if claim["salary_batch"]:
            print(f"\n  Cannot update: linked to batch '{claim['salary_batch']}'."); pause(); return

        print("\nLeave blank to skip.\n")
        cd = prompt_optional_field("Claim date (YYYY-MM-DD)", validate_claim_date, claim["claim_date"])
        pn = prompt_optional_field("Project number", validate_project_number, claim["project_number"])
        td = fz = fh = tz = th = None
        if claim["claim_type"] == "Travel":
            td = prompt_optional_field("Distance (km)", validate_travel_distance, claim["travel_distance"])
            fz = prompt_optional_field("From zip", validate_zipcode, claim["from_zip"])
            fh = prompt_optional_field("From house nr", validate_house_number, claim["from_housenumber"])
            tz = prompt_optional_field("To zip", validate_zipcode, claim["to_zip"])
            th = prompt_optional_field("To house nr", validate_house_number, claim["to_housenumber"])

        updates = {}
        for k, v in [("claim_date", cd), ("project_number", pn), ("travel_distance", td),
                      ("from_zip", fz), ("from_housenumber", fh), ("to_zip", tz), ("to_housenumber", th)]:
            if v:
                updates[k] = v
        if updates and prompt_confirmation("\nConfirm? (yes/no): "):
            ok, msg = update_claim(int(cid), **updates)
            print(f"\n{msg}")
        elif not updates:
            print("\nNo changes.")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def delete_my_claim_ui():
    clear(); header("DELETE MY CLAIM"); user_info()
    try:
        cid = prompt_with_validation("\nClaim ID: ", validate_id)
        claim = get_claim_by_id(int(cid))
        if not claim:
            print(f"\n  Claim {cid} not found."); pause(); return
        _show_claim_detail(claim)
        if claim["salary_batch"]:
            print(f"\n  Cannot delete: linked to batch '{claim['salary_batch']}'."); pause(); return
        if prompt_confirmation("\n  Delete this claim? (yes/no): "):
            ok, msg = delete_claim(int(cid))
            print(f"\n{msg}")
    except CancelInputException:
        print("\nCancelled.")
    pause()


# ═════════════════════════════════════════════════════════════════════════
# LOGS
# ═════════════════════════════════════════════════════════════════════════
def view_logs_menu():
    while True:
        clear(); header("SYSTEM LOGS"); user_info()
        for i, t in enumerate(["All Logs", "Recent (last 20)",
                                "Suspicious Only", "Back"], 1):
            print(f"  {i}. {t}")
        ch = input("\nChoice (1-4): ")
        if ch == "1":
            clear(); header("ALL LOGS"); display_logs(get_all_logs()); pause()
        elif ch == "2":
            clear(); header("RECENT LOGS"); display_logs(get_all_logs()[-20:]); pause()
        elif ch == "3":
            clear(); header("SUSPICIOUS ACTIVITIES")
            display_logs([l for l in get_all_logs() if l["suspicious"] == "Yes"]); pause()
        elif ch == "4":
            break


# ═════════════════════════════════════════════════════════════════════════
# BACKUP & RESTORE
# ═════════════════════════════════════════════════════════════════════════
def backup_restore_menu():
    u = get_current_user()
    is_sa = u and u["role"] == "super_admin"
    while True:
        clear(); header("BACKUP & RESTORE"); user_info()
        items = ["Create Backup", "List Backups", "Restore Backup"]
        if is_sa:
            items += ["Generate Restore Code", "Revoke Restore Code",
                      "List Restore Codes"]
        items.append("Back")
        for i, t in enumerate(items, 1):
            print(f"  {i}. {t}")
        ch = input(f"\nChoice (1-{len(items)}): ")

        if ch == "1":
            clear(); header("CREATE BACKUP")
            ok, msg, fn = create_backup()
            print(f"\n{msg}"); pause()
        elif ch == "2":
            clear(); header("BACKUPS")
            for b in list_backups():
                print(f"  {b['filename']}  ({b['size']} bytes, {b['created']})")
            pause()
        elif ch == "3":
            _restore_backup_ui()
        elif ch == "4" and is_sa:
            _generate_restore_code_ui()
        elif ch == "5" and is_sa:
            _revoke_restore_code_ui()
        elif ch == "6" and is_sa:
            clear(); header("RESTORE CODES")
            for c in list_restore_codes():
                print(f"  {c['code']}  Manager:{c['target_username']}  Backup:{c['backup_filename']}")
            pause()
        elif ch == str(len(items)):
            break


def _restore_backup_ui():
    u = get_current_user()
    clear(); header("RESTORE BACKUP")
    bk = list_backups()
    if not bk:
        print("\nNo backups."); pause(); return

    for i, b in enumerate(bk, 1):
        print(f"  {i}. {b['filename']} ({b['created']})")
    ch = input(f"\nBackup number (1-{len(bk)}): ")
    if not validate_number_input(ch, len(bk)):
        print("\nInvalid."); pause(); return
    fname = bk[int(ch) - 1]["filename"]

    code = None
    if u and u["role"] == "manager":
        code = input("\nRestore code: ")
        if not validate_restore_code_input(code):
            print("\n  Invalid code format."); pause(); return

    if prompt_confirmation(f"\n  Restore '{fname}'? This overwrites current data. (yes/no): "):
        ok, msg = restore_backup(fname, code)
        print(f"\n{msg}")
    pause()


def _generate_restore_code_ui():
    clear(); header("GENERATE RESTORE CODE")
    try:
        bk = list_backups()
        if not bk:
            print("\nNo backups."); pause(); return
        for i, b in enumerate(bk, 1):
            print(f"  {i}. {b['filename']}")
        ch = prompt_menu_choice(f"\nBackup (1-{len(bk)}): ", 1, len(bk))
        fname = bk[int(ch) - 1]["filename"]
        target = prompt_with_validation("Manager username: ", validate_username)
        ok, msg, code = generate_restore_code(fname, target)
        print(f"\n{msg}")
        if ok:
            print(f"\n  Code: {code}")
            print(f"  For: {target} | Backup: {fname}")
            print("  One-use only. Share securely.")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def _revoke_restore_code_ui():
    clear(); header("REVOKE RESTORE CODE")
    codes = list_restore_codes()
    if not codes:
        print("\nNo active codes."); pause(); return
    for i, c in enumerate(codes, 1):
        print(f"  {i}. {c['code']} – {c['target_username']} – {c['backup_filename']}")
    ch = input(f"\nCode to revoke (1-{len(codes)}): ")
    try:
        sel = codes[int(ch) - 1]
    except (ValueError, IndexError):
        print("\nInvalid."); pause(); return
    if prompt_confirmation(f"\n  Revoke code for {sel['target_username']}? (yes/no): "):
        ok, msg = revoke_restore_code(sel["code"])
        print(f"\n{msg}")
    pause()


# ═════════════════════════════════════════════════════════════════════════
# PROFILE & PASSWORD
# ═════════════════════════════════════════════════════════════════════════
def view_my_profile_ui():
    clear(); header("MY PROFILE")
    u = get_current_user()
    if not u:
        pause(); return
    print(f"\n  Username   : {u['username']}")
    print(f"  Name       : {u['first_name']} {u['last_name']}")
    print(f"  Role       : {u['role_name']}")
    if u.get("must_change_password"):
        print("\n  Status: temporary password – please change it.")
    pause()


def update_my_password_ui():
    clear(); header("UPDATE PASSWORD"); user_info()
    print("\nRequirements: 12-50 chars, lowercase + uppercase + digit + special")
    cur_pw = input("\nCurrent password: ")
    if not cur_pw:
        print("\n  Cannot be empty."); pause(); return

    u = get_current_user()
    from database import get_connection, verify_password as db_verify
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE id = ?", (u["user_id"],))
    row = c.fetchone()
    conn.close()
    if not row or not db_verify(cur_pw, u["username"], row[0]):
        print("\n  Incorrect password."); pause(); return
    print("  Current password verified.")

    try:
        new_pw = prompt_password_with_confirmation(
            "New password: ", validate_password, current_password=cur_pw)
        ok, msg = update_password(cur_pw, new_pw)
        print(f"\n{msg}")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def update_my_account_ui():
    clear(); header("UPDATE MY ACCOUNT"); user_info()
    u = get_current_user()
    if not u:
        pause(); return
    try:
        fn = prompt_optional_field("New first name", lambda x: validate_name(x, "First name"),
                                   u["first_name"])
        ln = prompt_optional_field("New last name", lambda x: validate_name(x, "Last name"),
                                   u["last_name"])
        updates = {}
        if fn: updates["first_name"] = fn
        if ln: updates["last_name"] = ln
        if updates:
            ok, msg = update_user_profile(u["username"], **updates)
            print(f"\n{msg}")
        else:
            print("\nNo changes.")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def delete_my_account_ui():
    clear(); header("DELETE MY ACCOUNT"); user_info()
    u = get_current_user()
    if not u:
        pause(); return
    print(f"\n  WARNING: permanent deletion of {u['username']}")
    try:
        if prompt_confirmation("\n  Are you absolutely sure? (yes/no): "):
            ok, msg = delete_user(u["username"])
            if ok:
                logout()
                print(f"\n{msg}\nYou have been logged out.")
            else:
                print(f"\n  {msg}")
        else:
            print("\nCancelled.")
    except CancelInputException:
        print("\nCancelled.")
    pause()


def force_password_change():
    """Mandatory password change after receiving a temporary password."""
    clear(); header("PASSWORD CHANGE REQUIRED"); user_info()
    print("\nYou must change your temporary password before continuing.")
    print("Requirements: 12-50 chars, lowercase + uppercase + digit + special\n")
    try:
        new_pw = prompt_password_with_confirmation("New password: ", validate_password)
    except CancelInputException:
        print("\n  Cancelled – logging out.")
        logout(); pause(); return

    u = get_current_user()
    from database import get_connection, hash_password as db_hash
    try:
        conn = get_connection()
        c = conn.cursor()
        c.execute("UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                  (db_hash(new_pw), u["user_id"]))
        conn.commit()
        conn.close()
        u["must_change_password"] = False
        print("\n  Password changed. You can now use the system.")
    except Exception as e:
        print(f"\n  Error: {e}")
        logout()
    pause()


# ═════════════════════════════════════════════════════════════════════════
# LOGIN & MAIN LOOP
# ═════════════════════════════════════════════════════════════════════════
def login_screen():
    clear(); header("DECLARATIEAPP – LOGIN")
    print("\n  Hard-coded Super Admin: super_admin / Admin_123?\n")
    un = input("Username: ")
    pw = input("Password: ")
    if not validate_username_input(un) or not validate_password_input(pw, un):
        print("\n  Invalid credentials."); pause(); return False
    ok, msg = login(un, pw)
    if ok:
        print(f"\n  {msg}"); pause()
        u = get_current_user()
        if u and u.get("must_change_password"):
            force_password_change()
        return True
    print(f"\n  {msg}"); pause(); return False


def main():
    print("\n" + "=" * 70)
    print("  DECLARATIEAPP BACKEND SYSTEM")
    print("  Software Quality – Analysis 8")
    print("=" * 70 + "\n")

    from database import init_database
    init_database()
    pause()

    while True:
        if not login_screen():
            retry = prompt_confirmation("\nRetry? (yes/no): ")
            if not retry:
                print("\nGoodbye!"); return
            continue

        while True:
            u = get_current_user()
            if not u or not show_main_menu():
                break
            ch = input("\nChoice: ")

            actions_sa = {"1": manage_managers_menu, "2": manage_employees_menu,
                          "3": manage_claims_menu, "4": view_logs_menu,
                          "5": backup_restore_menu, "6": view_my_profile_ui}
            actions_mgr = {"1": manage_employees_menu, "2": manage_claims_menu,
                           "3": view_logs_menu, "4": backup_restore_menu,
                           "5": view_my_profile_ui, "6": update_my_password_ui,
                           "7": update_my_account_ui, "8": delete_my_account_ui}
            actions_emp = {"1": employee_claims_menu, "2": view_my_profile_ui,
                           "3": update_my_password_ui}

            if u["role"] == "super_admin":
                if ch == "7":
                    logout(); print("\n  Logged out."); pause(); break
                actions_sa.get(ch, lambda: (print("\nInvalid choice."), pause()))()
            elif u["role"] == "manager":
                if ch == "9":
                    logout(); print("\n  Logged out."); pause(); break
                if ch == "8":
                    delete_my_account_ui()
                    if not get_current_user():
                        break
                else:
                    actions_mgr.get(ch, lambda: (print("\nInvalid choice."), pause()))()
            elif u["role"] == "employee":
                if ch == "4":
                    logout(); print("\n  Logged out."); pause(); break
                actions_emp.get(ch, lambda: (print("\nInvalid choice."), pause()))()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nTerminated by user.")
    except Exception as e:
        print(f"\n\nFatal error: {e}")