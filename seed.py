"""Populate the database with demo data so the app is ready to explore."""
from werkzeug.security import generate_password_hash
from app import create_app
from app.db import get_db

app = create_app()

with app.app_context():
    db = get_db()

    users = [
        ("admin", "admin@sbl.com", "admin123", "Admin"),
        ("mgr_priya", "priya@sbl.com", "manager123", "Manager"),
        ("dev_rahul", "rahul@sbl.com", "dev123", "Developer"),
        ("dev_asha", "asha@sbl.com", "dev123", "Developer"),
        ("tester_kiran", "kiran@sbl.com", "test123", "Tester"),
    ]
    user_ids = {}
    for username, email, password, role in users:
        existing = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if existing:
            user_ids[username] = existing["id"]
            continue
        cur = db.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
            (username, email, generate_password_hash(password), role),
        )
        user_ids[username] = cur.lastrowid
    db.commit()

    if not db.execute("SELECT id FROM projects").fetchone():
        cur = db.execute(
            "INSERT INTO projects (name, description, created_by) VALUES (?, ?, ?)",
            ("Retail POS Platform", "Point-of-sale web app for retail chains.", user_ids["admin"]),
        )
        project_id = cur.lastrowid
        for uname in users:
            db.execute(
                "INSERT INTO project_members (project_id, user_id, project_role) VALUES (?, ?, ?)",
                (project_id, user_ids[uname[0]], uname[3]),
            )
        db.commit()

        bugs = [
            ("Checkout button unresponsive on mobile", "Tapping 'Pay Now' does nothing on iOS Safari.",
             "1. Open on iPhone Safari\n2. Add item to cart\n3. Tap Pay Now", "High", "Urgent", "In Progress",
             user_ids["tester_kiran"], user_ids["dev_rahul"]),
            ("Incorrect tax calculation for multi-item cart", "Tax is calculated on subtotal before discounts.",
             "1. Add 3 items with a coupon\n2. Check total tax", "Critical", "Urgent", "Fixed",
             user_ids["tester_kiran"], user_ids["dev_asha"]),
            ("Receipt PDF missing store logo", "Generated receipt PDF omits the store branding.",
             "1. Complete a sale\n2. Download receipt PDF", "Low", "Low", "New",
             user_ids["tester_kiran"], None),
            ("Session expires too quickly", "Cashier session times out after 2 minutes of inactivity.",
             "1. Login as cashier\n2. Wait 2 minutes\n3. Try an action", "Medium", "Medium", "Closed",
             user_ids["mgr_priya"], user_ids["dev_rahul"]),
        ]
        bug_ids = []
        for title, desc, steps, sev, pri, status, reporter, assignee in bugs:
            cur = db.execute(
                """INSERT INTO bugs (project_id, title, description, reproduction_steps, severity,
                   priority, status, reported_by, assigned_to) VALUES (?,?,?,?,?,?,?,?,?)""",
                (project_id, title, desc, steps, sev, pri, status, reporter, assignee),
            )
            bug_ids.append(cur.lastrowid)
            db.execute(
                "INSERT INTO bug_activity (bug_id, user_id, action) VALUES (?, ?, ?)",
                (cur.lastrowid, reporter, "Bug reported."),
            )
        db.commit()

        db.execute(
            """INSERT INTO root_cause_analysis (bug_id, category, root_cause, preventive_action,
               technical_recommendation, created_by) VALUES (?,?,?,?,?,?)""",
            (bug_ids[1], "Coding Error", "Tax computed before discount was subtracted from subtotal.",
             "Add unit tests covering discount + tax ordering.",
             "Refactor pricing engine to apply discounts before tax calculation.", user_ids["dev_asha"]),
        )
        db.execute(
            """INSERT INTO knowledge_base (bug_id, title, problem_summary, solution, tags, created_by)
               VALUES (?,?,?,?,?,?)""",
            (bug_ids[3], "Cashier session timeout too aggressive", "Sessions expired mid-transaction.",
             "Increase Flask-Login session lifetime to 30 minutes and add an idle-warning modal at 25 minutes.",
             "session, auth, timeout", user_ids["dev_rahul"]),
        )
        db.commit()

        cur = db.execute(
            """INSERT INTO releases (project_id, version_number, release_type, release_notes, status, created_by)
               VALUES (?,?,?,?,?,?)""",
            (project_id, "v1.3.0", "Minor", "Includes tax fix and session timeout fix.", "Released", user_ids["mgr_priya"]),
        )
        release_id = cur.lastrowid
        db.execute("INSERT INTO release_bugs (release_id, bug_id) VALUES (?, ?)", (release_id, bug_ids[1]))
        db.execute("INSERT INTO release_bugs (release_id, bug_id) VALUES (?, ?)", (release_id, bug_ids[3]))
        db.commit()

        import secrets
        db.execute(
            """INSERT INTO deployments (release_id, environment, deployed_by, verification_token, verified)
               VALUES (?,?,?,?,?)""",
            (release_id, "Production", user_ids["mgr_priya"], secrets.token_urlsafe(16), 1),
        )
        db.commit()

print("Seed data created.")
print("Login as: admin / admin123  (or mgr_priya / manager123, dev_rahul / dev123, tester_kiran / test123)")
