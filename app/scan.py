"""Helper: take an uploaded project .zip, scan it, and auto-create bugs.
Used by app/projects.py (no blueprint of its own)."""
import os
import shutil
import tempfile
from .db import get_db
from .scanner import safe_extract, scan_project, group_findings

MAX_BUGS_PER_SCAN = 100


def ensure_tables(db):
    db.execute("""CREATE TABLE IF NOT EXISTS project_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        project_id INTEGER NOT NULL,
        filename TEXT, stored_name TEXT,
        files_scanned INTEGER, findings_count INTEGER, bugs_created INTEGER,
        created_by INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE)""")
    columns = {row[1] for row in db.execute("PRAGMA table_info(project_scans)").fetchall()}
    if "stored_name" not in columns:
        db.execute("ALTER TABLE project_scans ADD COLUMN stored_name TEXT")
    db.commit()


def run_scan_for_project(project_id, zip_file, user):
    """user = g.user row. Returns a summary dict; raises ValueError on bad input."""
    if not zip_file or not zip_file.filename.lower().endswith(".zip"):
        raise ValueError("Please upload a .zip file of your project.")
    db = get_db()
    ensure_tables(db)
    upload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance", "project_uploads")
    os.makedirs(upload_dir, exist_ok=True)
    # ".upload" (not ".zip"): the Flask dev-server reloader restarts the app whenever a .zip changes,
    # which would kill this very request in the middle of the scan.
    stored_name = os.urandom(8).hex() + ".upload"
    stored_path = os.path.join(upload_dir, stored_name)
    zip_file.save(stored_path)

    tmp = tempfile.mkdtemp(prefix="sbl_scan_")
    try:
        zpath = stored_path
        src = os.path.join(tmp, "src")
        os.makedirs(src)
        try:
            safe_extract(zpath, src)
        except Exception as e:  # BadZipFile, ValueError
            raise ValueError(str(e) or "Invalid zip file.")
        scanned, findings = scan_project(src)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    groups = group_findings(findings)
    created = 0
    for grp in groups[:MAX_BUGS_PER_SCAN]:
        if db.execute("SELECT id FROM bugs WHERE project_id=? AND title=?",
                      (project_id, grp["title"])).fetchone():
            continue
        cur = db.execute(
            """INSERT INTO bugs (project_id, title, description, reproduction_steps,
               severity, priority, status, reported_by) VALUES (?,?,?,?,?,?, 'New', ?)""",
            (project_id, grp["title"], grp["description"], grp["steps"],
             grp["severity"], grp["priority"], user["id"]))
        db.execute("INSERT INTO bug_activity (bug_id, user_id, action) VALUES (?,?,?)",
                   (cur.lastrowid, user["id"],
                    "Bug auto-detected by project scanner (upload by %s)." % user["username"]))
        created += 1
    db.execute("""INSERT INTO project_scans (project_id, filename, stored_name, files_scanned,
                  findings_count, bugs_created, created_by) VALUES (?,?,?,?,?,?,?)""",
               (project_id, zip_file.filename, stored_name, scanned, len(findings), created, user["id"]))
    db.commit()
    return dict(files_scanned=scanned, findings=len(findings), bugs_created=created, groups=groups)
