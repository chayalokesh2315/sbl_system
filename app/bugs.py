import os
from werkzeug.utils import secure_filename
from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort, current_app, jsonify
from .db import get_db
from .auth import login_required, roles_required
from .notifications import create_notification
from .similarity import find_similar_bugs, find_similar_kb
from . import access

bp = Blueprint("bugs", __name__, url_prefix="/bugs")

SEVERITIES = ["Low", "Medium", "High", "Critical"]
PRIORITIES = ["Low", "Medium", "High", "Urgent"]
STATUSES = ["New", "Assigned", "In Progress", "Fixed", "Testing", "Closed"]
ALLOWED_EXT = {"png", "jpg", "jpeg", "gif", "txt", "log", "pdf"}
DONE_STATUSES = ("Fixed", "Testing", "Closed")
OPEN_STATUSES = ("New", "Assigned", "In Progress")
DUPLICATE_BLOCK_SCORE = 0.65   # at/above this the form asks "submit anyway?"
DUPLICATE_HINT_SCORE = 0.30    # live hint while typing


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT


def log_activity(db, bug_id, action):
    db.execute(
        "INSERT INTO bug_activity (bug_id, user_id, action) VALUES (?, ?, ?)",
        (bug_id, g.user["id"], action),
    )


@bp.route("/")
@login_required
def list_bugs():
    db = get_db()
    status = request.args.get("status", "")
    project_id = request.args.get("project_id", "")
    scope_sql, scope_params = access.bug_scope(g.user, "b")
    query = ("SELECT b.*, p.name AS project_name FROM bugs b JOIN projects p ON p.id = b.project_id "
             f"WHERE {scope_sql}")
    params = list(scope_params)
    if status:
        query += " AND b.status = ?"
        params.append(status)
    if project_id:
        query += " AND b.project_id = ?"
        params.append(project_id)
    query += " ORDER BY b.created_at DESC"
    bugs = db.execute(query, params).fetchall()
    projects = access.accessible_projects(db, g.user)
    return render_template(
        "bugs/list.html", bugs=bugs, projects=projects, statuses=STATUSES,
        selected_status=status, selected_project=project_id
    )


@bp.route("/new", methods=("GET", "POST"))
@login_required
def new_bug():
    db = get_db()
    projects = access.accessible_projects(db, g.user)
    if request.method == "POST":
        title = request.form["title"].strip()
        project_id = request.form["project_id"]
        description = request.form.get("description", "").strip()
        steps = request.form.get("reproduction_steps", "").strip()
        severity = request.form.get("severity", "Medium")
        priority = request.form.get("priority", "Medium")

        if not title or not project_id:
            flash("Title and project are required.", "danger")
            return render_template("bugs/new.html", projects=projects, severities=SEVERITIES,
                                   priorities=PRIORITIES, form=request.form, duplicates=[])

        if not access.has_project_access(db, g.user, project_id):
            flash("You can only report bugs in projects you belong to.", "danger")
            return render_template("bugs/new.html", projects=projects, severities=SEVERITIES,
                                   priorities=PRIORITIES, form=request.form, duplicates=[])

        # Duplicate detection: warn before filing a near-identical bug.
        if not request.form.get("force"):
            duplicates = find_similar_bugs(
                db, title, description, project_id=project_id, min_score=DUPLICATE_BLOCK_SCORE, limit=3,
                scope=access.bug_scope(g.user, "b"),
            )
            if duplicates:
                flash("This looks very similar to an existing bug. Check below, or submit anyway "
                      "(re-attach your file if you had one).", "warning")
                return render_template("bugs/new.html", projects=projects, severities=SEVERITIES,
                                       priorities=PRIORITIES, form=request.form, duplicates=duplicates)

        attachment_path = None
        file = request.files.get("attachment")
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            os.makedirs(current_app.config["UPLOAD_FOLDER"], exist_ok=True)
            unique_name = f"{os.urandom(4).hex()}_{filename}"
            file.save(os.path.join(current_app.config["UPLOAD_FOLDER"], unique_name))
            attachment_path = unique_name

        cur = db.execute(
            """INSERT INTO bugs (project_id, title, description, reproduction_steps, severity,
               priority, status, reported_by, attachment_path)
               VALUES (?, ?, ?, ?, ?, ?, 'New', ?, ?)""",
            (project_id, title, description, steps, severity, priority, g.user["id"], attachment_path),
        )
        bug_id = cur.lastrowid
        log_activity(db, bug_id, f"{g.user['username']} reported this bug.")
        db.commit()
        flash("Bug reported.", "success")
        if not access.can_view_bug(db, g.user, bug_id):
            # e.g. a Developer reporting a bug: it is not assigned to them, so it is not in their list
            flash("It will appear in your list once a manager assigns it to you.", "info")
            return redirect(url_for("bugs.list_bugs"))
        return redirect(url_for("bugs.detail", bug_id=bug_id))

    return render_template("bugs/new.html", projects=projects, severities=SEVERITIES,
                           priorities=PRIORITIES, form={}, duplicates=[])


@bp.route("/check_duplicates")
@login_required
def check_duplicates():
    """Live duplicate hints for the report form (JSON)."""
    title = request.args.get("title", "").strip()
    if len(title) < 4:
        return jsonify([])
    project_id = request.args.get("project_id", type=int)
    found = find_similar_bugs(
        get_db(), title, request.args.get("description", ""), project_id=project_id,
        min_score=DUPLICATE_HINT_SCORE, limit=3, scope=access.bug_scope(g.user, "b"),
    )
    return jsonify([
        dict(id=f["id"], title=f["title"], status=f["status"], percent=f["percent"],
             url=url_for("bugs.detail", bug_id=f["id"]))
        for f in found
    ])


def get_bug_or_404(bug_id):
    db = get_db()
    bug = db.execute(
        """SELECT b.*, p.name AS project_name,
                  ru.username AS reporter_name, au.username AS assignee_name,
                  tu.username AS tester_name
           FROM bugs b
           JOIN projects p ON p.id = b.project_id
           LEFT JOIN users ru ON ru.id = b.reported_by
           LEFT JOIN users au ON au.id = b.assigned_to
           LEFT JOIN users tu ON tu.id = b.assigned_tester
           WHERE b.id = ?""",
        (bug_id,),
    ).fetchone()
    if bug is None:
        abort(404)
    if not access.can_view_bug(db, g.user, bug_id):
        abort(403)          # the bug exists but this user is not allowed to see it
    return bug


def assignable_users(db, project_id):
    """Who a bug of this project may be assigned to: Admins, or Developers/Managers who are
    members of the project (otherwise they could never see the bug they were given)."""
    return db.execute(
        """SELECT u.id, u.username FROM users u
           WHERE u.role IN ('Developer','Manager','Admin')
             AND (u.role = 'Admin' OR EXISTS (SELECT 1 FROM project_members pm
                                              WHERE pm.project_id = ? AND pm.user_id = u.id))
           ORDER BY u.username""",
        (project_id,),
    ).fetchall()


@bp.route("/<int:bug_id>")
@login_required
def detail(bug_id):
    db = get_db()
    bug = get_bug_or_404(bug_id)
    comments = db.execute(
        """SELECT c.*, u.username FROM bug_comments c JOIN users u ON u.id = c.user_id
           WHERE c.bug_id = ? ORDER BY c.created_at ASC""",
        (bug_id,),
    ).fetchall()
    activity = db.execute(
        "SELECT * FROM bug_activity WHERE bug_id = ? ORDER BY created_at DESC", (bug_id,)
    ).fetchall()
    rca = db.execute("SELECT * FROM root_cause_analysis WHERE bug_id = ?", (bug_id,)).fetchall()
    devs = assignable_users(db, bug["project_id"])
    testers = db.execute(
        """SELECT u.id, u.username FROM users u
           JOIN project_members pm ON pm.user_id = u.id
           WHERE u.role = 'Tester' AND pm.project_id = ? ORDER BY u.username""",
        (bug["project_id"],),
    ).fetchall()
    similar_bugs = find_similar_bugs(
        db, bug["title"], bug["description"], exclude_id=bug_id, with_rca=True, limit=5,
        scope=access.bug_scope(g.user, "b"),
    )
    similar_kb = find_similar_kb(db, bug["title"], bug["description"])
    return render_template(
        "bugs/detail.html", bug=bug, comments=comments, activity=activity, rca=rca,
        statuses=STATUSES, devs=devs, testers=testers,
        similar_bugs=similar_bugs, similar_kb=similar_kb
    )


@bp.route("/<int:bug_id>/assign", methods=("POST",))
@login_required
def assign(bug_id):
    db = get_db()
    bug = get_bug_or_404(bug_id)
    assignee_id = request.form.get("assigned_to", type=int)
    allowed = {u["id"] for u in assignable_users(db, bug["project_id"])}
    if assignee_id not in allowed:
        flash("You can only assign a bug to a member of its project.", "danger")
        return redirect(url_for("bugs.detail", bug_id=bug_id))
    assignee = db.execute("SELECT username FROM users WHERE id = ?", (assignee_id,)).fetchone()
    reopened = 1 if bug["status"] in DONE_STATUSES else 0
    db.execute(
        """UPDATE bugs SET assigned_to = ?, status = 'Assigned', updated_at = CURRENT_TIMESTAMP,
           reopen_count = COALESCE(reopen_count, 0) + ? WHERE id = ?""",
        (assignee_id, reopened, bug_id),
    )
    if reopened:
        log_activity(db, bug_id, f"{g.user['username']} reopened this bug (was {bug['status']}).")
    log_activity(db, bug_id, f"{g.user['username']} assigned this bug to {assignee['username'] if assignee else 'someone'}.")
    if assignee:
        create_notification(
            assignee_id,
            f"Bug assigned to you: {bug['title']}",
            url_for("bugs.detail", bug_id=bug_id),
        )
    db.commit()
    flash("Bug assigned.", "success")
    if not access.can_view_bug(db, g.user, bug_id):
        # a Developer who hands their bug to someone else no longer has access to it
        return redirect(url_for("bugs.list_bugs"))
    return redirect(url_for("bugs.detail", bug_id=bug_id))


@bp.route("/<int:bug_id>/assign_tester", methods=("POST",))
@roles_required("Admin", "Manager")
def assign_tester(bug_id):
    db = get_db()
    bug = get_bug_or_404(bug_id)
    tester_id = request.form.get("assigned_tester")
    tester = db.execute(
        "SELECT id, username FROM users WHERE id = ? AND role = 'Tester'", (tester_id,)
    ).fetchone()
    if tester is None:
        flash("Please select a valid tester.", "danger")
        return redirect(url_for("bugs.detail", bug_id=bug_id))
    db.execute(
        "UPDATE bugs SET assigned_tester = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
        (tester["id"], bug_id),
    )
    log_activity(db, bug_id, f"{g.user['username']} assigned tester {tester['username']}.")
    create_notification(
        tester["id"],
        f"You are the assigned tester for: {bug['title']}",
        url_for("bugs.detail", bug_id=bug_id),
    )
    db.commit()
    flash("Tester assigned.", "success")
    return redirect(url_for("bugs.detail", bug_id=bug_id))


@bp.route("/<int:bug_id>/status", methods=("POST",))
@login_required
def update_status(bug_id):
    db = get_db()
    bug = get_bug_or_404(bug_id)
    new_status = request.form.get("status")
    if new_status not in STATUSES:
        abort(400)
    reopened = 1 if (bug["status"] in DONE_STATUSES and new_status in OPEN_STATUSES) else 0
    db.execute(
        """UPDATE bugs SET status = ?, updated_at = CURRENT_TIMESTAMP,
           reopen_count = COALESCE(reopen_count, 0) + ? WHERE id = ?""",
        (new_status, reopened, bug_id),
    )
    log_activity(db, bug_id, f"{g.user['username']} changed status to {new_status}.")
    if reopened:
        log_activity(db, bug_id, f"{g.user['username']} reopened this bug (was {bug['status']}).")
        if bug["assigned_to"] and bug["assigned_to"] != g.user["id"]:
            create_notification(
                bug["assigned_to"],
                f"Bug reopened: {bug['title']}",
                url_for("bugs.detail", bug_id=bug_id),
            )

    if new_status == "Fixed" and bug["assigned_tester"]:
        create_notification(
            bug["assigned_tester"],
            f"Bug fixed - please test it: {bug['title']}",
            url_for("bugs.detail", bug_id=bug_id),
        )

    if new_status == "Testing" and not bug["assigned_tester"]:
        testers = db.execute(
            """SELECT DISTINCT u.id
               FROM users u
               LEFT JOIN project_members pm ON pm.user_id = u.id AND pm.project_id = ?
               WHERE u.role = 'Tester' AND pm.project_id IS NOT NULL""",
            (bug["project_id"],),
        ).fetchall()
        for tester in testers:
            create_notification(
                tester["id"],
                f"Bug is ready for testing: {bug['title']}",
                url_for("bugs.detail", bug_id=bug_id),
            )

    db.commit()
    flash("Status updated.", "success")
    return redirect(url_for("bugs.detail", bug_id=bug_id))


@bp.route("/<int:bug_id>/comment", methods=("POST",))
@login_required
def add_comment(bug_id):
    get_bug_or_404(bug_id)          # 404 if missing, 403 if the user may not see this bug
    comment = request.form.get("comment", "").strip()
    if comment:
        db = get_db()
        db.execute(
            "INSERT INTO bug_comments (bug_id, user_id, comment) VALUES (?, ?, ?)",
            (bug_id, g.user["id"], comment),
        )
        log_activity(db, bug_id, f"{g.user['username']} commented.")
        db.commit()
    return redirect(url_for("bugs.detail", bug_id=bug_id))
