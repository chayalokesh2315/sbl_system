from flask import Blueprint, render_template, request, redirect, url_for, flash, g, jsonify
from .db import get_db
from .auth import login_required
from .bugs import get_bug_or_404, log_activity
from .similarity import find_similar_bugs, find_similar_kb
from . import ai_assist
from . import access

bp = Blueprint("rca", __name__, url_prefix="/rca")

CATEGORIES = [
    "Requirement Gap", "Design Flaw", "Coding Error", "Configuration Issue",
    "Environment Issue", "Third-Party Dependency", "Data Issue", "Testing Gap", "Other",
]


@bp.route("/bug/<int:bug_id>/new", methods=("GET", "POST"))
@login_required
def new(bug_id):
    bug = get_bug_or_404(bug_id)
    if request.method == "POST":
        category = request.form.get("category")
        root_cause = request.form.get("root_cause", "").strip()
        preventive_action = request.form.get("preventive_action", "").strip()
        recommendation = request.form.get("technical_recommendation", "").strip()

        if not root_cause:
            flash("Root cause is required.", "danger")
        else:
            db = get_db()
            db.execute(
                """INSERT INTO root_cause_analysis
                   (bug_id, category, root_cause, preventive_action, technical_recommendation, created_by)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (bug_id, category, root_cause, preventive_action, recommendation, g.user["id"]),
            )
            log_activity(db, bug_id, f"{g.user['username']} added a root cause analysis.")
            db.commit()
            flash("Root cause analysis recorded.", "success")
            return redirect(url_for("bugs.detail", bug_id=bug_id))

    return render_template("rca/new.html", bug=bug, categories=CATEGORIES,
                           ai_enabled=ai_assist.is_configured())


@bp.route("/bug/<int:bug_id>/suggest", methods=("POST",))
@login_required
def suggest(bug_id):
    """Return an RCA suggestion (JSON). It only pre-fills the form; nothing is saved here."""
    if not access.can_view_bug(get_db(), g.user, bug_id):
        # JSON endpoint: answer with JSON instead of the usual redirect page
        return jsonify(error="You don't have permission to access that bug."), 403
    bug = get_bug_or_404(bug_id)
    if not ai_assist.allow_request(g.user["id"]):
        return jsonify(error="Too many suggestion requests. Please wait a minute and try again."), 429
    db = get_db()
    similar_bugs = find_similar_bugs(
        db, bug["title"], bug["description"], exclude_id=bug_id, with_rca=True, limit=3,
        scope=access.bug_scope(g.user, "b"),
    )
    similar_kb = find_similar_kb(db, bug["title"], bug["description"], limit=2)
    result = ai_assist.suggest_rca(bug, similar_bugs, similar_kb, CATEGORIES,
                                   force_offline=request.form.get("offline") == "1")
    label = "Gemini AI" if result["source"] == "gemini" else "rule-based"
    log_activity(db, bug_id, f"{g.user['username']} requested a {label} root-cause suggestion.")
    db.commit()
    return jsonify(result)


@bp.route("/")
@login_required
def list_all():
    db = get_db()
    scope_sql, scope_params = access.bug_scope(g.user, "b")
    rows = db.execute(
        f"""SELECT r.*, b.title AS bug_title, b.id AS bug_id
           FROM root_cause_analysis r JOIN bugs b ON b.id = r.bug_id
           WHERE {scope_sql}
           ORDER BY r.created_at DESC""", scope_params
    ).fetchall()
    return render_template("rca/list.html", rows=rows)
