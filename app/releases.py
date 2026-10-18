from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort
from .db import get_db
from .auth import login_required, roles_required
from . import access

bp = Blueprint("releases", __name__, url_prefix="/releases")

TYPES = ["Major", "Minor", "Patch", "Hotfix"]
STATUSES = ["Planned", "In Progress", "Released", "Rolled Back"]


@bp.route("/")
@login_required
def list_releases():
    db = get_db()
    pscope, pparams = access.project_scope(g.user, "r.project_id")
    releases = db.execute(
        f"""SELECT r.*, p.name AS project_name FROM releases r
           JOIN projects p ON p.id = r.project_id WHERE {pscope} ORDER BY r.created_at DESC""", pparams
    ).fetchall()
    return render_template("releases/list.html", releases=releases)


@bp.route("/new", methods=("GET", "POST"))
@roles_required("Admin", "Manager")
def new_release():
    db = get_db()
    projects = access.accessible_projects(db, g.user)
    if request.method == "POST":
        project_id = request.form["project_id"]
        access.require_project_access(db, project_id)
        version_number = request.form["version_number"].strip()
        release_type = request.form.get("release_type", "Minor")
        notes = request.form.get("release_notes", "").strip()

        if not version_number:
            flash("Version number is required.", "danger")
        else:
            cur = db.execute(
                """INSERT INTO releases (project_id, version_number, release_type, release_notes, status, created_by)
                   VALUES (?, ?, ?, ?, 'Planned', ?)""",
                (project_id, version_number, release_type, notes, g.user["id"]),
            )
            db.commit()
            flash("Release created.", "success")
            return redirect(url_for("releases.detail", release_id=cur.lastrowid))

    return render_template("releases/new.html", projects=projects, types=TYPES)


def get_release_or_404(release_id):
    db = get_db()
    release = db.execute(
        """SELECT r.*, p.name AS project_name FROM releases r
           JOIN projects p ON p.id = r.project_id WHERE r.id = ?""",
        (release_id,),
    ).fetchone()
    if release is None:
        abort(404)
    access.require_project_access(db, release["project_id"])
    return release


@bp.route("/<int:release_id>")
@login_required
def detail(release_id):
    db = get_db()
    release = get_release_or_404(release_id)
    scope_sql, scope_params = access.bug_scope(g.user, "b")
    included_bugs = db.execute(
        f"""SELECT b.* FROM bugs b JOIN release_bugs rb ON rb.bug_id = b.id
           WHERE rb.release_id = ? AND {scope_sql}""",
        (release_id, *scope_params),
    ).fetchall()
    fixed_bugs = db.execute(
        f"""SELECT b.* FROM bugs b WHERE b.project_id = ? AND b.status IN ('Fixed','Testing','Closed')
           AND b.id NOT IN (SELECT bug_id FROM release_bugs WHERE release_id = ?) AND {scope_sql}""",
        (release["project_id"], release_id, *scope_params),
    ).fetchall()
    deployments = db.execute(
        "SELECT * FROM deployments WHERE release_id = ? ORDER BY deployed_at DESC", (release_id,)
    ).fetchall()
    return render_template(
        "releases/detail.html", release=release, included_bugs=included_bugs,
        fixed_bugs=fixed_bugs, statuses=STATUSES, deployments=deployments
    )


@bp.route("/<int:release_id>/add_bug", methods=("POST",))
@roles_required("Admin", "Manager")
def add_bug(release_id):
    bug_id = request.form.get("bug_id", type=int)
    db = get_db()
    release = get_release_or_404(release_id)        # 403 if the user may not access this project
    bug = db.execute("SELECT project_id FROM bugs WHERE id = ?", (bug_id,)).fetchone()
    if bug is None or bug["project_id"] != release["project_id"] \
            or not access.can_view_bug(db, g.user, bug_id):
        flash("That bug is not available for this release.", "danger")
        return redirect(url_for("releases.detail", release_id=release_id))
    try:
        db.execute(
            "INSERT INTO release_bugs (release_id, bug_id) VALUES (?, ?)", (release_id, bug_id)
        )
        db.commit()
        flash("Bug added to release.", "success")
    except Exception:
        flash("That bug is already in this release.", "warning")
    return redirect(url_for("releases.detail", release_id=release_id))


@bp.route("/<int:release_id>/status", methods=("POST",))
@roles_required("Admin", "Manager")
def update_status(release_id):
    status = request.form.get("status")
    if status not in STATUSES:
        abort(400)
    db = get_db()
    get_release_or_404(release_id)                  # 403 if the user may not access this project
    if status == "Released":
        db.execute(
            "UPDATE releases SET status = ?, released_at = CURRENT_TIMESTAMP WHERE id = ?",
            (status, release_id),
        )
    else:
        db.execute("UPDATE releases SET status = ? WHERE id = ?", (status, release_id))
    db.commit()
    flash("Release status updated.", "success")
    return redirect(url_for("releases.detail", release_id=release_id))
