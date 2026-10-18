from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort, send_from_directory
import os
from .db import get_db
from .auth import login_required, roles_required
from . import access
from .scan import run_scan_for_project

bp = Blueprint("projects", __name__, url_prefix="/projects")


@bp.route("/")
@login_required
def list_projects():
    db = get_db()
    if g.user["role"] == "Admin":
        projects = db.execute("SELECT * FROM projects ORDER BY created_at DESC").fetchall()
    else:
        projects = db.execute(
            """SELECT p.* FROM projects p
               JOIN project_members pm ON pm.project_id = p.id
               WHERE pm.user_id = ?
               ORDER BY p.created_at DESC""",
            (g.user["id"],),
        ).fetchall()
    return render_template("projects/list.html", projects=projects)


@bp.route("/new", methods=("GET", "POST"))
@roles_required("Admin", "Manager")
def new_project():
    if request.method == "POST":
        name = request.form["name"].strip()
        description = request.form.get("description", "").strip()
        if not name:
            flash("Project name is required.", "danger")
        else:
            db = get_db()
            cur = db.execute(
                "INSERT INTO projects (name, description, created_by) VALUES (?, ?, ?)",
                (name, description, g.user["id"]),
            )
            db.execute(
                "INSERT INTO project_members (project_id, user_id, project_role) VALUES (?, ?, ?)",
                (cur.lastrowid, g.user["id"], g.user["role"]),
            )
            db.commit()
            project_id = cur.lastrowid
            flash("Project created.", "success")

            # NEW: optional project upload -> automatic bug detection
            zip_file = request.files.get("project_zip")
            if zip_file and zip_file.filename:
                try:
                    summary = run_scan_for_project(project_id, zip_file, g.user)
                    flash(f"Scan complete: {summary['files_scanned']} files scanned, "
                          f"{summary['bugs_created']} bugs detected.", "info")
                except ValueError as e:
                    flash(f"Project created, but the scan failed: {e}", "warning")
            return redirect(url_for("projects.detail", project_id=project_id))
    return render_template("projects/new.html")


def get_project_or_404(project_id):
    db = get_db()
    project = db.execute("SELECT * FROM projects WHERE id = ?", (project_id,)).fetchone()
    if project is None:
        abort(404)
    return project


@bp.route("/<int:project_id>")
@login_required
def detail(project_id):
    db = get_db()
    project = get_project_or_404(project_id)
    access.require_project_access(db, project_id)
    members = db.execute(
        """SELECT u.id, u.username, u.role, pm.project_role FROM project_members pm
           JOIN users u ON u.id = pm.user_id WHERE pm.project_id = ?""",
        (project_id,),
    ).fetchall()
    scope_sql, scope_params = access.bug_scope(g.user, "b")
    bugs = db.execute(
        f"SELECT b.* FROM bugs b WHERE b.project_id = ? AND {scope_sql} ORDER BY b.created_at DESC LIMIT 10",
        (project_id, *scope_params),
    ).fetchall()
    releases = db.execute(
        "SELECT * FROM releases WHERE project_id = ? ORDER BY created_at DESC LIMIT 5",
        (project_id,),
    ).fetchall()
    all_users = db.execute("SELECT id, username, role FROM users ORDER BY username").fetchall()
    return render_template(
        "projects/detail.html", project=project, members=members, bugs=bugs,
        releases=releases, all_users=all_users
    )


@bp.route("/<int:project_id>/download")
@login_required
def download_project(project_id):
    """Download the most recently uploaded ZIP for a project."""
    get_project_or_404(project_id)
    db = get_db()
    access.require_project_access(db, project_id)
    scan = db.execute(
        """SELECT stored_name, filename FROM project_scans
           WHERE project_id = ? AND stored_name IS NOT NULL
           ORDER BY id DESC LIMIT 1""",
        (project_id,),
    ).fetchone()

    if not scan:
        flash("No uploaded project ZIP is available for download.", "warning")
        return redirect(url_for("projects.detail", project_id=project_id))

    upload_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "instance", "project_uploads")
    if not os.path.exists(os.path.join(upload_dir, scan["stored_name"])):
        flash("The uploaded project ZIP could not be found.", "warning")
        return redirect(url_for("projects.detail", project_id=project_id))

    return send_from_directory(
        upload_dir,
        scan["stored_name"],
        as_attachment=True,
        download_name=scan["filename"] or scan["stored_name"],
    )


@bp.route("/<int:project_id>/members", methods=("POST",))
@roles_required("Admin", "Manager")
def add_member(project_id):
    get_project_or_404(project_id)
    access.require_project_access(get_db(), project_id)
    user_id = request.form.get("user_id")
    project_role = request.form.get("project_role", "").strip()
    db = get_db()
    try:
        db.execute(
            "INSERT INTO project_members (project_id, user_id, project_role) VALUES (?, ?, ?)",
            (project_id, user_id, project_role),
        )
        db.commit()
        flash("Member added.", "success")
    except Exception:
        flash("That user is already on the project.", "warning")
    return redirect(url_for("projects.detail", project_id=project_id))


# NEW: scan an existing project by uploading its .zip
@bp.route("/<int:project_id>/scan", methods=("GET", "POST"))
@roles_required("Admin", "Manager")
def scan(project_id):
    project = get_project_or_404(project_id)
    access.require_project_access(get_db(), project_id)
    if request.method == "POST":
        try:
            summary = run_scan_for_project(project_id, request.files.get("project_zip"), g.user)
        except ValueError as e:
            flash(str(e), "danger")
            return redirect(url_for("projects.scan", project_id=project_id))
        return render_template("projects/scan_result.html", project=project, s=summary)
    return render_template("projects/scan.html", project=project)
