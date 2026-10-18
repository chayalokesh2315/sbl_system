"""Central access rules for bugs and projects.

Every route that returns or changes bug data goes through these helpers, so the rules are
enforced on the server (in SQL) and not only hidden in the templates.

    Admin      - everything
    Manager    - bugs of the projects they are a member of
    Developer  - ONLY bugs assigned to them, and only in projects they are a member of
    Tester     - unchanged: sees all bugs (no rule was requested for testers)

Project pages, project downloads and releases follow the same project-membership rule for
Managers and Developers. Admin and Tester keep their previous access.
"""
from flask import abort, g, redirect, request, url_for

_MEMBER_SQL = "SELECT project_id FROM project_members WHERE user_id = ?"
RESTRICTED_ROLES = ("Manager", "Developer")


def _role(user):
    return user["role"] if user is not None else None


def is_restricted(user):
    """True for the roles whose access is limited to their own projects."""
    return _role(user) in RESTRICTED_ROLES


def bug_scope(user, alias="b"):
    """SQL condition + params selecting the bugs `user` may see. `alias` is the bugs table alias."""
    a = (alias + ".") if alias else ""
    role = _role(user)
    if role in ("Admin", "Tester"):
        return "1=1", ()
    if role == "Manager":
        return f"{a}project_id IN ({_MEMBER_SQL})", (user["id"],)
    if role == "Developer":
        return (f"({a}assigned_to = ? AND {a}project_id IN ({_MEMBER_SQL}))",
                (user["id"], user["id"]))
    return "0=1", ()


def project_scope(user, column="p.id"):
    """SQL condition + params selecting the projects `user` may access."""
    role = _role(user)
    if role in ("Admin", "Tester"):
        return "1=1", ()
    if role in RESTRICTED_ROLES:
        return f"{column} IN ({_MEMBER_SQL})", (user["id"],)
    return "0=1", ()


def can_view_bug(db, user, bug_id):
    sql, params = bug_scope(user, "b")
    return db.execute(f"SELECT 1 FROM bugs b WHERE b.id = ? AND {sql}", (bug_id, *params)).fetchone() is not None


def has_project_access(db, user, project_id):
    sql, params = project_scope(user, "p.id")
    return db.execute(f"SELECT 1 FROM projects p WHERE p.id = ? AND {sql}", (project_id, *params)).fetchone() is not None


def require_project_access(db, project_id):
    if not has_project_access(db, g.user, project_id):
        abort(403)


def accessible_projects(db, user):
    """Projects for dropdowns (bug filter, report form, new release)."""
    sql, params = project_scope(user, "p.id")
    return db.execute(f"SELECT p.id, p.name FROM projects p WHERE {sql} ORDER BY p.name", params).fetchall()


def guard_uploads():
    """before_request hook: bug attachments live in /static/uploads, which Flask would serve to
    anyone. Require login, and for Managers/Developers require access to the owning bug."""
    if not request.path.startswith("/static/uploads/"):
        return None
    if g.user is None:
        return redirect(url_for("auth.login"))
    if g.user["role"] in ("Admin", "Tester"):
        return None
    from .db import get_db
    db = get_db()
    name = request.path.rsplit("/", 1)[-1]
    row = db.execute("SELECT id FROM bugs WHERE attachment_path = ?", (name,)).fetchone()
    if row is None or not can_view_bug(db, g.user, row["id"]):
        abort(403)
    return None
