import json
from flask import Blueprint, render_template, g
from .db import get_db
from .auth import login_required
from . import access

bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")

SEVERITY_ORDER = ["Low", "Medium", "High", "Critical"]


@bp.route("/")
@login_required
def home():
    db = get_db()
    # Every query below only sees the bugs/projects the logged-in user is allowed to access.
    vis, vp = access.bug_scope(g.user, "b")                  # bugs (alias b)
    pvis, pvp = access.project_scope(g.user, "p.id")         # projects (alias p)
    rvis, rvp = access.project_scope(g.user, "r.project_id")  # releases (alias r)

    total_bugs = db.execute(f"SELECT COUNT(*) c FROM bugs b WHERE {vis}", vp).fetchone()["c"]
    open_bugs = db.execute(
        f"SELECT COUNT(*) c FROM bugs b WHERE b.status NOT IN ('Closed') AND {vis}", vp
    ).fetchone()["c"]
    closed_bugs = db.execute(
        f"SELECT COUNT(*) c FROM bugs b WHERE b.status = 'Closed' AND {vis}", vp
    ).fetchone()["c"]
    total_projects = db.execute(f"SELECT COUNT(*) c FROM projects p WHERE {pvis}", pvp).fetchone()["c"]

    status_rows = db.execute(
        f"SELECT b.status AS status, COUNT(*) c FROM bugs b WHERE {vis} GROUP BY b.status", vp
    ).fetchall()
    severity_rows = db.execute(
        f"SELECT b.severity AS severity, COUNT(*) c FROM bugs b WHERE {vis} GROUP BY b.severity", vp
    ).fetchall()

    resolver_rows = db.execute(
        f"""SELECT u.username, COUNT(*) c FROM bugs b JOIN users u ON u.id = b.assigned_to
           WHERE b.status = 'Closed' AND {vis} GROUP BY u.username ORDER BY c DESC LIMIT 8""", vp
    ).fetchall()

    trend_rows = db.execute(
        f"""SELECT date(b.created_at) d, COUNT(*) c FROM bugs b WHERE {vis}
           GROUP BY date(b.created_at) ORDER BY d DESC LIMIT 14""", vp
    ).fetchall()

    recent_bugs = db.execute(
        f"""SELECT b.*, p.name AS project_name FROM bugs b JOIN projects p ON p.id = b.project_id
           WHERE {vis} ORDER BY b.updated_at DESC LIMIT 8""", vp
    ).fetchall()

    # ---------- Advanced analytics ----------
    # Time-to-fix = created -> first time the bug was marked Fixed (falls back to last update).
    ttf_rows = db.execute(
        f"""SELECT b.severity, COUNT(*) n,
                   AVG((julianday(COALESCE(
                        (SELECT MIN(a.created_at) FROM bug_activity a
                          WHERE a.bug_id = b.id AND a.action LIKE '%changed status to Fixed.'),
                        b.updated_at)) - julianday(b.created_at)) * 24.0) AS hrs
            FROM bugs b WHERE b.status IN ('Fixed','Testing','Closed') AND {vis}
            GROUP BY b.severity""", vp
    ).fetchall()
    ttf = {r["severity"]: (r["hrs"] or 0.0, r["n"]) for r in ttf_rows}
    ttf_labels = [x for x in SEVERITY_ORDER if x in ttf]
    ttf_hours = [round(ttf[x][0], 2) for x in ttf_labels]
    fixed_n = sum(v[1] for v in ttf.values())
    avg_fix_hours = (sum(v[0] * v[1] for v in ttf.values()) / fixed_n) if fixed_n else None
    avg_fix_text = "-" if avg_fix_hours is None else (
        f"{avg_fix_hours:.1f} h" if avg_fix_hours < 48 else f"{avg_fix_hours / 24:.1f} d")

    reopened_total = db.execute(
        f"SELECT COUNT(*) c FROM bugs b WHERE COALESCE(b.reopen_count, 0) > 0 AND {vis}", vp
    ).fetchone()["c"]
    reopened_bugs = db.execute(
        f"""SELECT b.id, b.title, b.status, b.reopen_count FROM bugs b
           WHERE COALESCE(b.reopen_count, 0) > 0 AND {vis}
           ORDER BY b.reopen_count DESC, b.updated_at DESC LIMIT 5""", vp
    ).fetchall()

    rca_rows = db.execute(
        f"""SELECT c.category AS category, COUNT(*) c FROM root_cause_analysis c
           JOIN bugs b ON b.id = c.bug_id WHERE {vis} GROUP BY c.category ORDER BY COUNT(*) DESC""", vp
    ).fetchall()
    workload_rows = db.execute(
        f"""SELECT u.username, COUNT(*) c FROM bugs b JOIN users u ON u.id = b.assigned_to
           WHERE b.status != 'Closed' AND {vis} GROUP BY u.username ORDER BY c DESC LIMIT 8""", vp
    ).fetchall()
    release_rows = db.execute(
        f"""SELECT p.name || ' ' || r.version_number AS label, COUNT(b.id) c
           FROM releases r JOIN projects p ON p.id = r.project_id
           LEFT JOIN release_bugs rb ON rb.release_id = r.id
           LEFT JOIN bugs b ON b.id = rb.bug_id AND {vis}
           WHERE {rvis}
           GROUP BY r.id ORDER BY r.created_at DESC LIMIT 8""", (*vp, *rvp)
    ).fetchall()

    fixed_total = db.execute(
        f"SELECT COUNT(*) c FROM bugs b WHERE b.status IN ('Fixed','Testing','Closed') AND {vis}", vp
    ).fetchone()["c"]
    fixed_with_rca = db.execute(
        f"""SELECT COUNT(DISTINCT b.id) c FROM bugs b
           JOIN root_cause_analysis r ON r.bug_id = b.id
           WHERE b.status IN ('Fixed','Testing','Closed') AND {vis}""", vp
    ).fetchone()["c"]
    rca_coverage = f"{round(100 * fixed_with_rca / fixed_total)}%" if fixed_total else "-"

    chart_data = {
        "ttf_labels": ttf_labels,
        "ttf_hours": ttf_hours,
        "rca_labels": [r["category"] for r in rca_rows],
        "rca_counts": [r["c"] for r in rca_rows],
        "workload_labels": [r["username"] for r in workload_rows],
        "workload_counts": [r["c"] for r in workload_rows],
        "release_labels": [r["label"] for r in reversed(release_rows)],
        "release_counts": [r["c"] for r in reversed(release_rows)],
        "status_labels": [r["status"] for r in status_rows],
        "status_counts": [r["c"] for r in status_rows],
        "severity_labels": [r["severity"] for r in severity_rows],
        "severity_counts": [r["c"] for r in severity_rows],
        "resolver_labels": [r["username"] for r in resolver_rows],
        "resolver_counts": [r["c"] for r in resolver_rows],
        "trend_labels": [r["d"] for r in reversed(trend_rows)],
        "trend_counts": [r["c"] for r in reversed(trend_rows)],
    }

    return render_template(
        "dashboard/home.html",
        total_bugs=total_bugs, open_bugs=open_bugs, closed_bugs=closed_bugs,
        total_projects=total_projects, recent_bugs=recent_bugs,
        chart_data=json.dumps(chart_data),
        avg_fix_text=avg_fix_text, reopened_total=reopened_total,
        reopened_bugs=reopened_bugs, rca_coverage=rca_coverage,
    )
