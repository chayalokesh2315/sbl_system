from flask import Blueprint, render_template, request, redirect, url_for, flash, g
from .db import get_db
from .auth import login_required, roles_required

bp = Blueprint("kb", __name__, url_prefix="/kb")


@bp.route("/")
@login_required
def list_articles():
    db = get_db()
    q = request.args.get("q", "").strip()
    if q:
        like = f"%{q}%"
        articles = db.execute(
            """SELECT k.*, u.username FROM knowledge_base k LEFT JOIN users u ON u.id = k.created_by
               WHERE k.title LIKE ? OR k.problem_summary LIKE ? OR k.solution LIKE ? OR k.tags LIKE ?
               ORDER BY k.created_at DESC""",
            (like, like, like, like),
        ).fetchall()
    else:
        articles = db.execute(
            """SELECT k.*, u.username FROM knowledge_base k LEFT JOIN users u ON u.id = k.created_by
               ORDER BY k.created_at DESC"""
        ).fetchall()
    return render_template("kb/list.html", articles=articles, q=q)


@bp.route("/new", methods=("GET", "POST"))
@roles_required("Admin", "Manager")
def new_article():
    bug_id = request.args.get("bug_id", type=int)
    if request.method == "POST":
        title = request.form.get("title", "").strip()
        problem_summary = request.form.get("problem_summary", "").strip()
        solution = request.form.get("solution", "").strip()
        tags = request.form.get("tags", "").strip()
        linked_bug_id = request.form.get("bug_id") or None

        if not title or not solution:
            flash("Title and solution are required.", "danger")
        else:
            db = get_db()
            db.execute(
                """INSERT INTO knowledge_base (bug_id, title, problem_summary, solution, tags, created_by)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (linked_bug_id, title, problem_summary, solution, tags, g.user["id"]),
            )
            db.commit()
            flash("Knowledge base article saved.", "success")
            return redirect(url_for("kb.list_articles"))

    return render_template("kb/new.html", bug_id=bug_id)


@bp.route("/<int:article_id>")
@login_required
def detail(article_id):
    db = get_db()
    article = db.execute(
        """SELECT k.*, u.username FROM knowledge_base k LEFT JOIN users u ON u.id = k.created_by
           WHERE k.id = ?""",
        (article_id,),
    ).fetchone()
    return render_template("kb/detail.html", article=article)
