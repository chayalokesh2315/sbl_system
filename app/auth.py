import functools
from flask import Blueprint, render_template, request, redirect, url_for, session, flash, g
from werkzeug.security import generate_password_hash, check_password_hash
from .db import get_db

bp = Blueprint("auth", __name__, url_prefix="/auth")

ROLES = ["Admin", "Manager", "Developer", "Tester"]


def login_required(view):
    @functools.wraps(view)
    def wrapped(**kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(**kwargs)
    return wrapped


def roles_required(*allowed_roles):
    def decorator(view):
        @functools.wraps(view)
        def wrapped(**kwargs):
            if g.user is None:
                return redirect(url_for("auth.login"))
            if g.user["role"] not in allowed_roles:
                flash("You don't have permission to access that.", "danger")
                return redirect(url_for("dashboard.home"))
            return view(**kwargs)
        return wrapped
    return decorator


@bp.route("/register", methods=("GET", "POST"))
def register():
    if request.method == "POST":
        username = request.form["username"].strip()
        email = request.form["email"].strip()
        password = request.form["password"]
        role = request.form.get("role", "Tester")
        db = get_db()
        error = None

        if not username or not email or not password:
            error = "Username, email, and password are required."
        elif role not in ROLES:
            error = "Invalid role."
        elif db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            error = "That username is already taken."
        elif db.execute("SELECT id FROM users WHERE email = ?", (email,)).fetchone():
            error = "That email is already registered."

        if error is None:
            db.execute(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?)",
                (username, email, generate_password_hash(password), role),
            )
            db.commit()
            flash("Account created. Please log in.", "success")
            return redirect(url_for("auth.login"))
        flash(error, "danger")

    return render_template("auth/register.html", roles=ROLES)


@bp.route("/login", methods=("GET", "POST"))
def login():
    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]
        db = get_db()
        error = None
        user = db.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()

        if user is None or not check_password_hash(user["password_hash"], password):
            error = "Incorrect username or password."

        if error is None:
            session.clear()
            session["user_id"] = user["id"]
            return redirect(url_for("dashboard.home"))
        flash(error, "danger")

    return render_template("auth/login.html")


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/users")
@roles_required("Admin")
def manage_users():
    db = get_db()
    users = db.execute("SELECT * FROM users ORDER BY created_at DESC").fetchall()
    return render_template("auth/users.html", users=users, roles=ROLES)


@bp.route("/users/<int:user_id>/role", methods=("POST",))
@roles_required("Admin")
def change_role(user_id):
    role = request.form.get("role")
    if role in ROLES:
        db = get_db()
        db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
        db.commit()
        flash("Role updated.", "success")
    return redirect(url_for("auth.manage_users"))
