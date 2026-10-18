from flask import Blueprint, render_template, redirect, url_for, g, abort
from .db import get_db
from .auth import login_required

bp = Blueprint("notifications", __name__, url_prefix="/notifications")


def create_notification(user_id, message, link=None):
    """Create a notification for a specific user."""
    if not user_id or user_id == g.user["id"]:
        return
    db = get_db()
    db.execute(
        "INSERT INTO notifications (user_id, message, link) VALUES (?, ?, ?)",
        (user_id, message, link),
    )


@bp.route("/")
@login_required
def list_notifications():
    db = get_db()
    notifications = db.execute(
        """SELECT * FROM notifications
           WHERE user_id = ?
           ORDER BY created_at DESC, id DESC""",
        (g.user["id"],),
    ).fetchall()
    return render_template("notifications/list.html", notifications=notifications)


@bp.route("/<int:notification_id>/read", methods=("POST",))
@login_required
def mark_read(notification_id):
    db = get_db()
    notification = db.execute(
        "SELECT id FROM notifications WHERE id = ? AND user_id = ?",
        (notification_id, g.user["id"]),
    ).fetchone()
    if notification is None:
        abort(404)
    db.execute(
        "UPDATE notifications SET is_read = 1 WHERE id = ?",
        (notification_id,),
    )
    db.commit()
    return redirect(request_referrer_or_notifications())


@bp.route("/read-all", methods=("POST",))
@login_required
def mark_all_read():
    db = get_db()
    db.execute(
        "UPDATE notifications SET is_read = 1 WHERE user_id = ?",
        (g.user["id"],),
    )
    db.commit()
    return redirect(url_for("notifications.list_notifications"))


def request_referrer_or_notifications():
    # Avoid depending on an external URL; only redirect to a local page.
    from flask import request
    referrer = request.referrer or ""
    if referrer.startswith("/"):
        return referrer
    return url_for("notifications.list_notifications")
