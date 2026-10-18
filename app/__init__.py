import os
from flask import Flask, session, g, redirect, url_for, flash
from . import db as db_module


def create_app():
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get("SBL_SECRET_KEY", "dev-secret-change-in-production")
    app.config["UPLOAD_FOLDER"] = os.path.join(app.root_path, "static", "uploads")
    app.config["MAX_CONTENT_LENGTH"] = 50 * 1024 * 1024  # 50MB uploads (project .zip scans)

    db_module.init_app(app)

    from .auth import bp as auth_bp
    from .projects import bp as projects_bp
    from .bugs import bp as bugs_bp
    from .rca import bp as rca_bp
    from .kb import bp as kb_bp
    from .releases import bp as releases_bp
    from .deploy import bp as deploy_bp
    from .dashboard import bp as dashboard_bp
    from .notifications import bp as notifications_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(projects_bp)
    app.register_blueprint(bugs_bp)
    app.register_blueprint(rca_bp)
    app.register_blueprint(kb_bp)
    app.register_blueprint(releases_bp)
    app.register_blueprint(deploy_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(notifications_bp)

    @app.before_request
    def load_logged_in_user():
        user_id = session.get("user_id")
        if user_id is None:
            g.user = None
        else:
            g.user = db_module.get_db().execute(
                "SELECT * FROM users WHERE id = ?", (user_id,)
            ).fetchone()

    # Bug attachments are served from /static/uploads: require login + access to the owning bug.
    from .access import guard_uploads
    app.before_request(guard_uploads)

    @app.errorhandler(403)
    def forbidden(_error):
        if g.get("user") is None:
            return redirect(url_for("auth.login"))
        flash("You don't have permission to access that.", "danger")
        return redirect(url_for("dashboard.home"))

    @app.route("/")
    def index():
        if g.user:
            return redirect(url_for("dashboard.home"))
        return redirect(url_for("auth.login"))

    @app.context_processor
    def inject_user():
        unread_notifications = 0
        if g.get("user"):
            unread_notifications = db_module.get_db().execute(
                "SELECT COUNT(*) AS count FROM notifications WHERE user_id = ? AND is_read = 0",
                (g.user["id"],),
            ).fetchone()["count"]
        return {
            "current_user": g.get("user"),
            "unread_notifications": unread_notifications,
        }

    return app
