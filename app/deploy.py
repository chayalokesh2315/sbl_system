import secrets
from flask import Blueprint, render_template, request, redirect, url_for, flash, g, abort
from .db import get_db
from .auth import login_required, roles_required
from .releases import get_release_or_404

bp = Blueprint("deploy", __name__, url_prefix="/deploy")

ENVIRONMENTS = ["Staging", "Production"]


def qr_svg_data_uri(text):
    """
    Lightweight QR-style code generator with no external dependencies.
    Falls back to this if the `qrcode` package isn't installed; if it is,
    swap this out for qrcode.make(text) for a spec-compliant QR code.
    """
    try:
        import qrcode
        import io, base64
        img = qrcode.make(text)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
    except ImportError:
        # Deterministic pseudo-QR grid derived from the token, so it's still
        # a unique scannable-looking visual per deployment without a dependency.
        import hashlib
        h = hashlib.sha256(text.encode()).digest()
        size = 21
        cells = []
        for i in range(size * size):
            cells.append(1 if (h[i % len(h)] >> (i % 8)) & 1 else 0)
        cell_px = 8
        svg = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {size*cell_px} {size*cell_px}">']
        svg.append(f'<rect width="100%" height="100%" fill="white"/>')
        for y in range(size):
            for x in range(size):
                if cells[y * size + x]:
                    svg.append(f'<rect x="{x*cell_px}" y="{y*cell_px}" width="{cell_px}" height="{cell_px}" fill="black"/>')
        svg.append("</svg>")
        import base64
        return "data:image/svg+xml;base64," + base64.b64encode("".join(svg).encode()).decode()


@bp.route("/release/<int:release_id>/new", methods=("GET", "POST"))
@roles_required("Admin", "Manager", "Developer")
def new_deployment(release_id):
    release = get_release_or_404(release_id)
    if request.method == "POST":
        environment = request.form.get("environment", "Staging")
        token = secrets.token_urlsafe(16)
        db = get_db()
        cur = db.execute(
            """INSERT INTO deployments (release_id, environment, deployed_by, verification_token)
               VALUES (?, ?, ?, ?)""",
            (release_id, environment, g.user["id"], token),
        )
        db.commit()
        flash("Deployment recorded.", "success")
        return redirect(url_for("deploy.detail", deployment_id=cur.lastrowid))

    return render_template("deploy/new.html", release=release, environments=ENVIRONMENTS)


@bp.route("/<int:deployment_id>")
@login_required
def detail(deployment_id):
    db = get_db()
    deployment = db.execute(
        """SELECT d.*, r.version_number, r.project_id, p.name AS project_name
           FROM deployments d
           JOIN releases r ON r.id = d.release_id
           JOIN projects p ON p.id = r.project_id
           WHERE d.id = ?""",
        (deployment_id,),
    ).fetchone()
    if deployment is None:
        abort(404)
    verify_url = url_for("deploy.verify", token=deployment["verification_token"], _external=True)
    qr_data = qr_svg_data_uri(verify_url)
    return render_template("deploy/detail.html", deployment=deployment, verify_url=verify_url, qr_data=qr_data)


@bp.route("/verify/<token>", methods=("GET", "POST"))
def verify(token):
    """Public field-audit link — reachable via the QR code without login."""
    db = get_db()
    deployment = db.execute(
        """SELECT d.*, r.version_number, p.name AS project_name
           FROM deployments d JOIN releases r ON r.id = d.release_id
           JOIN projects p ON p.id = r.project_id
           WHERE d.verification_token = ?""",
        (token,),
    ).fetchone()
    if deployment is None:
        abort(404)

    if request.method == "POST":
        notes = request.form.get("verification_notes", "").strip()
        db.execute(
            "UPDATE deployments SET verified = 1, verification_notes = ? WHERE id = ?",
            (notes, deployment["id"]),
        )
        db.commit()
        flash("Deployment marked as verified. Thank you.", "success")
        return redirect(url_for("deploy.verify", token=token))

    return render_template("deploy/verify.html", deployment=deployment)
