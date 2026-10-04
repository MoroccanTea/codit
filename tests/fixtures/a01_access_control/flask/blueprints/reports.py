from flask import Blueprint, abort, jsonify
from flask_login import current_user

from models import Report, db

reports_bp = Blueprint("reports", __name__)


@reports_bp.before_request
def require_login():
    # Applies to every route of this blueprint.
    if not current_user.is_authenticated:
        abort(401)


@reports_bp.route("/monthly")  # codit-safe: CWE-862 blueprint-wide before_request enforces login
def monthly():
    reports = Report.query.filter_by(owner_id=current_user.id).all()
    return jsonify([r.to_dict() for r in reports])


@reports_bp.route("/<int:report_id>", methods=["DELETE"])  # codit-safe: CWE-862,CWE-639 before_request login + owner-scoped delete
def delete_report(report_id):
    Report.query.filter_by(id=report_id, owner_id=current_user.id).delete()
    db.session.commit()
    return "", 204
