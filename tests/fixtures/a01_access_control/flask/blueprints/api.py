from flask import Blueprint, jsonify
from flask_jwt_extended import get_jwt_identity, jwt_required

from models import Order, db

api_bp = Blueprint("api", __name__)


@api_bp.route("/orders", methods=["GET"])  # codit-safe: CWE-862 @jwt_required()
@jwt_required()
def list_orders():
    orders = Order.query.filter_by(user_id=get_jwt_identity()).all()
    return jsonify([o.to_dict() for o in orders])


@api_bp.route("/orders/<int:order_id>", methods=["GET"])  # codit-safe: CWE-862,CWE-639 @jwt_required() + identity-scoped lookup
@jwt_required()
def get_order(order_id):
    order = Order.query.filter_by(id=order_id, user_id=get_jwt_identity()).first_or_404()
    return jsonify(order.to_dict())


@api_bp.route("/orders/<int:order_id>", methods=["DELETE"])  # codit-expect: CWE-862 missing @jwt_required() unlike its siblings
def delete_order(order_id):
    Order.query.filter_by(id=order_id).delete()
    db.session.commit()
    return "", 204
