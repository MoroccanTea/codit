from flask import request
from flask_restx import Namespace, Resource

from ..service import order_service
from ..util.decorator import customer_token_required

api = Namespace("orders", description="customer orders")


@api.route("/")
class OrderList(Resource):
    @customer_token_required()
    @api.doc("list the orders of the logged-in customer")
    def get(self):  # codit-safe: CWE-862 @customer_token_required
        return order_service.list_for_customer(request)

    @customer_token_required()
    @api.doc("place an order")
    def post(self):  # codit-safe: CWE-862 @customer_token_required
        return order_service.create(request, request.json)


@api.route("/cart")
class Cart(Resource):
    @customer_token_required(allow_inactive=True)
    def get(self):  # codit-safe: CWE-862 @customer_token_required
        return order_service.cart_for_customer(request)

    @customer_token_required()
    def put(self):  # codit-safe: CWE-862 @customer_token_required
        return order_service.update_cart(request, request.json)


@api.route("/<order_id>/cancel")
class OrderCancel(Resource):
    @api.doc("cancel an order")
    def post(self, order_id):  # codit-expect: CWE-862 no @customer_token_required unlike every sibling resource
        return order_service.cancel(order_id)
