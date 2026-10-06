from flask import request
from flask_restx import Namespace, Resource

from ..service.auth import login_customer

api = Namespace("auth")


@api.route("/login")
class Login(Resource):
    def post(self):  # codit-safe: CWE-862 login must be reachable anonymously
        return login_customer(request.json)
