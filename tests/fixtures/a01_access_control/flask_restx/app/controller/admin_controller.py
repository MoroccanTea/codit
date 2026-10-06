from flask import Blueprint
from flask_restful import Api, Resource

from ..service import admin_service
from ..util.decorator import token_required

admin_bp = Blueprint("admin", __name__)
api = Api(admin_bp)


class UserAdmin(Resource):
    method_decorators = [token_required(roles=["admin"])]

    def get(self, user_id):  # codit-safe: CWE-862 method_decorators enforce the admin role
        return admin_service.get_user(user_id)

    def delete(self, user_id):  # codit-safe: CWE-862 method_decorators enforce the admin role
        return admin_service.delete_user(user_id)


class AuditLog(Resource):
    method_decorators = {"get": [token_required(roles=["admin", "auditor"])]}

    def get(self):  # codit-safe: CWE-862 per-verb method_decorators enforce a role
        return admin_service.audit_log()


class RoleGrant(Resource):
    def post(self, user_id):  # codit-expect: CWE-862 grants roles without the admin check its siblings have
        return admin_service.grant_role(user_id)


api.add_resource(UserAdmin, "/admin/users/<int:user_id>")
api.add_resource(AuditLog, "/admin/audit")
api.add_resource(RoleGrant, "/admin/users/<int:user_id>/roles")
