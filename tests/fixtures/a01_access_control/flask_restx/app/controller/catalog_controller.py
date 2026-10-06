from flask_restx import Namespace, Resource

from ..service import catalog_service

api = Namespace("catalog", description="public product catalog")


@api.route("/products")
class Products(Resource):
    @api.doc("public product listing")
    def get(self):  # codit-safe: CWE-862 public catalog, no sibling is protected
        return catalog_service.list_products()


@api.route("/products/<slug>")
class Product(Resource):
    def get(self, slug):  # codit-safe: CWE-862 public product page
        return catalog_service.get_product(slug)
