import os
import uuid

from flask import Flask, abort, current_app, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from werkzeug.utils import secure_filename

from .models import Product, db, Order
from .payments import charge_card

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "webp"}
PRIVATE_UPLOADS = "/srv/storefront/private-uploads"


@app.route("/avatar", methods=["POST"])
@login_required
def upload_avatar():
    file = request.files["avatar"]
    # codit-expect: CWE-434 client file name saved as-is under the public static folder (any extension, e.g. .php/.html)
    file.save(os.path.join(current_app.static_folder, "avatars", file.filename))
    return redirect(url_for("profile"))



@app.route("/v2/avatar", methods=["POST"])
@login_required
def upload_avatar_v2():
    file = request.files["avatar"]
    ext = secure_filename(file.filename).rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTENSIONS:
        abort(400)
    # codit-safe: CWE-434 extension allow-list, random server-side name, stored outside the web root
    file.save(os.path.join(PRIVATE_UPLOADS, f"{uuid.uuid4().hex}.{ext}"))
    return redirect(url_for("profile"))



@app.route("/buy/<int:product_id>", methods=["POST"])
@login_required
def buy(product_id):
    product = Product.query.get_or_404(product_id)
    # codit-expect: CWE-602 price read from a hidden form field the user can edit
    amount = int(request.form["price"])
    charge_card(current_user, amount)
    db.session.add(Order(user_id=current_user.id, product_id=product.id, amount=amount))
    db.session.commit()
    return render_template("thanks.html")



@app.route("/v2/buy/<int:product_id>", methods=["POST"])
@login_required
def buy_v2(product_id):
    product = Product.query.get_or_404(product_id)
    # codit-safe: CWE-602 amount comes from the database record
    amount = product.price_cents
    charge_card(current_user, amount)
    db.session.add(Order(user_id=current_user.id, product_id=product.id, amount=amount))
    db.session.commit()
    return render_template("thanks.html")
