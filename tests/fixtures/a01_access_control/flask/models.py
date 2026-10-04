from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash

db = SQLAlchemy()


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def statement(self, full=False):
        rows = Invoice.query.filter_by(owner_id=self.id).all()
        return [r.to_dict() for r in rows] if full else {"count": len(rows)}


class Invoice(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    total_cents = db.Column(db.Integer, nullable=False)
    pdf_path = db.Column(db.String(512))

    def to_dict(self):
        return {"id": self.id, "total_cents": self.total_cents}


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    title = db.Column(db.String(255))

    def to_dict(self):
        return {"id": self.id, "title": self.title}


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    status = db.Column(db.String(32), default="open")

    def to_dict(self):
        return {"id": self.id, "status": self.status}
