import json
import pickle

import yaml
from flask import Blueprint, jsonify, request
from flask_login import login_required

bp = Blueprint("sync", __name__)


@bp.post("/sync/legacy")
@login_required
def sync_legacy():
    # codit-expect: CWE-502 pickle deserialisation of the raw request body
    state = pickle.loads(request.data)
    return jsonify(items=len(state.get("items", [])))



@bp.post("/sync")
@login_required
def sync():
    # codit-safe: CWE-502 JSON only produces plain data types
    state = json.loads(request.data)
    return jsonify(items=len(state.get("items", [])))



@bp.post("/rules/legacy")
@login_required
def upload_rules_legacy():
    # codit-expect: CWE-502 yaml.load with the full Loader instantiates arbitrary Python objects
    rules = yaml.load(request.data, Loader=yaml.Loader)
    return jsonify(count=len(rules))



@bp.post("/rules")
@login_required
def upload_rules():
    # codit-safe: CWE-502 safe_load only builds plain YAML types
    rules = yaml.safe_load(request.data)
    return jsonify(count=len(rules))
