import ipaddress
import logging
import socket
import traceback
from urllib.parse import urlparse

import requests
from flask import Blueprint, abort, jsonify, request
from flask_login import current_user, login_required

from .permissions import PermissionDenied, check_can_edit
from .models import Report, db

bp = Blueprint("integrations", __name__)
log = logging.getLogger(__name__)
ALLOWED_HOSTS = {"hooks.slack.com", "outlook.office.com"}


@bp.get("/fetch")
@login_required
def fetch_url():
    # codit-expect: CWE-918 arbitrary URL from the query string fetched server-side
    resp = requests.get(request.args["url"], timeout=5)
    return resp.text



def _is_public_allowed(url: str) -> bool:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        return False
    addr = ipaddress.ip_address(socket.gethostbyname(parsed.hostname))
    return not (addr.is_private or addr.is_loopback or addr.is_link_local)


@bp.get("/fetch-safe")
@login_required
def fetch_url_safe():
    url = request.args["url"]
    if not _is_public_allowed(url):
        abort(400)
    # codit-safe: CWE-918 host allow-list plus private-address check, redirects disabled
    resp = requests.get(url, timeout=5, allow_redirects=False)
    return resp.text



@bp.post("/jobs/<int:job_id>/done")
@login_required
def job_done(job_id):
    payload = request.get_json()
    # codit-expect: CWE-918 callback URL supplied by the client is called by the server
    requests.post(payload["callback_url"], json={"job": job_id, "status": "done"}, timeout=5)
    return jsonify(ok=True)



@bp.post("/reports/<int:report_id>/legacy-edit")
@login_required
def edit_report_legacy(report_id):
    report = Report.query.get_or_404(report_id)
    try:
        check_can_edit(current_user, report)
    # codit-expect: CWE-390 permission failure swallowed with except/pass, the edit proceeds anyway
    except Exception:
        pass
    report.title = request.json["title"]
    db.session.commit()
    return jsonify(ok=True)



@bp.post("/reports/<int:report_id>/edit")
@login_required
def edit_report(report_id):
    report = Report.query.get_or_404(report_id)
    try:
        check_can_edit(current_user, report)
    # codit-safe: CWE-390 denial is turned into a 403 and the edit never runs
    except PermissionDenied:
        abort(403)
    report.title = request.json["title"]
    db.session.commit()
    return jsonify(ok=True)



@bp.errorhandler(Exception)
def handle_error_legacy(exc):
    # codit-expect: CWE-209 full Python traceback returned to the client
    return jsonify(error=str(exc), trace=traceback.format_exc()), 500



def handle_error(exc):
    log.exception("unhandled error")
    # codit-safe: CWE-209 generic message only, details stay in the server log
    return jsonify(error="internal error"), 500
