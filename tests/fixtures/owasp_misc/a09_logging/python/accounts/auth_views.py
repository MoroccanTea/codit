import logging

from django.contrib.auth import authenticate, login
from django.http import JsonResponse
from django.views.decorators.http import require_POST

logger = logging.getLogger("accounts.auth")


def _clean(value: str) -> str:
    return value.replace("\r", "\\r").replace("\n", "\\n")


@require_POST
def login_legacy(request):
    username = request.POST.get("username", "")
    password = request.POST.get("password", "")



    # codit-expect: CWE-532 plaintext password written to the log
    logger.info(f"login attempt user={username} password={password}")



    user = authenticate(request, username=username, password=password)
    if user is None:
        # codit-expect: CWE-117 unsanitised username in the log line (forged entries via CR/LF)
        logger.warning(f"Failed login for {username}")
        return JsonResponse({"error": "invalid credentials"}, status=401)
    login(request, user)
    return JsonResponse({"ok": True})



@require_POST
def login_view(request):
    username = request.POST.get("username", "")
    user = authenticate(request, username=username, password=request.POST.get("password", ""))
    if user is None:
        # codit-safe: CWE-117 CR/LF escaped before logging
        logger.warning("Failed login for %s", _clean(username))
        return JsonResponse({"error": "invalid credentials"}, status=401)
    login(request, user)



    # codit-safe: CWE-532 only the user id is logged
    logger.info("login ok user_id=%s", user.pk)
    return JsonResponse({"ok": True})



def debug_headers(request):
    # codit-expect: CWE-532 bearer token from the Authorization header logged
    logger.debug("Authorization header: %s", request.headers.get("Authorization"))
    return JsonResponse({"ok": True})
