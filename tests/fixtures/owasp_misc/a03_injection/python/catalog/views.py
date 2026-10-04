import subprocess

from django.contrib.auth.decorators import login_required
from django.db import connection
from django.http import JsonResponse


@login_required
def product_search(request):
    name = request.GET.get("name", "")
    with connection.cursor() as cursor:
        # codit-expect: CWE-89 f-string SQL with a query-string value
        cursor.execute(f"SELECT id, name, price FROM catalog_product WHERE name = '{name}'")
        rows = cursor.fetchall()
    return JsonResponse({"results": rows})



@login_required
def product_search_safe(request):
    name = request.GET.get("name", "")
    with connection.cursor() as cursor:
        # codit-safe: CWE-89 driver-side %s parameter
        cursor.execute("SELECT id, name, price FROM catalog_product WHERE name = %s", [name])
        rows = cursor.fetchall()
    return JsonResponse({"results": rows})



@login_required
def import_archive(request):
    path = request.POST["archive"]
    # codit-expect: CWE-78 shell=True with a request value in the command string
    subprocess.run(f"tar xzf /srv/imports/{path} -C /srv/catalog", shell=True, check=True)
    return JsonResponse({"ok": True})



@login_required
def import_archive_safe(request):
    path = request.POST["archive"]
    if "/" in path or path.startswith("."):
        return JsonResponse({"error": "bad name"}, status=400)
    # codit-safe: CWE-78 argument list without a shell
    subprocess.run(["tar", "xzf", f"/srv/imports/{path}", "-C", "/srv/catalog"], check=True)
    return JsonResponse({"ok": True})
