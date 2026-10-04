from defusedxml import ElementTree as SafeET
from django.contrib.admin.views.decorators import staff_member_required
from django.http import JsonResponse
from lxml import etree


@staff_member_required
def import_feed_legacy(request):
    # codit-expect: CWE-611 lxml parser resolving entities and allowed to fetch over the network
    parser = etree.XMLParser(resolve_entities=True, no_network=False, load_dtd=True)
    root = etree.fromstring(request.body, parser)
    return JsonResponse({"items": len(root.findall("item"))})



@staff_member_required
def import_feed(request):
    # codit-safe: CWE-611 defusedxml rejects entities and DTDs
    root = SafeET.fromstring(request.body)
    return JsonResponse({"items": len(root.findall("item"))})
