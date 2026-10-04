import hashlib
import hmac
import json

from django.conf import settings
from django.contrib.auth.decorators import login_required, permission_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.views.generic import DetailView, ListView

from .models import Invoice, Order, Payment


@login_required
def invoice_list(request):  # codit-safe: CWE-862 @login_required
    invoices = Invoice.objects.filter(owner=request.user)
    return render(request, "billing/invoice_list.html", {"invoices": invoices})


@permission_required("billing.delete_invoice", raise_exception=True)
def invoice_delete(request, pk):  # codit-safe: CWE-862,CWE-639 @permission_required: staff-level model permission
    Invoice.objects.filter(pk=pk).delete()
    return JsonResponse({"deleted": pk})


def export_all_invoices(request):  # codit-expect: CWE-862 dumps every invoice with no login/permission check (DRF defaults do not cover plain Django views)
    rows = Invoice.objects.values("number", "owner__email", "total")
    return JsonResponse(list(rows), safe=False)


class InvoiceDetailView(LoginRequiredMixin, DetailView):  # codit-safe: CWE-862,CWE-639 LoginRequiredMixin + owner-filtered get_queryset
    model = Invoice
    template_name = "billing/invoice_detail.html"

    def get_queryset(self):
        return Invoice.objects.filter(owner=self.request.user)


class OrderListView(ListView):  # codit-expect: CWE-862 class-based view listing all orders without LoginRequiredMixin
    model = Order
    template_name = "billing/orders.html"


@login_required
def order_detail(request, pk):
    order = get_object_or_404(Order, pk=pk)  # codit-expect: CWE-639 no owner filter on a client-supplied pk
    return render(request, "billing/order_detail.html", {"order": order})


@login_required
def order_receipt(request, pk):
    order = get_object_or_404(Order, pk=pk, user=request.user)  # codit-safe: CWE-639 lookup scoped to request.user
    return render(request, "billing/receipt.html", {"order": order})


@login_required
def finance_dashboard(request):
    if request.COOKIES.get("role") != "finance":  # codit-expect: CWE-807 role read from an unsigned cookie
        return HttpResponse(status=403)
    return render(request, "billing/finance.html")


@login_required
def finance_overview(request):
    if not request.user.has_perm("billing.view_finance"):  # codit-safe: CWE-807 server-side permission check
        return HttpResponse(status=403)
    return render(request, "billing/finance_overview.html")


@csrf_exempt  # codit-expect: CWE-352 CSRF exemption on a session-authenticated, state-changing view
@login_required
@require_POST
def confirm_payment(request):
    payment = get_object_or_404(Payment, reference=request.POST["reference"], order__user=request.user)
    payment.confirmed = True
    payment.save(update_fields=["confirmed"])
    return JsonResponse({"ok": True})


@csrf_exempt  # codit-safe: CWE-352 server-to-server webhook, no session; authenticity enforced by HMAC signature below
@require_POST
def psp_webhook(request):
    expected = hmac.new(settings.PSP_WEBHOOK_SECRET.encode(), request.body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("X-Signature", "")):
        return HttpResponse(status=400)
    event = json.loads(request.body)
    Payment.objects.filter(reference=event["reference"]).update(confirmed=True)
    return HttpResponse(status=204)
