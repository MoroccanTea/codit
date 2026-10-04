from django.contrib.auth.decorators import login_required
from django.http import HttpResponseRedirect
from django.shortcuts import render
from django.urls import reverse
from django_otp import login as otp_login
from django_otp.decorators import otp_required
from django_otp.plugins.otp_totp.models import TOTPDevice

from .models import Invoice


# codit-safe: CWE-308 sensitive view requires a verified OTP device (otp_required), not just a password login
@otp_required
def invoices(request):
    rows = Invoice.objects.filter(account=request.user.account).order_by("-issued_at")[:50]
    return render(request, "billing/invoices.html", {"invoices": rows})


# The OTP page itself must accept a password-only session: that is how the user reaches it.
# codit-safe: CWE-308 login_required is correct here, this is the second-factor verification step
@login_required
def verify_otp(request):
    if request.method == "POST":
        device = TOTPDevice.objects.filter(user=request.user, confirmed=True).first()
        if device is not None and device.verify_token(request.POST.get("token", "")):
            otp_login(request, device)
            return HttpResponseRedirect(reverse("billing:invoices"))
    return render(request, "billing/verify_otp.html", status=200 if request.method == "GET" else 401)
