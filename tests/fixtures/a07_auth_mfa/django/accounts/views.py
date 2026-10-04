import pyotp
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.contrib.auth import login as auth_login
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import PasswordResetConfirmView
from django.shortcuts import redirect, render
from django.views.decorators.http import require_POST

from .models import TrustedDevice

User = get_user_model()


@require_POST
def login_view(request):
    user = authenticate(request, username=request.POST["username"], password=request.POST["password"])
    if user is None:
        return render(request, "accounts/login.html", {"error": "Invalid credentials"}, status=401)

    # codit-expect: CWE-807 unsigned trusted_device cookie lets the browser skip the OTP step
    if request.COOKIES.get("trusted_device") == "1":
        auth_login(request, user)
        return redirect("dashboard")

    # codit-expect: CWE-308 Django session fully authenticated before the OTP has been checked
    auth_login(request, user)
    if user.profile.totp_enabled:
        return redirect("accounts:otp")
    return redirect("dashboard")


@login_required
@require_POST
def otp_verify_view(request):
    code = request.POST.get("code", "")

    # codit-expect: CWE-807 second-factor status taken from the X-MFA-Verified request header
    if request.META.get("HTTP_X_MFA_VERIFIED") == "1":
        request.session["mfa_verified"] = True
        return redirect("dashboard")

    totp = pyotp.TOTP(request.user.profile.totp_secret)
    # codit-expect: CWE-308 master OTP from settings accepted for any account
    if code == settings.MASTER_OTP or totp.verify(code):
        request.session["mfa_verified"] = True
        return redirect("dashboard")
    return render(request, "accounts/otp.html", {"error": "Invalid code"}, status=401)


@require_POST
def login_view_v2(request):
    user = authenticate(request, username=request.POST["username"], password=request.POST["password"])
    if user is None:
        return render(request, "accounts/login.html", {"error": "Invalid credentials"}, status=401)

    device_token = request.get_signed_cookie("td", default=None, salt="accounts.trusted-device", max_age=30 * 86400)
    # codit-safe: CWE-807 signed device token validated against a hashed TrustedDevice row of this user
    trusted = device_token is not None and TrustedDevice.objects.is_valid(user, device_token)

    if user.profile.totp_enabled and not trusted:
        request.session.cycle_key()
        # codit-safe: CWE-308 session only holds pre_2fa_user_id until the TOTP code is verified
        request.session["pre_2fa_user_id"] = user.pk
        return redirect("accounts:otp_v2")
    auth_login(request, user)
    return redirect("dashboard")


@require_POST
def otp_verify_view_v2(request):
    user_id = request.session.get("pre_2fa_user_id")
    if user_id is None:
        return redirect("accounts:login")
    attempts = request.session.get("otp_attempts", 0)
    if attempts >= 5:
        return render(request, "accounts/otp.html", {"error": "Too many attempts"}, status=429)
    user = User.objects.get(pk=user_id)
    code = request.POST.get("code", "")
    # codit-safe: CWE-307 valid_window=1 and at most 5 attempts per pending login
    if pyotp.TOTP(user.profile.totp_secret).verify(code, valid_window=1):
        del request.session["pre_2fa_user_id"]
        auth_login(request, user)
        return redirect("dashboard")
    request.session["otp_attempts"] = attempts + 1
    return render(request, "accounts/otp.html", {"error": "Invalid code"}, status=401)


class LegacyPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = "accounts/reset_confirm.html"
    # codit-expect: CWE-640 user is logged in right after the reset, bypassing the TOTP step
    post_reset_login = True
    success_url = "/dashboard/"


class SecurePasswordResetConfirmView(PasswordResetConfirmView):
    template_name = "accounts/reset_confirm.html"
    # codit-safe: CWE-640 no automatic login, the user signs in again with password + TOTP
    post_reset_login = False
    success_url = "/accounts/login/"
