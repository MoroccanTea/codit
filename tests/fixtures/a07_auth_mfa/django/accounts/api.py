import pyotp
from rest_framework import serializers, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from .models import Profile


class ProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        # codit-expect: CWE-915 every model field is writable, including totp_enabled and totp_secret
        fields = "__all__"


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = Profile
        # codit-safe: CWE-915 explicit allow-list of non-security fields
        fields = ["display_name", "locale", "timezone"]


class Disable2FASerializer(serializers.Serializer):
    password = serializers.CharField()
    code = serializers.RegexField(r"^\d{6}$")


class ProfileView(APIView):
    permission_classes = [IsAuthenticated]

    def patch(self, request):
        serializer = ProfileSerializer(request.user.profile, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)


class Disable2FAView(APIView):
    permission_classes = [IsAuthenticated]

    # codit-expect: CWE-308 TOTP disabled with only the session, no password or OTP re-check
    def post(self, request):
        profile = request.user.profile
        profile.totp_enabled = False
        profile.totp_secret = ""
        profile.save(update_fields=["totp_enabled", "totp_secret"])
        return Response(status=status.HTTP_204_NO_CONTENT)


class Disable2FAViewV2(APIView):
    permission_classes = [IsAuthenticated]

    # codit-safe: CWE-308 requires the current password and a valid TOTP code
    def post(self, request):
        serializer = Disable2FASerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = request.user
        if not user.check_password(serializer.validated_data["password"]):
            return Response({"detail": "re-authentication failed"}, status=status.HTTP_403_FORBIDDEN)
        if not pyotp.TOTP(user.profile.totp_secret).verify(serializer.validated_data["code"], valid_window=1):
            return Response({"detail": "re-authentication failed"}, status=status.HTTP_403_FORBIDDEN)
        user.profile.totp_enabled = False
        user.profile.totp_secret = ""
        user.profile.save(update_fields=["totp_enabled", "totp_secret"])
        return Response(status=status.HTTP_204_NO_CONTENT)
