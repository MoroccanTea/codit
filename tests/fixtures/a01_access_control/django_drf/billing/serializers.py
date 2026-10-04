from django.contrib.auth import get_user_model
from rest_framework import serializers

from .models import Country, Invoice, Receipt, WebhookEndpoint

User = get_user_model()


class InvoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Invoice
        fields = ["id", "number", "total"]


class ReceiptSerializer(serializers.ModelSerializer):
    class Meta:
        model = Receipt
        fields = ["id", "order"]


class WebhookEndpointSerializer(serializers.ModelSerializer):
    class Meta:
        model = WebhookEndpoint
        fields = ["id", "url", "events"]


class CountrySerializer(serializers.ModelSerializer):
    class Meta:
        model = Country
        fields = ["code", "name"]


class AdminUserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "is_staff", "is_active"]


class AccountSerializer(serializers.ModelSerializer):
    """Used by the self-service /api/profile/ endpoint."""

    class Meta:
        model = User
        fields = "__all__"  # codit-expect: CWE-915 self-service serializer exposes is_staff/is_superuser/groups as writable


class PublicProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email"]  # codit-safe: CWE-915 explicit allow-list of harmless fields
        read_only_fields = ["email"]
