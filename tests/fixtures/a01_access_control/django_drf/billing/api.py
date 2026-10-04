from django.contrib.auth import authenticate, get_user_model, login as django_login
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny, IsAdminUser
from rest_framework.response import Response

from .models import Country, Invoice, Receipt, WebhookEndpoint
from .serializers import (
    AccountSerializer,
    AdminUserSerializer,
    CountrySerializer,
    InvoiceSerializer,
    ReceiptSerializer,
    WebhookEndpointSerializer,
)

User = get_user_model()


class InvoiceViewSet(viewsets.ModelViewSet):
    queryset = Invoice.objects.all()  # codit-expect: CWE-639 every customer's invoices; no get_queryset scoping to request.user
    serializer_class = InvoiceSerializer


class WebhookEndpointViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]  # codit-expect: CWE-862 mutating ModelViewSet (create/update/delete webhooks) opened to anonymous users
    queryset = WebhookEndpoint.objects.all()
    serializer_class = WebhookEndpointSerializer


class ReceiptViewSet(viewsets.ModelViewSet):
    serializer_class = ReceiptSerializer

    def get_queryset(self):
        return Receipt.objects.filter(owner=self.request.user)  # codit-safe: CWE-639 queryset filtered by request.user


class CountryViewSet(viewsets.ReadOnlyModelViewSet):
    permission_classes = [AllowAny]  # codit-safe: CWE-862,CWE-639 read-only public reference data
    queryset = Country.objects.all()
    serializer_class = CountrySerializer


class AdminUserViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAdminUser]  # codit-safe: CWE-862,CWE-639 staff-only management of all users
    queryset = User.objects.all()
    serializer_class = AdminUserSerializer


class ProfileViewSet(mixins.RetrieveModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet):
    serializer_class = AccountSerializer

    def get_object(self):
        return self.request.user


@api_view(["POST"])
@permission_classes([AllowAny])  # codit-safe: CWE-862 login endpoint must be reachable anonymously
def login(request):
    user = authenticate(request, username=request.data.get("username"), password=request.data.get("password"))
    if user is None:
        return Response({"detail": "Invalid credentials"}, status=status.HTTP_401_UNAUTHORIZED)
    django_login(request, user)
    return Response({"id": user.pk})
