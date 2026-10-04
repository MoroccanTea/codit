from django.urls import include, path
from rest_framework.routers import DefaultRouter

from billing import api, views

router = DefaultRouter()
router.register("invoices", api.InvoiceViewSet, basename="invoice")
router.register("webhook-endpoints", api.WebhookEndpointViewSet, basename="webhook-endpoint")
router.register("receipts", api.ReceiptViewSet, basename="receipt")
router.register("countries", api.CountryViewSet, basename="country")
router.register("staff/users", api.AdminUserViewSet, basename="admin-user")
router.register("profile", api.ProfileViewSet, basename="profile")

urlpatterns = [
    path("api/", include(router.urls)),
    path("api/login/", api.login),
    path("invoices/", views.invoice_list),
    path("invoices/<int:pk>/delete/", views.invoice_delete),
    path("invoices/export/", views.export_all_invoices),
    path("invoices/<int:pk>/", views.InvoiceDetailView.as_view()),
    path("orders/", views.OrderListView.as_view()),
    path("orders/<int:pk>/", views.order_detail),
    path("orders/<int:pk>/receipt/", views.order_receipt),
    path("finance/", views.finance_dashboard),
    path("finance/overview/", views.finance_overview),
    path("payments/confirm/", views.confirm_payment),
    path("hooks/psp/", views.psp_webhook),
]
