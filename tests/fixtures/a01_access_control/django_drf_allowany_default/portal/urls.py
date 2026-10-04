from django.urls import include, path
from rest_framework.routers import DefaultRouter

from tickets.api import CommentViewSet, TicketViewSet

router = DefaultRouter()
router.register("tickets", TicketViewSet, basename="ticket")
router.register("comments", CommentViewSet, basename="comment")

urlpatterns = [
    path("api/", include(router.urls)),
]
