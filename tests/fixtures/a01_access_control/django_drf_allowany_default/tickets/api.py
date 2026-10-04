from rest_framework import serializers, viewsets
from rest_framework.permissions import IsAuthenticated

from .models import Comment, Ticket


class TicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ticket
        fields = ["id", "subject", "body", "status"]


class CommentSerializer(serializers.ModelSerializer):
    class Meta:
        model = Comment
        fields = ["id", "ticket", "body"]


class TicketViewSet(viewsets.ModelViewSet):  # codit-expect: CWE-862 no permission_classes while the project default is AllowAny
    serializer_class = TicketSerializer

    def get_queryset(self):
        return Ticket.objects.filter(status__in=["open", "pending"])


class CommentViewSet(viewsets.ModelViewSet):  # codit-safe: CWE-862,CWE-639 explicit IsAuthenticated + author-scoped queryset
    permission_classes = [IsAuthenticated]
    serializer_class = CommentSerializer

    def get_queryset(self):
        return Comment.objects.filter(author=self.request.user)

    def perform_create(self, serializer):
        serializer.save(author=self.request.user)
