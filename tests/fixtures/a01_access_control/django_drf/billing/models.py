from django.conf import settings
from django.db import models


class Invoice(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="invoices")
    number = models.CharField(max_length=32, unique=True)
    total = models.DecimalField(max_digits=10, decimal_places=2)


class Order(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name="orders")
    status = models.CharField(max_length=16, default="open")


class Receipt(models.Model):
    owner = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    order = models.OneToOneField(Order, on_delete=models.CASCADE)


class Payment(models.Model):
    order = models.ForeignKey(Order, on_delete=models.CASCADE)
    reference = models.CharField(max_length=64)
    confirmed = models.BooleanField(default=False)


class WebhookEndpoint(models.Model):
    url = models.URLField()
    secret = models.CharField(max_length=128)
    events = models.JSONField(default=list)


class Country(models.Model):
    code = models.CharField(max_length=2, primary_key=True)
    name = models.CharField(max_length=64)
