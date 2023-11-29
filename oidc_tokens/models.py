from django.db import models
from oauthlib.common import Request
from oauthlib.openid import RequestValidator

# Create your models here.

class Client(models.Model):
    client_id = models.CharField(max_length=100, unique=True)
    grant_type = models.CharField(max_length=8,
    choices=[('implicit', 'Implicit Grant')])
    response_type = models.CharField(max_length=8,
                                               choices=[('id_token', 'ID Token')])
    scopes = models.TextField()
    default_scopes = models.TextField()

    redirect_uris = models.TextField()
    default_redirect_uri = models.TextField()

class TokenRequestValidator(RequestValidator):

    def validate_client_id(self, client_id, request):
        try:
            Client.objects.get(client_id=client_id)
            return True
        except Client.DoesNotExist:
            return False
