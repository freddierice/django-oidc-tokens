
from oauthlib.oauth2.rfc6749.endpoints import (
    AuthorizationEndpoint, IntrospectEndpoint, ResourceEndpoint,
    RevocationEndpoint, MetadataEndpoint
)
from oauthlib.oauth2.rfc6749.grant_types import (
    ImplicitGrant as OAuth2ImplicitGrant,
)
from oauthlib.oauth2.rfc6749.tokens import BearerToken

from oauthlib.openid.connect.core.grant_types import (
    ImplicitGrant, ImplicitTokenGrantDispatcher
)
from oauthlib.openid.connect.core.endpoints.userinfo import UserInfoEndpoint
from oauthlib.openid.connect.core.tokens import JWTToken

from oidc_tokens.models import Client, TokenRequestValidator

class Server(AuthorizationEndpoint, IntrospectEndpoint,
             ResourceEndpoint, RevocationEndpoint, UserInfoEndpoint):
    
    def __init__(self, request_validator, token_expires_in=None,
                 token_generator=None, refresh_token_generator=None,
                 *args, **kwargs):
        self.implicit_grant = OAuth2ImplicitGrant(request_validator)
        self.openid_connect_implicit = ImplicitGrant(request_validator)
        self.bearer = BearerToken(request_validator, token_generator,
                                token_expires_in, refresh_token_generator)
        self.jwt = JWTToken(request_validator, token_generator,
                            token_expires_in, refresh_token_generator)
        self.implicit_grant_choice = ImplicitTokenGrantDispatcher(
            default_grant=self.implicit_grant, 
            oidc_grant=self.openid_connect_implicit)

        AuthorizationEndpoint.__init__(self, default_response_type='id_token',
                                       response_types={
                                           'id_token': self.openid_connect_implicit,
                                       },
                                       default_token_type=self.bearer)
        ResourceEndpoint.__init__(self, default_token='Bearer',
                                  token_types={'Bearer': self.bearer, 'JWT': self.jwt})
        RevocationEndpoint.__init__(self, request_validator)
        IntrospectEndpoint.__init__(self, request_validator)
        UserInfoEndpoint.__init__(self, request_validator)
token_server = Server(request_validator=TokenRequestValidator())

token_metadata = MetadataEndpoint([token_server], claims={'scopes_supported': ['openid']})