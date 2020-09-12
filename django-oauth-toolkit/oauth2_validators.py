from datetime import datetime, timedelta

from django.conf import settings
from django.utils import timezone
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings


class GatePassOAuth2Validator(OAuth2Validator):
    """
    Custom OAuth2 Validator with
    """
    def validate_refresh_token(self, refresh_token, client, request, *args, **kwargs):
        """
        Validate a refresh token based upon
            created_date + OAUTH2_PROVIDER_MY_REFRESH_TOKEN_EXPIRE_SECONDS
        Introduced a custom setting variable, 
            because oauth2_provider wasn't allowing custom settings inside its scope
        """
        validation = super().validate_refresh_token(refresh_token, client, request, *args, **kwargs)

        # Need extra check, if validation passed at earlier step
        if validation:
            refresh_token_instance = request.refresh_token_instance
            refresh_token_should_expire_at = timezone.now() - timedelta(seconds=settings.OAUTH2_PROVIDER_MY_REFRESH_TOKEN_EXPIRE_SECONDS)
            # Custom Check to ensure that the refresh_token was NOT created before expiry margin
            if refresh_token_instance.created <= refresh_token_should_expire_at:
                request.user = None
                request.refresh_token = None
                request.refresh_token_instance = None
                return False

        return True
