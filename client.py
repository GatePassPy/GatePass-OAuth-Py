import base64
import hashlib
import urllib
import uuid

import requests

OAUTH_CLIENT_ID='2H7EwXHRy5YESvL8AkBVJtzGQVOgo3geu3DaWfWf'
OAUTH_CLIENT_SECRET='vQ8KAITx0HFu3CI496iQdAs8NzhvIdz94aWTkmBYVR77h52qiiLzsZrhH5nVE5BPd67vkYuptDRJk5W83tsjFekXrTCy908zdqCXbgLT7pRxPsT4l2QTX52YMISFbkvR'
OAUTH_ACCESS_TOKEN_URL='http://example.com:8004/o/token/'
OAUTH_REFRESH_TOKEN_URL='http://example.com:8004/o/token/'
OAUTH_AUTHORIZE_URL='http://example.com:8004/o/authorize/'

class GatepassOAuthClient():
    name=None
    client_id=None
    client_secret=None
    access_token_url=None
    authorize_url=None
    access_token_url=None
    refresh_token_url=None 
    code_challenge=False
    code_challenge_method="S256"

    def __init__(self, client_id, client_secret, name=None):
        self.client_id=client_id
        self.client_secret=client_secret
        if name:
            self.name = name

    def configure(self, authorize_url, access_token_url, refresh_token_url, code_challenge=False, code_challenge_method='S256'):
        self.authorize_url=authorize_url
        self.access_token_url=access_token_url
        self.refresh_token_url=refresh_token_url
        self.code_challenge=code_challenge
        self.code_challenge_method=code_challenge_method

    def _uuid(self):
        return str(uuid.uuid4()).encode()

    def _client_auth_headers(self):
        auth_string = "{}:{}".format(self.client_id, self.client_secret)
        encoded_creds = base64.b64encode(auth_string.encode()).decode()
        return { 
            "Authorization": "Basic {}".format(encoded_creds)
        }

    def _get_challenge_code_for_authorization(self, code):
        if self.code_challenge_method=='S256':
            # reference : oauthlib/oauth2/rfc6749/grant_types/authorization_code.py
            return base64.urlsafe_b64encode(
                hashlib.sha256(code.encode()).digest()
            ).decode().rstrip('=')
        elif self.code_challenge_method == "PLAIN":
            return code
        else:
            raise Exception("Invalid Encryption Method for Code_Challenge")

    def get_random_challenge_code(self): 
        # Just some Randomizer and then MD5
        return hashlib.md5(self._uuid()).hexdigest()

    def generate_authorize_url(self, redirect_uri, state=None, code_challenge=None, extras={}):
        if state is None:
            state = base64.b64encode(self._uuid()).decode()

        args = dict(
            client_id=self.client_id,
            state=state,
            redirect_uri=redirect_uri,
            response_type='code'
        )

        if self.code_challenge is True and code_challenge is None:
            code_challenge = self.get_random_challenge_code()

        # PKCE - Code Challenge
        if self.code_challenge:
            args['code_challenge'] = self._get_challenge_code_for_authorization(code_challenge)
            args['code_challenge_method'] = self.code_challenge_method

        return {
            'url': "{}?{}".format(self.authorize_url, urllib.parse.urlencode(args)),
            'state': state,
            'code_challenge': code_challenge,
            'code_challenge_authorization': args.get('code_challenge', None) # If enabled and included in url
        }

    def make_access_token_request(self, code, state, redirect_uri=None, code_challenge=None):
        postdata=dict(
            code=code,
            # state=state,
            grant_type='authorization_code',
            client_id=self.client_id,
        )
        if redirect_uri:
            postdata['redirect_uri'] = redirect_uri

        if self.code_challenge is True and code_challenge is None:
            raise Exception("code_challenge is required for access_token request")
        elif self.code_challenge:
            postdata['code_verifier'] = code_challenge
    
        response = requests.post(
            self.access_token_url, data=postdata, headers=self._client_auth_headers()
        )

        return response

    def make_refresh_token_request(self, refresh_token, scope=None):
        postdata=dict(
            grant_type='refresh_token',
            refresh_token=refresh_token,
        )
        if scope:
            postdata['scope'] = scope

        response = requests.post(
            self.refresh_token_url, data=postdata, headers=self._client_auth_headers()
        )

        return response

    def make_revoke_token_request(self, token, token_type_hint=None):
        postdata=dict(token=token)
        if token_type_hint is not None and not in ['access_token', 'refresh_token']:
            raise Exception("Invalid parameter token_type_hint")
        elif token_type_hint:
            postdata['token_type_hint'] = token_type_hint

        repsonse = requests.post(
            self.revoke_token_url, data=postdata, headers=self._client_auth_headers()
        )

        return repsonse
