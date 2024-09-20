import unittest
from typing import Any
from urllib.parse import urlparse
from urllib.parse import parse_qs
from aioresponses import aioresponses, CallbackResult
from crossauth_backend.oauth.wellknown import OpenIdConfiguration
from crossauth_backend.oauth.client import OAuthClient

def get(name : str, url : str):
    parsed_url = urlparse(url)
    return parse_qs(parsed_url.query)[name][0]

oidcConfiguration : OpenIdConfiguration = {
    "issuer": "http://localhost",
    "authorization_endpoint": "http://localhost/authorize",
    "token_endpoint": "http://localhost/token",
    "token_endpoint_auth_methods_supported": ["client_secret_post"],
    "jwks_uri": "http://localhost/jwks",
    "response_types_supported": ["code"],
    "response_modes_supported": ["query"],
    "grant_types_supported": ["authorization_code", "client_credentials", "password", "refresh_token"],
    "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "claims_supported": ["iss", "sub", "aud", "jti", "iat", "type"],
    "request_uri_parameter_supported": True,
    "require_request_uri_registration": True,
}

class SessionManagerTest(unittest.IsolatedAsyncioTestCase):

    async def test_authorizationCodeFlow(self):
        global args

        oauth_client = OAuthClient("http://localhost", {
            "client_id": "ABC",
            "client_secret": "DEF",
            "redirect_uri": "http://localhost/authzcode"
        })
        with aioresponses() as m:
            m.get('http://localhost/.well-known/openid-configuration', payload=oidcConfiguration) # type: ignore
            await oauth_client.load_config()

        resp = await oauth_client.start_authorization_code_flow("read write", False)
        self.assertIsNotNone(resp["url"])
        state = get("state", resp["url"])
        self.assertIsNotNone(state)

        with aioresponses() as m:
            m.post('http://localhost/token', callback=mockresponse) # type: ignore
            ret = await oauth_client.redirect_endpoint("XXX", state, None, None)
            self.assertEqual(ret["access_token"] if "access_token" in ret else "", "XYZ")
            self.assertEqual(args["grant_type"], "authorization_code")
            self.assertEqual(args["client_id"], "ABC")
            self.assertEqual(args["client_secret"], "DEF")

    async def test_clientCredentialsFlow(self):
        global args

        oauth_client = OAuthClient("http://localhost", {
            "client_id": "ABC",
            "client_secret": "DEF",
            "redirect_uri": "http://localhost/authzcode"
        })
        await oauth_client.load_config(oidcConfiguration)

        with aioresponses() as m:
            m.post('http://localhost/token', callback = mockresponse) # type: ignore
            ret = await oauth_client.client_credentials_flow("read write")
            self.assertEqual(ret["access_token"] if "access_token" in ret else "", "XYZ")
            self.assertEqual(ret["access_token"] if "access_token" in ret else "", "XYZ")
            self.assertEqual(args["grant_type"], "client_credentials")
            self.assertEqual(args["client_id"], "ABC")
            self.assertEqual(args["client_secret"], "DEF")
            self.assertEqual(args["scope"], "read write")

    async def test_passwordFlow(self):
        global args

        oauth_client = OAuthClient("http://localhost", {
            "client_id": "ABC",
            "client_secret": "DEF",
            "redirect_uri": "http://localhost/authzcode"
        })
        await oauth_client.load_config(oidcConfiguration)

        with aioresponses() as m:
            m.post('http://localhost/token', callback = mockresponse) # type: ignore
            ret = await oauth_client.password_flow("user", "password", "read write")
            self.assertEqual(ret["access_token"] if "access_token" in ret else "", "XYZ")
            self.assertEqual(args["grant_type"], "password")
            self.assertEqual(args["username"], "user")
            self.assertEqual(args["password"], "password")
            self.assertEqual(args["client_id"], "ABC")
            self.assertEqual(args["client_secret"], "DEF")
            self.assertEqual(args["scope"], "read write")

    async def test_refreshTokenFlow(self):
        global args

        oauth_client = OAuthClient("http://localhost", {
            "client_id": "ABC",
            "client_secret": "DEF",
            "redirect_uri": "http://localhost/authzcode"
        })
        await oauth_client.load_config(oidcConfiguration)

        with aioresponses() as m:
            m.post('http://localhost/token', callback = mockresponse) # type: ignore
            ret = await oauth_client.refresh_token_flow("XXX")
            self.assertEqual(ret["access_token"] if "access_token" in ret else "", "XYZ")
            self.assertEqual(args["grant_type"], "refresh_token")
            self.assertEqual(args["client_id"], "ABC")
            self.assertEqual(args["client_secret"], "DEF")
            self.assertEqual(args["refresh_token"], "XXX")

def mockresponse(url : str, **kwargs : Any):
    global args
    args = kwargs["json"]
    return CallbackResult(payload = {"access_token": "XYZ"})
