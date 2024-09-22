import unittest
from typing import Any
from datetime import datetime, timedelta, timezone
from crossauth_backend.oauth.resserver import OAuthResourceServer
from crossauth_backend.oauth.tokenconsumer import OAuthTokenConsumer
from jwt import (
    JWT,
    jwk_from_pem,
    AbstractJWKBase
)
from jwt.utils import get_int_from_datetime

class SessionManagerTest(unittest.IsolatedAsyncioTestCase):

    def create_token(self) -> str:
        with open("keys/rsa-private-key.pem", 'rb') as f:
            private_key = f.read()
        private_jwk : AbstractJWKBase = jwk_from_pem(private_key)

        instance = JWT()

        exp = get_int_from_datetime(
            datetime.now(timezone.utc) + timedelta(hours=1))
        message : dict[str, Any]= {
            "a": "x", 
            "exp": exp,
            "iss": "http://localhost/iss",
            "aud": "http://localhost/aud",
            "type": "access",
        }
        return instance.encode(message, private_jwk, alg='RS256')

    async def test_validToken(self):

        consumer = OAuthTokenConsumer("http://localhost/aud", {
            "auth_server_base_url": "http://localhost/iss",
            "jwt_public_key_file": "keys/rsa-public-key.pem"
        })
        resserver = OAuthResourceServer([consumer])
        payload = await resserver.access_token_authorized(self.create_token())
        self.assertEqual(payload is not None and payload["a"], "x")

    async def test_invalidToken(self):

        consumer = OAuthTokenConsumer("http://localhost/aud", {
            "auth_server_base_url": "http://localhost/iss",
            "jwt_public_key_file": "keys/rsa-public-key-wrong.pem"
        })
        resserver = OAuthResourceServer([consumer])
        payload = await resserver.access_token_authorized(self.create_token())
        self.assertIsNone(payload)

    async def test_invalidAud(self):

        consumer = OAuthTokenConsumer("http://localhost/aud2", {
            "auth_server_base_url": "http://localhost/iss",
            "jwt_public_key_file": "keys/rsa-public-key-wrong.pem"
        })
        resserver = OAuthResourceServer([consumer])
        payload = await resserver.access_token_authorized(self.create_token())
        self.assertIsNone(payload)

    async def test_invalidIss(self):

        consumer = OAuthTokenConsumer("http://localhost/aud", {
            "auth_server_base_url": "http://localhost/iss2",
            "jwt_public_key_file": "keys/rsa-public-key-wrong.pem"
        })
        resserver = OAuthResourceServer([consumer])
        payload = await resserver.access_token_authorized(self.create_token())
        self.assertIsNone(payload)
