import unittest
from jwt import JWT, jwk_from_pem, AbstractJWKBase
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from jwt.utils import get_int_from_datetime
from datetime import datetime, timedelta, timezone
from typing import Dict, Any

from crossauth_backend.oauth.client import OAuthTokenConsumer 
from crossauth_fastapi.fastapiresserver import FastApiOAuthResourceServer, ProtectedEndpoint

def make_access_token(expired : bool) -> str:
    with open("keys/rsa-private-key.pem", 'rb') as f:
        private_key = f.read()
    private_jwk : AbstractJWKBase = jwk_from_pem(private_key)
    instance = JWT()
    hours = -1 if expired else 1
    expiry = get_int_from_datetime(datetime.now(timezone.utc) + timedelta(hours=hours))
    payload : dict[str, Any]= {
        "jti": "ABC", 
        "exp": expiry,
        "aud": "correctaud",
        "sub": "bob",
        "iss": "http://localhost/iss",
        "type": "access",
    }
    return instance.encode(payload, private_jwk, alg='RS256')

access_token = make_access_token(False)
expired_access_token = make_access_token(True)

async def state(request : Request) -> Dict[str, Any]:
    return request.state.__dict__["_state"]

async def authorized(request : Request) -> Dict[str, Any]:
    global gserver
    resp = await gserver.authorized(request)
    return resp if resp is not None else {"authorized": False}


class TestOAuthCLientResponse(unittest.IsolatedAsyncioTestCase):

    async def test_goodToken(self):
        app = FastAPI()
        app.get("/")(state)
        resserver = FastApiOAuthResourceServer(
            app, 
            [OAuthTokenConsumer( "correctaud", {
                "auth_server_base_url": "http://localhost/iss",
                "jwt_public_key_file": "keys/rsa-public-key.pem"
        })])
        resp = await resserver.access_token_authorized(access_token)
        self.assertEqual(resp is not None and resp["jti"], "ABC")

    async def test_expiredToken(self):
        app = FastAPI()
        app.get("/")(state)
        resserver = FastApiOAuthResourceServer(
            app, 
            [OAuthTokenConsumer( "correctaud", {
                "auth_server_base_url": "http://localhost/iss",
                "jwt_public_key_file": "keys/rsa-public-key.pem"
        })])
        resp = await resserver.access_token_authorized(expired_access_token)
        self.assertIsNone(resp)

    async def test_wrongAud(self):
        app = FastAPI()
        app.get("/")(state)
        resserver = FastApiOAuthResourceServer(
            app, 
            [OAuthTokenConsumer( "wrongaud", {
                "auth_server_base_url": "http://localhost/iss",
                "jwt_public_key_file": "keys/rsa-public-key.pem"
        })])
        resp = await resserver.access_token_authorized(access_token)
        self.assertIsNone(resp)

    async def test_wrongIssuer(self):
        app = FastAPI()
        app.get("/")(state)
        resserver = FastApiOAuthResourceServer(
            app, 
            [OAuthTokenConsumer( "correctaud", {
                "auth_server_base_url": "http://localhost/wrong",
                "jwt_public_key_file": "keys/rsa-public-key.pem"
        })])
        resp = await resserver.access_token_authorized(access_token)
        self.assertIsNone(resp)

    async def test_goodTokenAuthorized(self):
        global gserver
        app = FastAPI()
        app.get("/")(authorized)
        gserver = FastApiOAuthResourceServer(
            app, 
            [OAuthTokenConsumer( "correctaud", {
                "auth_server_base_url": "http://localhost/iss",
                "jwt_public_key_file": "keys/rsa-public-key.pem"
        })])

        fclient = TestClient(app)
        resp = fclient.get("/", headers={"Authorization": "Bearer " + access_token})
        json = resp.json()
        self.assertTrue(json["authorized"])
        self.assertEqual(json["token_payload"]["jti"], "ABC")

    async def test_goodTokenMiddleware(self):
        global gserver
        app = FastAPI()
        app.get("/")(state)
        gserver = FastApiOAuthResourceServer(
            app, 
            [OAuthTokenConsumer( "correctaud", {
                "auth_server_base_url": "http://localhost/iss",
                "jwt_public_key_file": "keys/rsa-public-key.pem"
        })], {
            "protected_endpoints": {"/": ProtectedEndpoint()}
        })

        fclient = TestClient(app)
        resp = fclient.get("/", headers={"Authorization": "Bearer " + access_token})
        json = resp.json()
        self.assertEqual(json["user"]["username"], "bob")
        self.assertEqual(json["access_token_payload"]["jti"], "ABC")
