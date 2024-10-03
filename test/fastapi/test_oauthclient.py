import unittest
from jwt import JWT, jwk_from_pem, AbstractJWKBase
from jwt.utils import get_int_from_datetime
from datetime import datetime, timedelta, timezone
from typing import Any, TypedDict, Dict, cast
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from aioresponses import aioresponses, CallbackResult
from urllib.parse import urlparse
from urllib.parse import parse_qs

from crossauth_fastapi.fastapiserver import FastApiServer 
from crossauth_fastapi.fastapisession import FastApiSessionServer
from crossauth_fastapi.fastapioauthclient import FastApiOAuthClient
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage
from crossauth_backend.oauth.client import OAuthFlows
from crossauth_backend.oauth.wellknown import OpenIdConfiguration

def state(request : Request) -> Dict[str, Any]:
    return request.state.__dict__["_state"]

def get(name : str, url : str):
    parsed_url = urlparse(url)
    return parse_qs(parsed_url.query)[name][0]

oidcConfiguration : OpenIdConfiguration = {
    "issuer": "http://localhost/server",
    "authorization_endpoint": "http://localhost/server/authorize",
    "token_endpoint": "http://localhost/server/token",
    "token_endpoint_auth_methods_supported": ["client_secret_post"],
    "jwks_uri": "http://localhost/server/jwks",
    "response_types_supported": ["code"],
    "response_modes_supported": ["query"],
    "grant_types_supported": ["authorization_code", "client_credentials", "password", "refresh_token", "urn:ietf:params:oauth:grant-type:device_code"],
    "token_endpoint_auth_signing_alg_values_supported": ["RS256"],
    "subject_types_supported": ["public"],
    "id_token_signing_alg_values_supported": ["RS256"],
    "claims_supported": ["iss", "sub", "aud", "jti", "iat", "type"],
    "request_uri_parameter_supported": True,
    "require_request_uri_registration": True,
}

class ServerAndClient(TypedDict):
    app: FastAPI
    server : FastApiServer
    session: FastApiSessionServer
    client: FastApiOAuthClient
    key_storage: InMemoryKeyStorage
    fclient : TestClient
    csrf_cookie: str
    csrf_token: str

def make_token() -> str:
    with open("keys/rsa-private-key.pem", 'rb') as f:
        private_key = f.read()
    private_jwk : AbstractJWKBase = jwk_from_pem(private_key)
    instance = JWT()
    payload : dict[str, Any]= {"jti": "ABC", "exp": get_int_from_datetime(
            datetime.now(timezone.utc) + timedelta(hours=1))}
    return instance.encode(payload, private_jwk, alg='RS256')

token = make_token()
session_id = ""

def mockresponse(url : str, **kwargs : Any):
    global args
    args = kwargs["json"]
    return CallbackResult(payload = {
        "access_token": "XYZ", 
        "access_token": "XYZ", 
        "user_code": "USERCODE",
        "device_code": "DEVICECODE",
        "verification_uri": "http://localhost/server/device",
        "verification_uri_complete": "http://localhost/server/device?user_code=USERCODE",
        "expires_in": 120,
        "args": kwargs["json"]})

class TestOAuthCLientResponse(unittest.IsolatedAsyncioTestCase):
    
    async def makeServerAndClient(self, response_type : str = "send_json") -> ServerAndClient:
        app = FastAPI()
        key_storage = InMemoryKeyStorage()
        server = FastApiServer({
            "session": {
                "key_storage": key_storage
            },
            "oauth_client": {
                "auth_server_base_url": "http://localhost/server",
                "options": {
                    "valid_flows": [OAuthFlows.All],
                    "client_id": "ABC",
                    "client_secret": "DEF",
                    "redirect_uri": "http://localhost/redirect",
                    "device_authorization_url": "devicecode",
                    "token_response_type": response_type # type: ignore
                }
            }
        }, {
            "app": app
        })
        session = server.session_server
        client = server.oauth_client
        if (client is None): raise Exception("unexpectedly got  no client")
        
        fclient = TestClient(app)

        app.get("/")(state)
        key_storage = InMemoryKeyStorage()
        resp = fclient.get("/", follow_redirects=False)
        json = resp.json()
        self.assertIsNotNone(json["csrf_token"])
        self.assertIsNone(json["session_id"])
        csrf_cookie = resp.cookies.get("CSRFTOKEN")
        fclient.cookies.set("CSRFTOKEN", csrf_cookie or "")

        with aioresponses() as m:
            m.get('http://localhost/server/.well-known/openid-configuration', payload=oidcConfiguration) # type: ignore
            await client.load_config()

        return {
            "app": app,
            "server": server,
            "session": cast(FastApiSessionServer, session),
            "client": client,
            "key_storage": key_storage,
            "fclient": fclient,
            "csrf_cookie": csrf_cookie or "",
            "csrf_token": json["csrf_token"] or "",
        }

    async def test_authzcodeflow(self):
        client = await self.makeServerAndClient()

        resp = client["fclient"].get('/authzcodeflow', follow_redirects=False)
        self.assertEqual(resp.status_code, 307)
        url = resp.headers["location"]
        self.assertTrue(url.startswith("http://localhost/server/authorize"))
        self.assertIsNotNone(url)
        state = get("state", url)
        self.assertIsNotNone(state)

        with aioresponses() as m:
            m.post('http://localhost/server/token', callback=mockresponse) # type: ignore
            ret = client["fclient"].get(f"/authzcode?code=XXX&state={state}")
            body = ret.json()
            self.assertEqual(body["access_token"] if "access_token" in body else "", "XYZ")

    async def test_authzcodeflowpkce(self):
        client = await self.makeServerAndClient()

        resp = client["fclient"].get('/authzcodeflowpkce', follow_redirects=False)
        self.assertEqual(resp.status_code, 307)
        self.assertTrue(resp.headers["location"].startswith("http://localhost/server/authorize"))

    async def test_clientcredentials(self):
        client = await self.makeServerAndClient()

        with aioresponses() as m:
            m.post('http://localhost/server/token', callback=mockresponse) # type: ignore
            resp = client["fclient"].post('/clientcredflow', 
                follow_redirects=False,
                json={"csrf_token": client["csrf_token"]})
            body = resp.json()
            self.assertEqual(body["access_token"] if "access_token" in body else "", "XYZ")
            self.assertEqual(body["args"]["grant_type"], "client_credentials")
            self.assertEqual(body["args"]["client_id"], "ABC")
            self.assertEqual(body["args"]["client_secret"], "DEF")

    async def test_password(self):
        client = await self.makeServerAndClient()

        with aioresponses() as m:
            m.post('http://localhost/server/token', callback=mockresponse) # type: ignore
            resp = client["fclient"].post('/passwordflow', 
                follow_redirects=False,
                json={
                    "csrf_token": client["csrf_token"],
                    "username": "bob",
                    "password": "bobPass123"
                })
            body = resp.json()
            self.assertEqual(body["access_token"] if "access_token" in body else "", "XYZ")
            self.assertEqual(body["args"]["grant_type"], "password")
            self.assertEqual(body["args"]["username"], "bob")
            self.assertEqual(body["args"]["password"], "bobPass123")
            self.assertEqual(body["args"]["client_id"], "ABC")
            self.assertEqual(body["args"]["client_secret"], "DEF")

    async def test_devicecodeflow(self):
        client = await self.makeServerAndClient()

        with aioresponses() as m:
            m.post('http://localhost/server/devicecode', callback=mockresponse) # type: ignore
            resp = client["fclient"].post('/devicecodeflow', 
                follow_redirects=False,
                json={
                    "csrf_token": client["csrf_token"],
                    "username": "bob",
                    "password": "bobPass123"
                })
            body = resp.json()
            self.assertEqual(body["device_code"], "DEVICECODE")
            self.assertEqual(body["user_code"], "USERCODE")
            self.assertEqual(body["verification_uri"], "http://localhost/server/device")
            self.assertEqual(body["error"], "")
            self.assertEqual(body["error_description"], "")

    async def test_middleware(self):
        client = await self.makeServerAndClient("save_in_session_and_redirect")

        res = await client["session"].session_manager.create_anonymous_session()
        client["fclient"].cookies.set("SESSIONID", res.session_cookie["value"])

        client["client"]._test_middleware = True # type: ignore
        session_id = res.session_cookie["value"].split(".")[0]
        id_token_payload = {"sub": "bob"}
        expires_at = int((datetime.now() + timedelta(hours=1)).timestamp()*1000)
        oauth : dict[str,Any] = {"id_payload": id_token_payload, "expires_at": expires_at}
        await client["session"].session_manager.update_session_data(session_id, "oauth", oauth)
        client["fclient"].get('/passwordflow')
        self.assertEqual(client["client"]._test_request.state.user["username"], "bob") # type: ignore
        self.assertEqual(client["client"]._test_request.state.id_token_payload["sub"], "bob") # type: ignore
