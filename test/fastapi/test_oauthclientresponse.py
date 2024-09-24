import unittest
import json
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse
from crossauth_backend.common.interfaces import Key
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage
from crossauth_backend.oauth.client import OAuthTokenResponse
from crossauth_fastapi.fastapiserver import FastApiServer 
from crossauth_fastapi.fastapisession import FastApiSessionServer
from crossauth_fastapi.fastapioauthclient import FastApiOAuthClient, \
    json_error, \
    page_error, \
    send_json, \
    send_in_page, \
    save_in_session_and_load, \
    save_in_session_and_redirect

from jwt.utils import get_int_from_datetime
from datetime import datetime, timedelta, timezone
from jwt import (
    JWT,
    jwk_from_pem,
    AbstractJWKBase
)
from typing import Any

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

async def get_json_error(request : Request, response : Response) -> Response:
    server = FastApiServer()
    client = FastApiOAuthClient(server)
    ce = CrossauthError(ErrorCode.Configuration, "Error message")
    return await json_error(client, request, response, ce)

async def get_page_error(request : Request, response : Response) -> Response:
    server = FastApiServer()
    client = FastApiOAuthClient(server)
    ce = CrossauthError(ErrorCode.Configuration, "Error message")
    return await page_error(client, request, response, ce)

async def get_send_json(request : Request, response : Response) -> Response:
    server = FastApiServer()
    client = FastApiOAuthClient(server)
    token_response : OAuthTokenResponse = {
        "access_token": token
    }
    return await send_json(token_response, client, request, response) or JSONResponse({})

async def get_send_in_page(request : Request, response : Response) -> Response:
    server = FastApiServer()
    client = FastApiOAuthClient(server)
    token_response : OAuthTokenResponse = {
        "access_token": token
    }
    return await send_in_page(token_response, client, request, response) or JSONResponse({})


async def get_save_in_session_and_load(request : Request, response : Response) -> Response:
    global server
    global session_id
    client = FastApiOAuthClient(server)

    token_response : OAuthTokenResponse = {
        "access_token": token
    }
    resp = await save_in_session_and_load(token_response, client, request, response) or JSONResponse({})
    session_id = request.state.session_id
    return resp

async def get_save_in_session_and_redirect(request : Request, response : Response) -> Response:
    global server
    global session_id
    client = FastApiOAuthClient(server)

    token_response : OAuthTokenResponse = {
        "access_token": token
    }
    resp = await save_in_session_and_redirect(token_response, client, request, response) or JSONResponse({})
    session_id = request.state.session_id
    return resp

class TestOAuthCLientResponse(unittest.IsolatedAsyncioTestCase):
    
    async def test_json_error(self):
        app = FastAPI()
        app.get("/")(get_json_error)

        fclient = TestClient(app)
        resp = fclient.get("/")
        json = resp.json()
        self.assertEqual(json["error_code_name"], "Configuration")
    
    async def test_page_error(self):
        app = FastAPI()
        app.get("/")(get_page_error)

        fclient = TestClient(app)
        resp = fclient.get("/")
        self.assertEqual(resp.text.strip(), "Configuration")

    async def test_send_json(self):
        app = FastAPI()
        app.get("/")(get_send_json)

        fclient = TestClient(app)
        resp = fclient.get("/").json()
        self.assertEqual(resp["access_token"], token)

    async def test_send_in_page(self):
        global app
        app = FastAPI()
        app.get("/")(get_send_in_page)

        fclient = TestClient(app)
        resp = fclient.get("/").text.strip()
        self.assertEqual(resp, token)

    async def test_save_in_session_and_load(self):
        global server
        global session_id
        app = FastAPI()
        key_storage = InMemoryKeyStorage()
        session = FastApiSessionServer(app, key_storage, {}, {})
        server = FastApiServer(session)
        app.get("/")(get_save_in_session_and_load)

        fclient = TestClient(app)
        resp = fclient.get("/").text.strip()
        self.assertEqual(resp, token)

        self.assertIsNotNone(session_id)
        parts = (session_id or "").split(".")
        hash_session_id = session.session_manager.session.hash_session_id(parts[0])
        key : Key|None = None
        try:
            key = await key_storage.get_key(hash_session_id)
        except: pass
        self.assertIsNotNone(key)
        if (key is not None):
            data = key["data"] if "data" in key else "{}"
            keydata = json.loads(data)
            self.assertEqual(keydata["oauth"]["access_token"], token)

    async def test_save_in_session_and_redirect(self):
        global server
        global session_id
        app = FastAPI()
        key_storage = InMemoryKeyStorage()
        session = FastApiSessionServer(app, key_storage, {}, {})
        server = FastApiServer(session)
        app.get("/")(get_save_in_session_and_redirect)

        fclient = TestClient(app)
        resp = fclient.get("/", follow_redirects=False)
        self.assertEqual(resp.headers.get("location"), "http://authorized")

        self.assertIsNotNone(session_id)
        parts = (session_id or "").split(".")
        hash_session_id = session.session_manager.session.hash_session_id(parts[0])
        key : Key|None = None
        try:
            key = await key_storage.get_key(hash_session_id)
        except: pass
        self.assertIsNotNone(key)
        if (key is not None):
            data = key["data"] if "data" in key else "{}"
            keydata = json.loads(data)
            self.assertEqual(keydata["oauth"]["access_token"], token)
