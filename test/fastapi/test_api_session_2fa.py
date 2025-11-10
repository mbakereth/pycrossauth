import unittest
import unittest.mock
from pathlib import Path
import json
from jinja2 import Template
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, NamedTuple
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from starlette.responses import HTMLResponse
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage, InMemoryUserStorage
from crossauth_backend.authenticators.passwordauth import LocalPasswordAuthenticator
from crossauth_backend.authenticators.totpauth import TotpAuthenticator
from crossauth_backend.authenticators.dummyfactor2 import DummyFactor2Authenticator
from crossauth_fastapi.fastapisession import FastApiSessionServer, FastApiSessionServerOptions

from backend.testuserdata import get_test_user_storage

def state(request : Request) -> Dict[str, Any]:
    return {"state": request.state.__dict__["_state"], "cookies": request.cookies}

email_data : Dict[str,Any] = {}
def mock_render(**kwargs: Dict[str,Any]):
    global email_data    
    email_data = kwargs
    return json.dumps(kwargs)

def mock_template(file : str):
    return Template("")

sendmessage_msg : MIMEMultipart
def mock_sendmessage(msg: MIMEMultipart):
    global sendmessage_msg
    sendmessage_msg = msg

class App(NamedTuple):
    userStorage : InMemoryUserStorage
    keyStorage : InMemoryKeyStorage
    server: FastApiSessionServer
    app: FastAPI

async def make_app_with_options(options: FastApiSessionServerOptions = {}, factor2: str = "dummy") -> App:
    """
    Async function to create a Fastify server with options
    
    Args:
        options: FastifyServerOptions configuration object, defaults to empty if None
    
    Returns:
        Dictionary containing userStorage, keyStorage, and server instances
    """
     
    user_storage = await get_test_user_storage(factor2=factor2)
    key_storage = InMemoryKeyStorage()
    
    lp_authenticator = LocalPasswordAuthenticator(user_storage, {
        'pbkdf2_iterations': 1_000,
    })
    totp_authenticator = TotpAuthenticator("FastifyTest")
    dummy_authenticator = DummyFactor2Authenticator("0000")

    # Create a FastAPI app (Python equivalent to Fastify) with logging disabled
    app = FastAPI()
    
    # Get the directory path equivalent to __dirname in Node.js
    current_dir = Path(__file__).parent
    views_path = current_dir / '../views'
    options["views"] = str(views_path)

    server = FastApiSessionServer(app, key_storage, {
        "localpassword": lp_authenticator,
        "totp": totp_authenticator,
        "dummy": dummy_authenticator,
    }, {
        "user_storage": user_storage,
        "endpoints": ["api/login", "api/logout", "api/loginfactor2", "api/signup", "api/configurefactor2"],
        **options
    })

    return App(user_storage, key_storage, server, app)

class FastApiSession2FATest(unittest.IsolatedAsyncioTestCase):

    async def test_api_login_2fa(self):
        app = await make_app_with_options({"allowed_factor2": ["none", "dummy"], "enable_email_verification": False})


        client = TestClient(app.app)

        # Get CSRF Token
        resp =client.get("/api/getcsrftoken")
        client.cookies = resp.cookies
        body = resp.json()
        csrf_token = body["csrfToken"]

        client.cookies = resp.cookies

        resp =client.post("/api/login", json={
            "csrfToken": csrf_token,
            "username": "mary",
            "password": "maryPass123"
        })

        body = resp.json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(body["ok"], True)
        self.assertEqual(body["twoFactorRequired"], True)

        client.cookies = resp.cookies
        resp = client.post("/api/loginfactor2", 
            json={
                "csrfToken": csrf_token,
                "otp": "0000"
                })
        body = resp.json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(body["ok"], True)
        self.assertEqual(body["user"]["username"], "mary")
