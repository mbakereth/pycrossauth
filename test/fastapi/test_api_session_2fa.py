import unittest
import unittest.mock
from pathlib import Path
import json
from jinja2 import Template
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, NamedTuple
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
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
        "endpoints": [
            "api/login", 
            "api/logout", 
            "api/loginfactor2", 
            "api/signup", 
            "api/configurefactor2", 
            "api/userforsessionkey"
            "api/changefactor2"
            ],
        "allowed_factor2": ["dummy", "totp"],
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

        # get user
        resp = client.get("/api/userforsessionkey")
        body = resp.json()
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(body["ok"], True)
        self.assertEqual(body["user"]["username"], "mary")

    async def test_api_signup_2fa(self):
        app = await make_app_with_options({"enable_email_verification": False})

        client = TestClient(app.app)

        # Get CSRF Token
        resp =client.get("/api/getcsrftoken")
        client.cookies = resp.cookies
        body = resp.json()
        csrf_token = body["csrfToken"]

        resp1 = client.post("/api/signup", json={
            "csrfToken": csrf_token,
            "username": "bob1",
            "user_email": "bob1@bob1.com",
            "password": "bobPass1231",
            "factor2": "dummy",
            }, follow_redirects=False)
        body = resp1.json()
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(body["ok"], True)
        self.assertEqual(body["emailVerificationNeeded"], False)
        self.assertEqual(body["factor2"], "dummy")

        resp1 = client.post("/api/configurefactor2", json={
            "csrfToken": csrf_token,
            "otp": "0000",
            }, follow_redirects=False)
        body = resp1.json()
        self.assertEqual(resp1.status_code, 200)
        self.assertEqual(body["user"]["username"], "bob1")
        user = await app.userStorage.get_user_by_username("bob1", {"skip_active_check": True, "skip_email_verified_check": True})
        self.assertEqual(user["user"]["state"], "active")

    async def test_api_signup_2fa_verification(self):
        app = await make_app_with_options({"enable_email_verification": True})

        client = TestClient(app.app)

        # Get CSRF Token
        resp =client.get("/api/getcsrftoken")
        client.cookies = resp.cookies
        body = resp.json()
        csrf_token = body["csrfToken"]

        with unittest.mock.patch('smtplib.SMTP.send_message') as render_sendmessage:
            with unittest.mock.patch('jinja2.Environment.get_template') as render_get_template:
                with unittest.mock.patch('jinja2.Template.render') as render_render:
                    render_sendmessage.side_effect = mock_sendmessage
                    render_render.side_effect = mock_render
                    render_get_template.side_effect = mock_template


                    resp1 = client.post("/api/signup", json={
                        "csrfToken": csrf_token,
                        "username": "bob1",
                        "user_email": "bob1@bob1.com",
                        "password": "bobPass1231",
                        "factor2": "dummy",
                        }, follow_redirects=False)
                    body = resp1.json()
                    self.assertEqual(resp1.status_code, 200)
                    self.assertEqual(body["ok"], True)
                    self.assertEqual(body["emailVerificationNeeded"], True)
                    self.assertEqual(body["factor2"], "dummy")

                    resp1 = client.post("/api/configurefactor2", json={
                        "csrfToken": csrf_token,
                        "otp": "0000",
                        }, follow_redirects=False)
                    body = resp1.json()
                    self.assertEqual(resp1.status_code, 200)
                    self.assertEqual(body["user"]["username"], "bob1")
                    user = await app.userStorage.get_user_by_username("bob1", {"skip_active_check": True, "skip_email_verified_check": True})
                    self.assertEqual(user["user"]["state"], "awaitingemailverification")

    async def test_api_change_factor2_to_dummy(self):
        app = await make_app_with_options()

        client = TestClient(app.app)

        # Get CSRF Token
        resp =client.get("/api/getcsrftoken")
        client.cookies = resp.cookies
        body = resp.json()
        csrf_token = body["csrfToken"]

        # login
        resp =client.post("/api/login", json={
            "csrfToken": csrf_token,
            "username": "bob",
            "password": "bobPass123"
        })
        client.cookies.set("SESSIONID", resp.cookies["SESSIONID"])

        body = resp.json()
        self.assertEqual(body["ok"], True)
        self.assertEqual(body["user"]["username"], "bob")

        # change factor2
        resp =client.post("/api/changepassword", json={
            "csrfToken": csrf_token,
            "old_password": "bobPass123",
            "new_password": "bobPass12",
        })

        # logout
        body = resp.json()
        self.assertEqual(body["ok"], True)

        resp =client.post("/api/logout", json={
            "csrfToken": csrf_token,
        })

        body = resp.json()
        self.assertEqual(body["ok"], True)
        client.cookies.delete("SESSIONID")

        # Get CSRF Token
        resp =client.get("/api/getcsrftoken")
        client.cookies = resp.cookies
        body = resp.json()
        csrf_token = body["csrfToken"]

        # login with new credentials
        resp =client.post("/api/login", json={
            "csrfToken": csrf_token,
            "username": "bob",
            "password": "bobPass12"
        })

        body = resp.json()
        self.assertEqual(body["ok"], True)
        self.assertEqual(body["user"]["username"], "bob")
