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

template_page = ""
template_data : Dict[str,Any] = {}
template_status: int=200

def state(request : Request) -> Dict[str, Any]:
    return {"state": request.state.__dict__["_state"], "cookies": request.cookies}

def mock_TemplateResponse(req : Request, template: str, data: Dict[str,Any], status : int=200):
    global template_data
    global template_page
    global template_status

    template_page = template
    template_data = data
    template_status=status
    return HTMLResponse(json.dumps(template_data), status_code=status)

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
        "endpoints": ["login", "logout", "loginfactor2", "signup", "configurefactor2"],
        **options
    })

    return App(user_storage, key_storage, server, app)

class FastApiSession2FATest(unittest.IsolatedAsyncioTestCase):

    async def test_get_login_2fa(self):
        app = await make_app_with_options({"allowed_factor2": ["none", "dummy"]})
        app.app.get("/")(state)

        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            render_mock.side_effect = mock_TemplateResponse

            client = TestClient(app.app)
            resp = client.get("/login")
            self.assertIn("csrfToken", template_data)
            csrfToken = template_data["csrfToken"]
            client.cookies = resp.cookies
            resp = client.post("/login", 
                    json={
                    "csrfToken": csrfToken,
                    "username": "mary",
                    "password": "maryPass123"
                    }, follow_redirects=False)
            self.assertEqual(resp.status_code, 302)

            client.cookies = resp.cookies
            csrfToken = template_data["csrfToken"]
            resp = client.post("/loginfactor2", 
                json={
                    "csrfToken": csrfToken,
                    "otp": "0000"
                    })
            body = resp.json()
            self.assertEqual(body["state"]["user"]["username"], "mary")
            self.assertIn("SESSIONID", body["cookies"])

    async def test_signup_factor2(self):
        app = await make_app_with_options({"enable_email_verification": False, "allowed_factor2": ["none", "dummy"]})
        app.app.get("/")(state)

        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            render_mock.side_effect = mock_TemplateResponse

            client = TestClient(app.app)
            client.get("/signup")
            self.assertIn("csrfToken", template_data)
            csrfToken = template_data["csrfToken"]
            client.post("/signup", json={
                "csrfToken": csrfToken,
                "username": "bob1",
                "user_email": "bob1@bob1.com",
                "password": "bobPass1231",
                "factor2": "dummy",
                }, follow_redirects=False)
            self.assertEqual(template_status, 200)
            self.assertEqual(template_data["username"], "bob1")
            self.assertEqual(template_data["factor2"], "dummy")
            self.assertEqual(template_page, "configurefactor2.njk")

            # send confgure post
            client.post("/configurefactor2", json={
                "csrfToken": csrfToken,
                "next": "/",
                "otp": "0000",
                }, follow_redirects=False)

            resp = client.get("/")
            body = resp.json()
            self.assertEqual(body["state"]["user"]["username"], "bob1")
            self.assertEqual(body["state"]["user"]["state"], "active")

    async def test_signup_factor2_email_verification(self):
        app = await make_app_with_options({"enable_email_verification": True, "allowed_factor2": ["none", "dummy"]})
        app.app.get("/")(state)

        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            render_mock.side_effect = mock_TemplateResponse

            client = TestClient(app.app)
            print("GET SIGNUP")
            resp = client.get("/signup")
            self.assertIn("csrfToken", template_data)
            csrfToken = template_data["csrfToken"]
            client.cookies = resp.cookies

            print("SIGNUP")
            resp1 = client.post("/signup", json={
                "csrfToken": csrfToken,
                "username": "bob1",
                "user_email": "bob1@bob1.com",
                "password": "bobPass1231",
                "factor2": "dummy",
                }, follow_redirects=False)
            self.assertEqual(resp1.status_code, 200)
            self.assertEqual(template_data["username"], "bob1")
            self.assertEqual(template_data["factor2"], "dummy")
            self.assertEqual(template_page, "configurefactor2.njk")
            csrfToken = template_data["csrfToken"]


            # send confgure post
            print("CONFIGURE")
            resp1 = client.post("/configurefactor2", json={
                "csrfToken": csrfToken,
                "next": "/",
                "otp": "0000",
                }, follow_redirects=False)

            user = await app.userStorage.get_user_by_username("bob1", {"skip_active_check": True, "skip_email_verified_check": True})
            self.assertEqual(user["user"]["state"], "awaitingemailverification")