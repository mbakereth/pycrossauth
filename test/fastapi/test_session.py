import unittest
import unittest.mock
from pathlib import Path

from typing import Dict, Any, NamedTuple
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage, InMemoryUserStorage
from crossauth_backend.authenticators.passwordauth import LocalPasswordAuthenticator
from crossauth_backend.authenticators.totpauth import TotpAuthenticator
from crossauth_backend.authenticators.dummyfactor2 import DummyFactor2Authenticator
from crossauth_fastapi.fastapisession import FastApiSessionServer, FastApiSessionServerOptions

from backend.testuserdata import get_test_user_storage

template_page = ""
template_data : Dict[str,Any] = {}
def state(request : Request) -> Dict[str, Any]:
    return {"state": request.state.__dict__["_state"], "cookies": request.cookies, "url": request.url.path}

def mock_TemplateResponse(template: str, data: Dict[str,Any]):
    global template_data
    global template_page
    template_page = template
    template_data = data
    return template_data

class App(NamedTuple):
    userStorage : InMemoryUserStorage
    keyStorage : InMemoryKeyStorage
    server: FastApiSessionServer
    app: FastAPI

async def make_app_with_options(options: FastApiSessionServerOptions = {}, factor2: str|None=None) -> App:
    """
    Async function to create a Fastify server with options
    
    Args:
        options: FastifyServerOptions configuration object, defaults to empty if None
    
    Returns:
        Dictionary containing userStorage, keyStorage, and server instances
    """
     
    user_storage = await get_test_user_storage()
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
        "endpoints": ["login", "logout", "signup"],
        **options
    })

    return App(user_storage, key_storage, server, app)

class FastApiSessionTest(unittest.IsolatedAsyncioTestCase):

    async def test_get_login_get(self):
        app = await make_app_with_options()

        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            render_mock.side_effect = mock_TemplateResponse

            client = TestClient(app.app)
            client.get("/login")
            self.assertEqual(template_page, "login.njk")
            self.assertIn("csrfToken", template_data)

    async def test_get_login_post(self):
        app = await make_app_with_options()
        app.app.get("/")(state)

        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            render_mock.side_effect = mock_TemplateResponse

            client = TestClient(app.app)
            client.get("/login")
            self.assertIn("csrfToken", template_data)
            csrfToken = template_data["csrfToken"]
            resp = client.post("/login", json={
                "csrfToken": csrfToken,
                "username": "bob",
                "password": "bobPass123"
                })
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertEqual(body["state"]["user"]["username"], "bob")
            self.assertIn("session_id", body["state"])
            self.assertIn("csrf_token", body["state"])
            self.assertIn("SESSIONID", body["cookies"])
            self.assertIn("CSRFTOKEN", body["cookies"])

    async def test_get_login_post_form(self):
        app = await make_app_with_options()
        app.app.get("/")(state)

        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            render_mock.side_effect = mock_TemplateResponse

            client = TestClient(app.app)
            client.get("/login")
            self.assertIn("csrfToken", template_data)
            csrfToken = template_data["csrfToken"]
            resp = client.post("/login", data={
                "csrfToken": csrfToken,
                "username": "bob",
                "password": "bobPass123"
                })
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertEqual(body["state"]["user"]["username"], "bob")
            self.assertIn("session_id", body["state"])
            self.assertIn("csrf_token", body["state"])
            self.assertIn("SESSIONID", body["cookies"])
            self.assertIn("CSRFTOKEN", body["cookies"])

    async def test_get_login_logout(self):
        app = await make_app_with_options()
        app.app.get("/")(state)

        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            render_mock.side_effect = mock_TemplateResponse

            client = TestClient(app.app)
            client.get("/login")
            self.assertIn("csrfToken", template_data)
            csrfToken = template_data["csrfToken"]
            resp = client.post("/login", json={
                "csrfToken": csrfToken,
                "username": "bob",
                "password": "bobPass123"
                })
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertEqual(body["state"]["user"]["username"], "bob")
            self.assertIn("session_id", body["state"])
            self.assertIn("csrf_token", body["state"])
            self.assertIn("SESSIONID", body["cookies"])
            self.assertIn("CSRFTOKEN", body["cookies"])
            resp = client.post("/logout", json={
                "csrfToken": csrfToken,
            })
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertIsNone(body["state"]["session_id"])
            self.assertIsNone(body["state"]["user"])
            self.assertNotIn("SESSIONID", body["cookies"])

    async def test_signup(self):
        app = await make_app_with_options({"enable_email_verification": False})
        app.app.get("/")(state)

        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            render_mock.side_effect = mock_TemplateResponse

            client = TestClient(app.app)
            client.get("/signup")
            self.assertIn("csrfToken", template_data)
            csrfToken = template_data["csrfToken"]
        resp1 = client.post("/signup", json={
            "csrfToken": csrfToken,
            "username": "bob1",
            "user_email": "bob1@bob1.com",
            "password": "bobPass1231"
            }, follow_redirects=False)
        self.assertEqual(resp1.status_code, 302)
