import unittest
import unittest.mock
from pathlib import Path
import json
from jinja2 import Template
from email.mime.multipart import MIMEMultipart
from fastapi.responses import JSONResponse

from typing import Dict, Any, NamedTuple
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage, InMemoryUserStorage
from crossauth_backend.authenticators.passwordauth import LocalPasswordAuthenticator
from crossauth_backend.authenticators.totpauth import TotpAuthenticator
from crossauth_backend.authenticators.dummyfactor2 import DummyFactor2Authenticator
from crossauth_fastapi.fastapisession import FastApiSessionServer, FastApiSessionServerOptions

from backend.testuserdata import get_test_user_storage

template_page = ""
template_data : Dict[str,Any] = {}
template_status: int=200
def state(request : Request, response: Response) -> Dict[str, Any]:
    return {"state": request.state.__dict__["_state"], "cookies": request.cookies, "url": request.url.path}

def mock_TemplateResponse(request: Request, template: str, data: Dict[str,Any], status: int=200):
    global template_data
    global template_page
    global template_status
    template_page = template
    template_data = data
    template_status=status
    return JSONResponse(template_data)

email_data : Dict[str,Any] = {}
def mock_render(param: Any|None=None, **kwargs: Dict[str,Any]):
    global email_data    
    if (param):
        email_data = param
    else:
        email_data = {**kwargs}
    return json.dumps(email_data)

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
        "endpoints": [
            "login", 
            "logout", 
            "signup", 
            "requestpasswordreset", 
            "resetpassword", 
            "verifyemail",
            "changepassword",
            "updateuser",
            "deleteuser"
        ],
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
            client.cookies.set("SESSIONID", body["cookies"]["SESSIONID"])
            self.assertEqual(body["state"]["user"]["username"], "bob")
            self.assertIn("session_id", body["state"])
            self.assertIn("csrf_token", body["state"])
            self.assertIn("SESSIONID", body["cookies"])
            self.assertIn("CSRFTOKEN", body["cookies"])

            #client.cookies.set("SESSIONID", resp.cookies["SESSIONID"])
            resp = client.post("/logout", json={
                "csrfToken": csrfToken,
            })
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertIsNone(body["state"]["session_id"])
            self.assertIsNone(body["state"]["user"])
            #self.assertNotIn("SESSIONID", body["cookies"])

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
        user = await app.userStorage.get_user_by_username("bob1", {"skip_active_check": True, "skip_email_verified_check": True})
        self.assertEqual(user["user"]["state"], "active")

    async def test_signup_repeat_password(self):
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
            "password": "bobPass1231",
            "repeat_password": "bobPass1231"
            }, follow_redirects=False)
        self.assertEqual(resp1.status_code, 302)

    async def test_signup_repeat_password_wrong(self):
        app = await make_app_with_options({"enable_email_verification": False})
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
                "repeat_password": ""
                }, follow_redirects=False)
            self.assertEqual(template_status, 401)

    async def test_signup_verification(self):
        app = await make_app_with_options({"enable_email_verification": True})
        app.app.get("/")(state)

        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            with unittest.mock.patch('smtplib.SMTP.send_message') as render_sendmessage:
                with unittest.mock.patch('jinja2.Environment.get_template') as render_get_template:
                    with unittest.mock.patch('jinja2.Template.render') as render_render:
                        render_mock.side_effect = mock_TemplateResponse
                        render_sendmessage.side_effect = mock_sendmessage
                        render_render.side_effect = mock_render
                        render_get_template.side_effect = mock_template

                        client = TestClient(app.app)
                        client.get("/signup")
                        self.assertIn("csrfToken", template_data)
                        csrfToken = template_data["csrfToken"]

                        client.post("/signup", json={
                            "csrfToken": csrfToken,
                            "username": "bob1",
                            "user_email": "bob1@bob1.com",
                            "password": "bobPass1231"
                            }, follow_redirects=False)
                        self.assertEqual(template_status, 200)
                        self.assertEqual(template_data["message"], "Please check your email to finish signing up.")
                        self.assertIn("token", email_data)

                        token = email_data["token"]
                        resp = client.get("/verifyemail/"+token, 
                                follow_redirects=False)
                        #body = resp.json()    
                        self.assertEqual(resp.status_code, 200)
                        self.assertEqual(template_data["user"]["username"], "bob1")

    async def test_reset_password(self):
        app = await make_app_with_options({"enable_email_verification": False})
        global email_data
        app.app.get("/")(state)

        client = TestClient(app.app)


        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            with unittest.mock.patch('smtplib.SMTP.send_message') as render_sendmessage:
                with unittest.mock.patch('jinja2.Environment.get_template') as render_get_template:
                    with unittest.mock.patch('jinja2.Template.render') as render_render:
                        render_mock.side_effect = mock_TemplateResponse
                        render_sendmessage.side_effect = mock_sendmessage
                        render_render.side_effect = mock_render
                        render_get_template.side_effect = mock_template

                        client = TestClient(app.app)
                        client.get("/requestpasswordreset")
                        self.assertIn("csrfToken", template_data)
                        csrfToken = template_data["csrfToken"]

                        resp = client.post("/requestpasswordreset", json={
                            "csrfToken": csrfToken,
                            "email": "bob@bob.com",
                            }, follow_redirects=False)
                        #body = resp.json()
                        self.assertEqual(template_status, 200)
                        self.assertIn("token", email_data)
                        token = email_data["token"]

                        resp = client.post("/resetpassword", json={
                            "csrfToken": csrfToken,
                            "token": token,
                            "new_password": "bobPass124",
                            }, follow_redirects=False)
                        self.assertEqual(resp.status_code, 200)
                        self.assertEqual(template_data["user"]["username"], "bob")

    async def test_get_change_passwordt(self):
        app = await make_app_with_options()
        app.app.get("/")(state)

        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            render_mock.side_effect = mock_TemplateResponse

            client = TestClient(app.app)
            resp = client.get("/login")
            self.assertIn("csrfToken", template_data)
            csrfToken = template_data["csrfToken"]
            client.cookies.set("CSRFTOKEN", resp.cookies["CSRFTOKEN"])

            # login
            resp = client.post("/login", json={
                "csrfToken": csrfToken,
                "username": "bob",
                "password": "bobPass123"
                })
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            csrfToken = template_data["csrfToken"]
            self.assertEqual(body["state"]["user"]["username"], "bob")
            self.assertIn("session_id", body["state"])
            self.assertIn("csrf_token", body["state"])
            self.assertIn("SESSIONID", body["cookies"])
            self.assertIn("CSRFTOKEN", body["cookies"])
            client.cookies.set("SESSIONID", body["cookies"]["SESSIONID"])
            client.cookies.set("CSRFTOKEN", body["cookies"]["CSRFTOKEN"])

            client.get("/changepassword")
            self.assertIn("csrfToken", template_data)
            # change password
            resp = client.post("/changepassword", json={
                "csrfToken": csrfToken,
                "old_password": "bobPass123",
                "new_password": "bobPass12",
                "repeat_password": "bobPass12",
                })
            body = resp.json()
            self.assertEqual(resp.status_code, 200)
            self.assertEqual(body["next"], "/")
        
            #client.cookies.set("SESSIONID", resp.cookies["SESSIONID"])
            resp = client.post("/logout", json={
                "csrfToken": csrfToken,
            })
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertIsNone(body["state"]["session_id"])
            self.assertIsNone(body["state"]["user"])
            #self.assertNotIn("SESSIONID", body["cookies"])
            client.cookies.delete("SESSIONID")

            # login with new credentials
            resp = client.post("/login", json={
                "csrfToken": csrfToken,
                "username": "bob",
                "password": "bobPass12"
                })
            self.assertEqual(resp.status_code, 200)
            body = resp.json()
            self.assertEqual(body["state"]["user"]["username"], "bob")

    async def test_update_user(self):
        app = await make_app_with_options({"enable_email_verification": True})
        global email_data
        app.app.get("/")(state)

        client = TestClient(app.app)


        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            with unittest.mock.patch('smtplib.SMTP.send_message') as render_sendmessage:
                with unittest.mock.patch('jinja2.Environment.get_template') as render_get_template:
                    with unittest.mock.patch('jinja2.Template.render') as render_render:
                        render_mock.side_effect = mock_TemplateResponse
                        render_sendmessage.side_effect = mock_sendmessage
                        render_render.side_effect = mock_render
                        render_get_template.side_effect = mock_template

                        client = TestClient(app.app)
                        resp = client.get("/login")
                        self.assertIn("csrfToken", template_data)
                        csrfToken = template_data["csrfToken"]
                        client.cookies.set("CSRFTOKEN", resp.cookies["CSRFTOKEN"])

                        # login
                        resp = client.post("/login", json={
                            "csrfToken": csrfToken,
                            "username": "bob",
                            "password": "bobPass123"
                            })
                        self.assertEqual(resp.status_code, 200)
                        body = resp.json()
                        csrfToken = template_data["csrfToken"]
                        self.assertEqual(body["state"]["user"]["username"], "bob")
                        self.assertIn("session_id", body["state"])
                        self.assertIn("csrf_token", body["state"])
                        self.assertIn("SESSIONID", body["cookies"])
                        self.assertIn("CSRFTOKEN", body["cookies"])
                        client.cookies.set("SESSIONID", body["cookies"]["SESSIONID"])
                        client.cookies.set("CSRFTOKEN", body["cookies"]["CSRFTOKEN"])

                        # update user
                        client.get("/updateuser")
                        self.assertIn("csrfToken", template_data)
                        resp = client.post("/updateuser", json={
                            "csrfToken": csrfToken,
                            "user_dummyField": "val1",
                            })
                        body = resp.json()
                        self.assertEqual(resp.status_code, 200)
                        self.assertEqual(body["message"], "Your details have been updated")

    async def test_update_user_email(self):
        app = await make_app_with_options({"enable_email_verification": True})
        global email_data
        app.app.get("/")(state)

        client = TestClient(app.app)


        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            with unittest.mock.patch('smtplib.SMTP.send_message') as render_sendmessage:
                with unittest.mock.patch('jinja2.Environment.get_template') as render_get_template:
                    with unittest.mock.patch('jinja2.Template.render') as render_render:
                        render_mock.side_effect = mock_TemplateResponse
                        render_sendmessage.side_effect = mock_sendmessage
                        render_render.side_effect = mock_render
                        render_get_template.side_effect = mock_template

                        client = TestClient(app.app)
                        resp = client.get("/login")
                        self.assertIn("csrfToken", template_data)
                        csrfToken = template_data["csrfToken"]
                        client.cookies.set("CSRFTOKEN", resp.cookies["CSRFTOKEN"])

                        # login
                        resp = client.post("/login", json={
                            "csrfToken": csrfToken,
                            "username": "bob",
                            "password": "bobPass123"
                            })
                        self.assertEqual(resp.status_code, 200)
                        body = resp.json()
                        csrfToken = template_data["csrfToken"]
                        self.assertEqual(body["state"]["user"]["username"], "bob")
                        self.assertIn("session_id", body["state"])
                        self.assertIn("csrf_token", body["state"])
                        self.assertIn("SESSIONID", body["cookies"])
                        self.assertIn("CSRFTOKEN", body["cookies"])
                        client.cookies.set("SESSIONID", body["cookies"]["SESSIONID"])
                        client.cookies.set("CSRFTOKEN", body["cookies"]["CSRFTOKEN"])

                        # update user
                        client.get("/updateuser")
                        self.assertIn("csrfToken", template_data)
                        resp = client.post("/updateuser", json={
                            "csrfToken": csrfToken,
                            "user_email": "bob1@bob.com",
                            })
                        body = resp.json()
                        self.assertEqual(resp.status_code, 200)
                        self.assertEqual(body["message"], "Please click on the link in your email to verify your email address.")

    async def test_delete_user(self):
        app = await make_app_with_options({"enable_email_verification": False})
        global email_data
        app.app.get("/")(state)
        user_storage = app.userStorage

        client = TestClient(app.app)


        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            with unittest.mock.patch('jinja2.Environment.get_template') as render_get_template:
                with unittest.mock.patch('jinja2.Template.render') as render_render:
                    render_mock.side_effect = mock_TemplateResponse
                    render_render.side_effect = mock_render
                    render_get_template.side_effect = mock_template

                    client = TestClient(app.app)
                    resp = client.get("/login")
                    self.assertIn("csrfToken", template_data)
                    csrfToken = template_data["csrfToken"]
                    client.cookies.set("CSRFTOKEN", resp.cookies["CSRFTOKEN"])

                    # login
                    resp = client.post("/login", json={
                        "csrfToken": csrfToken,
                        "username": "bob",
                        "password": "bobPass123"
                        })
                    self.assertEqual(resp.status_code, 200)
                    body = resp.json()
                    csrfToken = template_data["csrfToken"]
                    self.assertEqual(body["state"]["user"]["username"], "bob")
                    self.assertIn("session_id", body["state"])
                    self.assertIn("csrf_token", body["state"])
                    self.assertIn("SESSIONID", body["cookies"])
                    self.assertIn("CSRFTOKEN", body["cookies"])
                    client.cookies.set("SESSIONID", body["cookies"]["SESSIONID"])
                    client.cookies.set("CSRFTOKEN", body["cookies"]["CSRFTOKEN"])

                    # delete user
                    client.get("/deleteuser")
                    self.assertIn("csrfToken", template_data)
                    resp = client.post("/deleteuser", json={
                        "csrfToken": csrfToken,
                        })
                    body = resp.json()
                    self.assertEqual(resp.status_code, 200)
                    self.assertEqual(body["userid"], "bob")

                    found = False
                    try:
                        user = await user_storage.get_user_by_username("bob")
                        found = True
                    except:
                        pass
                    self.assertFalse(found)
                    