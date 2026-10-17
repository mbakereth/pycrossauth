# Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file

import unittest
import unittest.mock

from fastapi.testclient import TestClient

from pathlib import Path
import json
from jinja2 import Template
from email.mime.multipart import MIMEMultipart
from fastapi.responses import JSONResponse

from typing import Dict, Any, NamedTuple, cast
from fastapi import FastAPI, Request, Response
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage, InMemoryUserStorage
from crossauth_backend.authenticators.passwordauth import LocalPasswordAuthenticator
from crossauth_backend.authenticators.totpauth import TotpAuthenticator
from crossauth_backend.authenticators.dummyfactor2 import DummyFactor2Authenticator
from crossauth_fastapi.fastapisession import FastApiSessionServer, FastApiSessionServerOptions

from backend.testuserdata import get_test_user_storage

template_page = ""
template_data : Dict[str,Any] = {"a": 1}
template_status: int=200
def state(request : Request, response: Response) -> Dict[str, Any]:
    return {"state": request.state.__dict__["_state"], "cookies": request.cookies, "url": request.url.path}

def mock_TemplateResponse(request: Request, template: str, data: Dict[str,Any], status: int=200):
    global template_data, template_page, template_status
    template_page = template
    template_data = {**data}
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

async def make_app_with_options(options: FastApiSessionServerOptions = cast(FastApiSessionServerOptions, {}), factor2: str|None=None) -> App:
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
            "deleteuser",
            "admin/createuser",
            "admin/updateuser"
        ],
        **options
    })

    return App(user_storage, key_storage, server, app)

class FastApiSessionAdminTest(unittest.IsolatedAsyncioTestCase):

    async def test_admin_create_user(self):
        app = await make_app_with_options({"enable_email_verification": True})
        app.app.get("/")(state)
        client = TestClient(app.app)


        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            with unittest.mock.patch('smtplib.SMTP.send_message') as render_sendmessage:
                with unittest.mock.patch('jinja2.Environment.get_template') as render_get_template:
                    with unittest.mock.patch('jinja2.Template.render') as render_render:
                        render_mock.side_effect = mock_TemplateResponse
                        render_sendmessage.side_effect = mock_template
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
                            "username": "admin",
                            "password": "adminPass123"
                            })
                        self.assertEqual(resp.status_code, 200)
                        body = resp.json()
                        csrfToken = template_data["csrfToken"]
                        self.assertEqual(body["state"]["user"]["username"], "admin")
                        self.assertEqual(body["state"]["user"]["admin"], True)
                        self.assertIn("session_id", body["state"])
                        self.assertIn("csrf_token", body["state"])
                        self.assertIn("SESSIONID", body["cookies"])
                        self.assertIn("CSRFTOKEN", body["cookies"])
                        client.cookies.set("SESSIONID", body["cookies"]["SESSIONID"])
                        client.cookies.set("CSRFTOKEN", body["cookies"]["CSRFTOKEN"])

                        # create user
                        client.get("/admin/createuser")
                        self.assertIn("csrfToken", template_data)
                        resp = client.post("/admin/createuser", json={
                            "csrfToken": csrfToken,
                            "username": "bob1",
                            "user_email": "bob1@bob1.com",
                            "password": "bobPass1231",
                            "repeat_password": "bobPass1231",
                            "user_dummyField": "val1",
                            "factor1": "localpassword",
                            })
                        body = resp.json()
                        self.assertNotIn("errorMessage", body)
                        self.assertEqual(resp.status_code, 200)

    async def test_admin_update_user(self):
        app = await make_app_with_options({"enable_email_verification": True})
        app.app.get("/")(state)
        client = TestClient(app.app)
        user_storage = app.userStorage
        bob = await user_storage.get_user_by_username("bob")


        with unittest.mock.patch('fastapi.templating.Jinja2Templates.TemplateResponse') as render_mock:
            with unittest.mock.patch('smtplib.SMTP.send_message') as render_sendmessage:
                with unittest.mock.patch('jinja2.Environment.get_template') as render_get_template:
                    with unittest.mock.patch('jinja2.Template.render') as render_render:
                        render_mock.side_effect = mock_TemplateResponse
                        render_sendmessage.side_effect = mock_template
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
                            "username": "admin",
                            "password": "adminPass123"
                            })
                        self.assertEqual(resp.status_code, 200)
                        body = resp.json()
                        csrfToken = template_data["csrfToken"]
                        self.assertEqual(body["state"]["user"]["username"], "admin")
                        self.assertEqual(body["state"]["user"]["admin"], True)
                        self.assertIn("session_id", body["state"])
                        self.assertIn("csrf_token", body["state"])
                        self.assertIn("SESSIONID", body["cookies"])
                        self.assertIn("CSRFTOKEN", body["cookies"])
                        client.cookies.set("SESSIONID", body["cookies"]["SESSIONID"])
                        client.cookies.set("CSRFTOKEN", body["cookies"]["CSRFTOKEN"])

                        # create user
                        resp = client.get("/admin/updateuser/" + str(bob["user"]["id"]))
                        self.assertIn("csrfToken", template_data)
                        self.assertEqual(resp.status_code, 200)

                        resp = client.post("/admin/updateuser/" + str(bob["user"]["id"]), json={
                            "csrfToken": template_data["csrfToken"],
                            "user_email": "bob1@bob1.com",
                            })
                        body = resp.json()
                        self.assertNotIn("errorMessage", body)
                        self.assertEqual(resp.status_code, 200)

