import unittest
from pathlib import Path

from typing import Dict, Any, NamedTuple
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage, InMemoryUserStorage
from crossauth_backend.authenticators.passwordauth import LocalPasswordAuthenticator
from crossauth_backend.authenticators.totpauth import TotpAuthenticator
from crossauth_backend.common.interfaces import Key
from crossauth_fastapi.fastapisession import FastApiSessionServer, FastApiSessionServerOptions
from backend.testuserdata import get_test_user_storage

def state(request : Request) -> Dict[str, Any]:
    return request.state.__dict__["_state"]

class App(NamedTuple):
    userStorage : InMemoryUserStorage
    keyStorage : InMemoryKeyStorage
    server: FastApiSessionServer
    app: FastAPI

async def make_app_with_options(options: FastApiSessionServerOptions = {}) -> App:
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

     # Create a FastAPI app (Python equivalent to Fastify) with logging disabled
     app = FastAPI()
     
     # Get the directory path equivalent to __dirname in Node.js
     current_dir = Path(__file__).parent
     views_path = current_dir / '../views'
     options["views"] = str(views_path)

     server = FastApiSessionServer(app, key_storage, {
          "password": lp_authenticator,
          "totp": totp_authenticator,
     }, options)

     return App(user_storage, key_storage, server, app)

class FastApiSessionTest(unittest.IsolatedAsyncioTestCase):

     async def test_get_createCsrfToken(self):
          app = await make_app_with_options()
          app.app.get("/")(state)
          client = TestClient(app.app)
          resp = client.get("/")
          json = resp.json()
          self.assertIsNotNone(json["csrf_token"])
          self.assertIsNone(json["session_id"])
          csrf_cookie = resp.cookies.get("CSRFTOKEN")
          self.assertIsNotNone(csrf_cookie)
          token = resp.headers.get("x-crossauth-csrf")
          self.assertIsNotNone(token)
