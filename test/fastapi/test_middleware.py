import unittest
from typing import Dict, Any
from fastapi import FastAPI, Request, Response
from fastapi.testclient import TestClient
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage
from crossauth_backend.common.interfaces import Key
from crossauth_fastapi.fastapisession import FastApiSessionServer

def state(request : Request) -> Dict[str, Any]:
    return request.state.__dict__["_state"]

async def create_session(request : Request, response : Response) -> Dict[str, Any]:
    global session_server
    await session_server.create_anonymous_session(request, response)
    return request.state.__dict__["_state"]

class FastifyMiddlewareTest(unittest.IsolatedAsyncioTestCase):

   async def test_get_createCsrfToken(self):
        app = FastAPI()
        app.get("/")(state)
        key_storage = InMemoryKeyStorage()
        FastApiSessionServer(app, key_storage, {}, {})
        client = TestClient(app)
        resp = client.get("/")
        json = resp.json()
        self.assertTrue("csrf_token" in json)
        self.assertFalse("session_id" in json)
        csrf_cookie = resp.cookies.get("CSRFTOKEN")
        self.assertIsNotNone(csrf_cookie)
        token = resp.headers.get("x-crossauth-csrf")
        self.assertIsNotNone(token)


   async def test_post_noCsrfToken(self):
        global session_server
        app = FastAPI()
        app.post("/")(state)
        key_storage = InMemoryKeyStorage()
        session_server = FastApiSessionServer(app, key_storage, {}, {})
        client = TestClient(app)
        resp = client.post("/")
        json = resp.json()
        self.assertFalse("csrf_token" in json)
        self.assertFalse("session_id" in json)
        csrf_cookie = resp.cookies.get("CSRFTOKEN")
        self.assertIsNone(csrf_cookie)
        token = resp.headers.get("x-crossauth-csrf")
        self.assertIsNone(token)

   async def test_cascade_createCsrfToken(self):
        global session_server
        app = FastAPI()
        key_storage = InMemoryKeyStorage()
        session_server = FastApiSessionServer(app, key_storage, {}, {})
        app.get("/")(state)
        app.post("/")(state)
        client = TestClient(app)
        resp = client.get("/")
        json = resp.json()
        self.assertTrue("csrf_token" in json)
        self.assertFalse("session_id" in json)
        csrf_cookie = resp.cookies.get("CSRFTOKEN")
        self.assertIsNotNone(csrf_cookie)
        token = resp.headers.get("x-crossauth-csrf")
        self.assertIsNotNone(token)

        client.cookies.set("CSRFTOKEN", csrf_cookie or "")
        resp = client.post("/", json={"csrf_token": token or ""})
        json = resp.json()
        self.assertTrue("csrf_token" in json)
        self.assertFalse("session_id" in json)
        csrf_cookie = resp.cookies.get("CSRFTOKEN")
        token = resp.headers.get("x-crossauth-csrf")
        self.assertIsNotNone(token)

   async def test_createAnonymousSession(self):
        global session_server
        app = FastAPI()
        app.get("/")(create_session)
        key_storage = InMemoryKeyStorage()
        session_server = FastApiSessionServer(app, key_storage, {}, {})
        client = TestClient(app)
        resp = client.get("/")
        json = resp.json()
        self.assertTrue("csrf_token" in json)
        self.assertTrue("session_id" in json)
        session_id = resp.cookies.get("SESSIONID")
        self.assertIsNotNone(session_id)
        parts = (session_id or "").split(".")
        hash_session_id = session_server.session_manager.session.hash_session_id(parts[0])
        key : Key|None = None
        try:
            key = await key_storage.get_key(hash_session_id)
        except: pass
        self.assertIsNotNone(key)
