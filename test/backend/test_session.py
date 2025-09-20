import unittest
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage
from crossauth_backend.authenticators.passwordauth import LocalPasswordAuthenticator
from crossauth_backend.cookieauth import SessionCookie
from crossauth_backend.session import SessionManager
from .testuserdata import get_test_user_storage
import datetime

class SessionManagerTest(unittest.IsolatedAsyncioTestCase):
    async def test_anonymous_session(self):
        keyStorage = InMemoryKeyStorage()
        session = SessionManager( keyStorage, {}, {"secret": "ABCDEFGHIJKLMNOPQRSTUVWX"})
        ret = await session.create_anonymous_session()
        self.assertIsNotNone(ret.session_cookie)
        if (ret.session_cookie is None): return
        self.assertEqual(ret.session_cookie["name"], "SESSIONID")
        self.assertIsNotNone(ret.csrf_cookie)
        if (ret.csrf_cookie is None): return
        self.assertEqual(ret.csrf_cookie["name"], "CSRFTOKEN")
        self.assertIsNotNone(ret.csrf_form_or_header_value)
        if (ret.csrf_form_or_header_value is None): return
        session_id : str|None = None
        try:
            session_id = session.get_session_id(ret.session_cookie["value"])
        except:
            pass
        self.assertIsNotNone(session_id)

        success = False
        try:
            session.validate_double_submit_csrf_token(ret.csrf_cookie["value"], ret.csrf_form_or_header_value)
            success = True
        except:
            pass
        self.assertTrue(success)

    async def test_createSessionKey(self):
        key_storage = InMemoryKeyStorage()
        user_storage = await get_test_user_storage()
        auth = SessionCookie( key_storage, {"user_storage": user_storage, "secret": "ABCDEFGHIJKLMNOPQRSTUVWX", "site_url": "http://locahost:3000"})
        bobret  = await user_storage.get_user_by_username("bob")
        bob = bobret["user"]
        key1 = await auth.create_session_key(bob["id"])
        value = key1["value"]
        date_created = key1["created"]
        expires = key1["expires"] if "expires" in key1 else None
        key = await key_storage.get_key(SessionCookie.hash_session_id(value))
        key_expires = key["expires"] if "expires" in key else None
        self.assertIsNotNone(key_expires)
        self.assertIn("userid", key)
        if ("userid" in key):
            self.assertEqual(key["userid"], bob["id"])
        if (type(expires) == datetime.datetime and type(key_expires) == datetime.datetime):
            self.assertEqual(key_expires.timestamp()-date_created.timestamp(), expires.timestamp()-date_created.timestamp())

    async def test_loginGetKeyLogout(self):
        key_storage = InMemoryKeyStorage()
        user_storage = await get_test_user_storage()
        authenticator = LocalPasswordAuthenticator(user_storage)
        manager = SessionManager(key_storage, {"localpassword": authenticator}, {"user_storage": user_storage, "secret": "ABCDEFGHIJKLMNOPQRSTUVWX"})
        bobret = await manager.login("bob", {"password": "bobPass123"})
        bob = bobret.user
        cookie = bobret.session_cookie
        self.assertIsNotNone(bob)
        self.assertIsNotNone(cookie)
        if (not bob or not cookie): return
        self.assertEqual(bob["username"], "bob")
        sessionId = manager.get_session_id(cookie["value"])
        userret = await manager.user_for_session_id(sessionId)
        self.assertIsNotNone(userret.user)
        if (userret.user is None): return
        self.assertEqual(userret.user["username"], "bob")
        await manager.logout(sessionId)
        ok = False
        try:
            await manager.user_for_session_id(sessionId)
            ok = True
        except:
            pass
        self.assertFalse(ok)

