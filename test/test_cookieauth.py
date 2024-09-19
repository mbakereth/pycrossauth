import unittest
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage
from crossauth_backend.cookieauth import SessionCookie, DoubleSubmitCsrfToken
from crossauth_backend.crypto import Crypto
from nulltype import NullType

class SessionKeyTest(unittest.IsolatedAsyncioTestCase):

    async def test_create_session_key(self):
        keyStorage = InMemoryKeyStorage()
        auth = SessionCookie( keyStorage, {"secret": "ABCDEFGHIJKLMNOPQRSTUVWX"})
        ret = await auth.create_session_key(None)
        # { value, created: dateCreated, expires } 
        key = await keyStorage.get_key(SessionCookie.hash_session_id(ret.value))
        self.assertTrue("expires" in key)
        self.assertTrue(type(key["expires"]) != NullType)
        self.assertIsNotNone(ret.expires)
        self.assertIsNone(ret.userid)
        print("Expires", key["expires"], ret.expires)
        self.assertTrue(key["expires"] == ret.expires) # type: ignore
        self.assertTrue(key["expires"] > ret.created) # type: ignore

class CsrfCookieTest(unittest.IsolatedAsyncioTestCase):
    secret = "ABCDEFGHIJKLMNOPQRSTUVWX"
    auth = DoubleSubmitCsrfToken({"secret": secret})
    token = auth.create_csrf_token()
    cookie = auth.make_csrf_cookie(token)
    cookie_token = Crypto.unsign_secure_token(cookie["value"], secret)
