import unittest
from crossauth_backend.cookieauth import SessionCookie, DoubleSubmitCsrfToken
from crossauth_backend.crypto import Crypto
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage
from nulltype import NullType

class SessionKeyTest(unittest.IsolatedAsyncioTestCase):

    async def test_create_session_key(self):
        keyStorage = InMemoryKeyStorage()
        auth = SessionCookie( keyStorage, {"secret": "ABCDEFGHIJKLMNOPQRSTUVWX"})
        ret = await auth.create_session_key(None)
        # { value, created: dateCreated, expires } 
        key = await keyStorage.get_key(SessionCookie.hash_session_id(ret["value"]))
        self.assertTrue("expires" in key)
        self.assertTrue(type(key["expires"]) != NullType)
        self.assertIsNotNone(ret["expires"])
        self.assertIsNone(ret["userid"] if "userid" in ret else None)
        self.assertTrue(key["expires"] == ret["expires"]) # type: ignore
        self.assertTrue(key["expires"] > ret["created"]) # type: ignore

class CsrfCookieTest(unittest.IsolatedAsyncioTestCase):

    async def test_sign_and_unsign_cookie(self):
        secret = "ABCDEFGHIJKLMNOPQRSTUVWX"
        auth = DoubleSubmitCsrfToken({"secret": secret})
        token = auth.create_csrf_token()
        cookie = auth.make_csrf_cookie(token)
        cookie_token = Crypto.unsign_secure_token(cookie["value"], secret)
        self.assertEqual(cookie_token, token)

    async def make_and_recover_form_or_header_token(self):
        secret = "ABCDEFGHIJKLMNOPQRSTUVWX"
        auth = DoubleSubmitCsrfToken({"secret": secret})
        token = auth.create_csrf_token()
        form_or_header_value = auth.make_csrf_form_or_header_token(token)
        recovered_token = auth.unmask_csrf_token(form_or_header_value)
        self.assertEqual(recovered_token, token)
    
    async def create_and_validate_csrf_token(self):
        auth = DoubleSubmitCsrfToken({"secret": "ABCDEFGHIJKLMNOPQRSTUVWX"})
        token = auth.create_csrf_token()
        cookie = auth.make_csrf_cookie(token)
        form_or_header_value = auth.make_csrf_form_or_header_token(token)
        valid = False
        try:
            auth.validate_double_submit_csrf_token(cookie["value"], form_or_header_value)
            valid = True
        except:
            pass
        self.assertTrue(valid)
