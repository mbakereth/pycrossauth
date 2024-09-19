import unittest
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage
from crossauth_backend.session import SessionManager

class SessionManagerTest(unittest.IsolatedAsyncioTestCase):
    async def test_anonymous_session(self):
        keyStorage = InMemoryKeyStorage()
        session = SessionManager( keyStorage, {}, {"secret": "ABCDEFGHIJKLMNOPQRSTUVWX"})
        ret = await session.create_anonymous_session()
        self.assertEqual(ret.session_cookie["name"], "SESSIONID")
        self.assertEqual(ret.csrf_cookie["name"], "CSRFTOKEN")
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
