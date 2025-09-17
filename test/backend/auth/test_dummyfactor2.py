import unittest
from crossauth_backend.authenticators.dummyfactor2 import DummyFactor2Authenticator
from crossauth_backend.common.interfaces import UserState, UserInputFields
import time

class default_dummyfactor2_validator_test(unittest.IsolatedAsyncioTestCase):

    async def test_valid_code(self):
        authenticator = DummyFactor2Authenticator("ABC")
        ok = False
        try:
            user : UserInputFields = {
                "username": "bob",
                "state": UserState.active,
                "factor1": "password",
                "factor2": "dummy",
                "email": "bob@bob.com"
            }
            now = int(time.time() * 1000)  # Get current time in milliseconds
            await authenticator.authenticate_user(user, {"otp": "ABC", "expiry": now+60000}, {"otp": "ABC"})
            ok = True
        except Exception as e:
            print(e)
        self.assertEqual(ok, True)

    async def test_invalid_code(self):
        authenticator = DummyFactor2Authenticator("ABC")
        ok = False
        try:
            user : UserInputFields = {
                "username": "bob",
                "state": UserState.active,
                "factor1": "password",
                "factor2": "dummy",
                "email": "bob@bob.com"
            }
            now = int(time.time() * 1000)  # Get current time in milliseconds
            await authenticator.authenticate_user(user, {"otp": "ABC", "expiry": now+60000}, {"otp": "ABCD"})
            ok = True
        except Exception as e:
            print(e)
        self.assertEqual(ok, False)

    async def test_valid_code_expired(self):
        authenticator = DummyFactor2Authenticator("ABC")
        ok = False
        try:
            user : UserInputFields = {
                "username": "bob",
                "state": UserState.active,
                "factor1": "password",
                "factor2": "dummy",
                "email": "bob@bob.com"
            }
            now = int(time.time() * 1000)  # Get current time in milliseconds
            await authenticator.authenticate_user(user, {"otp": "ABC", "expiry": now-60000}, {"otp": "ABC"})
            ok = True
        except Exception as e:
            print(e)
        self.assertEqual(ok, False)
