import unittest
from crossauth_backend.authenticators.dummyfactor2 import DummyFactor2Authenticator
from crossauth_backend.storageimpl.inmemorystorage import InMemoryUserStorage
from crossauth_backend.common.interfaces import UserState, UserInputFields, UserSecretsInputFields, Key
import time
from typing import cast
import json
from datetime import datetime
from nulltype import Null

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
        except:
            pass
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
        except:
            pass
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
        except:
            pass
        self.assertEqual(ok, False)

    async def test_one_time_secrets(self):
        user_storage = InMemoryUserStorage()
        authenticator = DummyFactor2Authenticator("ABC")
        ok = False
        try:
            user_input : UserInputFields = {
                "username": "bob",
                "state": UserState.active,
                "factor1": "password",
                "factor2": "dummy",
                "email": "bob@bob.com"
            }
            user = await user_storage.create_user(user_input)
            secrets = await authenticator.create_one_time_secrets(user)
            await authenticator.authenticate_user(user, cast(UserSecretsInputFields, secrets), {"otp": "ABC"})
            ok = True
        except:
            pass
        self.assertEqual(ok, True)

    async def test_prepare_configuration(self):
        authenticator = DummyFactor2Authenticator("ABC")
        authenticator.factor_name = "dummy"
        user_input : UserInputFields = {
            "username": "bob",
            "state": UserState.active,
            "factor1": "password",
            "factor2": "dummy",
            "email": "bob@bob.com"
        }
        now = int(time.time() * 1000)  # Get current time in milliseconds
        out = await authenticator.prepare_configuration(user_input)
        self.assertTrue(out is not None and "userData" in out)
        self.assertEqual(out is not None and "userData" in out and "username" in out["userData"] and out["userData"]["username"], "bob")
        self.assertEqual(out is not None and "userData" in out and "factor2" in out["userData"] and out["userData"]["factor2"], "dummy")
        expiry = cast(int, out["sessionData"]["expiry"]) # type: ignore
        self.assertGreater(expiry, now)

        session_key : Key = {"value": "ABC", "created": datetime.now(), "expires": Null, "data": json.dumps({"2fa": out["sessionData"]})} # type: ignore
        out = await authenticator.reprepare_configuration("bob", session_key)
        self.assertEqual(out["newSessionData"]["username"], "bob") # type: ignore
        self.assertEqual(out["newSessionData"]["otp"], "ABC") # type: ignore
        self.assertGreater(int(out["newSessionData"]["expiry"]), now) # type: ignore
