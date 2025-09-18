import unittest
from crossauth_backend.authenticators.dummysmsauth import DummySmsAuthenticator
import crossauth_backend.authenticators.dummysmsauth
from crossauth_backend.common.interfaces import UserState, UserInputFields, UserSecretsInputFields, Key, User
import time
from typing import cast, Dict, Any
import json
from datetime import datetime
from nulltype import Null

class default_emailauth_validator_test(unittest.IsolatedAsyncioTestCase):

    
    async def test_valid_code(self):

            authenticator = DummySmsAuthenticator({
                "sms_authenticator_from": "88888888"
            })
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
        authenticator = DummySmsAuthenticator({
            "sms_authenticator_from": "88888888"
        })
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
        authenticator = DummySmsAuthenticator({
            "sms_authenticator_from": "88888888"
        })
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

    async def test_one_time_secrets_custom_render(self):
        authenticator = DummySmsAuthenticator({
            "sms_authenticator_from": "+418888888"
        })
        ok = False
        try:
            user: Dict[str,Any]= {
                "userid": "bob",
                "username_normalized": "bob",
                "username": "bob",
                "state": UserState.active,
                "factor1": "password",
                "factor2": "dummy",
                "email": "bob@bob.com",
                "phone": "+418888887"
            }
            secrets = await authenticator.create_one_time_secrets(cast(User,user))
            secrets_otp = secrets["otp"]
            self.assertEqual(secrets_otp, crossauth_backend.authenticators.dummysmsauth.otp)
            await authenticator.authenticate_user(cast(User,user), cast(UserSecretsInputFields, secrets), {"otp": crossauth_backend.authenticators.dummysmsauth.otp})
            ok = True
        except Exception as e:
            print(e)
        self.assertEqual(ok, True)

    async def test_prepare_configuration(self):
        authenticator = DummySmsAuthenticator({
            "sms_authenticator_from": "+418888888"
        })
        authenticator.factor_name = "smtp"
        user: Dict[str,Any]= {
            "userid": "bob",
            "username_normalized": "bob",
            "username": "bob",
            "state": UserState.active,
            "factor1": "password",
            "factor2": "dummy",
            "email": "bob@bob.com",
            "phone": "+418888887"
        }
        now = int(time.time() * 1000)  # Get current time in milliseconds

        out = await authenticator.prepare_configuration(cast(User,user))
        self.assertTrue(out is not None and "userData" in out)
        self.assertEqual(out is not None and "userData" in out and "username" in out["userData"] and out["userData"]["username"], "bob")
        self.assertEqual(out is not None and "userData" in out and "factor2" in out["userData"] and out["userData"]["factor2"], "smtp")
        expiry = cast(int, out["sessionData"]["expiry"]) # type: ignore
        self.assertGreater(expiry, now)

        session_key : Key = {"value": crossauth_backend.authenticators.dummysmsauth.otp, "created": datetime.now(), "expires": Null, "data": json.dumps({"2fa": out["sessionData"]})} # type: ignore
        out = await authenticator.reprepare_configuration("bob", session_key)
        self.assertEqual(out["newSessionData"]["username"], "bob") # type: ignore
        self.assertEqual(out["newSessionData"]["otp"], crossauth_backend.authenticators.dummysmsauth.otp) # type: ignore
        self.assertGreater(int(out["newSessionData"]["expiry"]), now) # type: ignore
