import unittest
from crossauth_backend.authenticators.totpauth import TotpAuthenticator
from crossauth_backend.storageimpl.inmemorystorage import InMemoryUserStorage
from crossauth_backend.common.interfaces import UserState, UserInputFields, UserSecretsInputFields, Key
import time
from typing import cast, Dict
import json
from datetime import datetime
from nulltype import Null
import pyotp

smtp_data = ""
smtp_body = ""
def mock_sendmail(from_addr : str, to_addr: str, msg : str):
    global smtp_body
    smtp_body = msg

def render(body : str, data: Dict[str, str]):
    global smtp_data
    smtp_data = json.dumps(data)
    return smtp_data

def mock_render(data: Dict[str, str]):
    global smtp_data
    smtp_data = json.dumps(data)
    return smtp_data


class default_totpauth_validator_test(unittest.IsolatedAsyncioTestCase):

    
    async def test_valid_code(self):

            authenticator = TotpAuthenticator("Test")
            secret = pyotp.random_base32()
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
                totp = pyotp.TOTP(secret)
                otp = totp.now()
                await authenticator.authenticate_user(user, {"totpsecret": secret, "expiry": now+60000}, {"otp": otp})
                ok = True
            except:
                pass
            self.assertEqual(ok, True)

    async def test_invalid_code(self):
        authenticator = TotpAuthenticator("Test")
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
            secret = pyotp.random_base32()
            await authenticator.authenticate_user(user, {"totpsecret": secret, "expiry": now+60000}, {"otp": "ABCD"})
            ok = True
        except:
            pass
        self.assertEqual(ok, False)

    async def test_one_time_secrets(self):
        user_storage = InMemoryUserStorage()
        authenticator = TotpAuthenticator("Test")
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
            secrets = await authenticator.create_persistent_secrets("bob", {}, {})
            secret = secrets["totpsecret"]
            totp = pyotp.TOTP(secret)
            otp = totp.now()
            await authenticator.authenticate_user(user, cast(UserSecretsInputFields, secrets), {"otp": otp})
            ok = True
        except Exception as e:
            print(e)
        self.assertEqual(ok, True)

    async def test_prepare_configuration(self):
        authenticator = TotpAuthenticator("Test")
        authenticator.factor_name = "totp"
        user_input : UserInputFields = {
            "username": "bob",
            "state": UserState.active,
            "factor1": "password",
            "factor2": "totp",
            "email": "bob@bob.com"
        }

        out = await authenticator.prepare_configuration(user_input)
        self.assertTrue(out is not None and "userData" in out and "totpsecret" in out["userData"])
        self.assertEqual(out["userData"]["totpsecret"] if out else "x", out["sessionData"]["totpsecret"] if out else "y")

        session_key : Key = {"value": "XXX", "created": datetime.now(), "expires": Null, "data": json.dumps({"2fa": out["sessionData"]})} # type: ignore
        out = await authenticator.reprepare_configuration("bob", session_key)
        self.assertIsNone(out["newSessionData"]) # type: ignore
