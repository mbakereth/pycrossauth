import unittest
import unittest.mock
from crossauth_backend.authenticators.emailauth import EmailAuthenticator
from crossauth_backend.storageimpl.inmemorystorage import InMemoryUserStorage
from crossauth_backend.common.interfaces import UserState, UserInputFields, UserSecretsInputFields, Key
import time
from typing import cast, Dict
import json
from datetime import datetime
from nulltype import Null
import smtplib

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


class default_emailauth_validator_test(unittest.IsolatedAsyncioTestCase):

    
    async def test_valid_code(self):

            authenticator = EmailAuthenticator()
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
        authenticator = EmailAuthenticator()
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
        authenticator = EmailAuthenticator()
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
        user_storage = InMemoryUserStorage()
        authenticator = EmailAuthenticator({
            "render": render
        })
        ok = False
        with unittest.mock.patch('smtplib.SMTP.sendmail') as sendmail_mock:
            sendmail_mock.side_effect = mock_sendmail
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
                secrets_otp = secrets["otp"]
                emailed_otp = json.loads(smtp_data)["otp"]
                self.assertEqual(secrets_otp, emailed_otp)
                self.assertIn(smtp_data, smtp_body)
                await authenticator.authenticate_user(user, cast(UserSecretsInputFields, secrets), {"otp": emailed_otp})
                ok = True
            except Exception as e:
                print(e)
            self.assertEqual(ok, True)

    async def test_one_time_secrets_jinja(self):
        user_storage = InMemoryUserStorage()
        authenticator = EmailAuthenticator()
        ok = False
        with unittest.mock.patch('smtplib.SMTP.sendmail') as sendmail_mock:
            with unittest.mock.patch('jinja2.Template.render') as render_mock:
                sendmail_mock.side_effect = mock_sendmail
                render_mock.side_effect = mock_render
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
                    secrets_otp = secrets["otp"]
                    emailed_otp = json.loads(smtp_data)["otp"]
                    self.assertEqual(secrets_otp, emailed_otp)
                    self.assertIn(smtp_data, smtp_body)
                    await authenticator.authenticate_user(user, cast(UserSecretsInputFields, secrets), {"otp": emailed_otp})
                    ok = True
                except Exception as e:
                    print(e)
                self.assertEqual(ok, True)

    async def test_prepare_configuration(self):
        authenticator = EmailAuthenticator({
            "render": render
        })
        authenticator.factor_name = "smtp"
        user_input : UserInputFields = {
            "username": "bob",
            "state": UserState.active,
            "factor1": "password",
            "factor2": "smtp",
            "email": "bob@bob.com"
        }
        now = int(time.time() * 1000)  # Get current time in milliseconds
        with unittest.mock.patch('smtplib.SMTP.sendmail') as sendmail_mock:
            sendmail_mock.side_effect = mock_sendmail

            out = await authenticator.prepare_configuration(user_input)
            emailed_otp = json.loads(smtp_data)["otp"]
            self.assertTrue(out is not None and "userData" in out)
            self.assertEqual(out is not None and "userData" in out and "username" in out["userData"] and out["userData"]["username"], "bob")
            self.assertEqual(out is not None and "userData" in out and "factor2" in out["userData"] and out["userData"]["factor2"], "smtp")
            expiry = cast(int, out["sessionData"]["expiry"]) # type: ignore
            self.assertGreater(expiry, now)

            session_key : Key = {"value": emailed_otp, "created": datetime.now(), "expires": Null, "data": json.dumps({"2fa": out["sessionData"]})} # type: ignore
            out = await authenticator.reprepare_configuration("bob", session_key)
            emailed_otp = json.loads(smtp_data)["otp"]
            self.assertEqual(out["newSessionData"]["username"], "bob") # type: ignore
            self.assertEqual(out["newSessionData"]["otp"], emailed_otp) # type: ignore
            self.assertGreater(int(out["newSessionData"]["expiry"]), now) # type: ignore
 