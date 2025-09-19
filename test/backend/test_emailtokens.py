import unittest
import unittest.mock
from crossauth_backend.emailtoken import TokenEmailer
from crossauth_backend.storageimpl.inmemorystorage import InMemoryUserStorage, InMemoryKeyStorage
from crossauth_backend.common.interfaces import UserState, UserInputFields, UserSecretsInputFields, Key
import time
from typing import cast, Dict, Any
import json
from datetime import datetime
from nulltype import Null

smtp_data = ""
smtp_body = ""
def mock_sendmail(from_addr : str, to_addr: str, msg : str, arg1 : Any, arg2: Any):
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


class default_emailtokens_test(unittest.IsolatedAsyncioTestCase):

    
    async def test_one_time_secrets_custom_render(self):
        user_storage = InMemoryUserStorage()
        key_storage = InMemoryKeyStorage()
        emailer = TokenEmailer(user_storage, key_storage, {
            "site_url": "http://localhost",
            "smtp_host": "localhost",
            "render": render

        })
        with unittest.mock.patch('smtplib.SMTP.sendmail') as sendmail_mock:
            sendmail_mock.side_effect = mock_sendmail
            user_input : UserInputFields = {
                "username": "bob",
                "state": UserState.active,
                "factor1": "password",
                "factor2": "dummy",
                "email": "bob@bob.com"
            }
            await user_storage.create_user(user_input)
            await emailer.send_email_verification_token("bob")
        self.assertIn("token", smtp_data)
        data_json = json.loads(smtp_data)
        token = data_json["token"]
        self.assertIn(token, cast(bytes,smtp_body).decode())
