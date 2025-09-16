import unittest
from crossauth_backend.authenticators.passwordauth import default_password_validator, LocalPasswordAuthenticator
from crossauth_backend.storageimpl.inmemorystorage import InMemoryUserStorage
from crossauth_backend.common.interfaces import UserState

class default_password_validator_test(unittest.IsolatedAsyncioTestCase):

    async def test_valid_password(self):
        errors = default_password_validator({"password": "AbcdEf01"})
        self.assertEqual(len(errors), 0)

    async def test_invalid_password(self):
        errors = default_password_validator({"password": "ABCdefgh"})
        self.assertEqual(len(errors), 1)
        errors = default_password_validator({"password": "ABCDEF01"})
        self.assertEqual(len(errors), 1)
        errors = default_password_validator({"password": "ABCDEFGHI"})
        self.assertEqual(len(errors), 2)
        errors = default_password_validator({"password": "ABCD"})
        self.assertEqual(len(errors), 3)

    async def test_authenticate_user(self):
        user_storage = InMemoryUserStorage()
        authenticator = LocalPasswordAuthenticator(user_storage)
        hash = await authenticator.create_password_hash("bobPass123")
        await user_storage.create_user({"username": "bob", "state": UserState.active, "factor1": "password"}, 
            {"password": hash})
        user_and_secrets = await user_storage.get_user_by_username("bob")
        ok = False
        try:
            await authenticator.authenticate_user(user_and_secrets["user"], user_and_secrets["secrets"], {"password": "bobPass123"})
            ok = True
        except Exception as e:
            print(e)
        
        self.assertTrue(ok)

    async def test_authenticate_user_with_secret(self):
        user_storage = InMemoryUserStorage()
        authenticator = LocalPasswordAuthenticator(user_storage, {"secret": "ABCDEFGHIJKLMNOPQRSTUV", "enable_secret_for_password_hash": True})
        hash = await authenticator.create_password_hash("bobPass123")
        await user_storage.create_user({"username": "bob", "state": UserState.active, "factor1": "password"}, 
            {"password": hash})
        user_and_secrets = await user_storage.get_user_by_username("bob")
        ok = False
        try:
            await authenticator.authenticate_user(user_and_secrets["user"], user_and_secrets["secrets"], {"password": "bobPass123"})
            ok = True
        except Exception as e:
            print(e)
        
        self.assertTrue(ok)
