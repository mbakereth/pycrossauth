# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import unittest
from datetime import datetime, timedelta
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage, InMemoryUserStorage, InMemoryOAuthClientStorage, InMemoryOAuthAuthorizationStorage
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.interfaces import PartialUser, PartialUserSecrets, UserState, \
    UserInputFields, UserSecretsInputFields, OAuthClient, PartialOAuthClient
import json
from crossauth_backend.oauth.client import OAuthFlows
from nulltype import Null

class in_memory_key_storage_test(unittest.IsolatedAsyncioTestCase):

    async def test_createAndDeleteSession(self):
        key = "ABCDEF123"
        key_storage = InMemoryKeyStorage()
        now = datetime.now()
        expiry = datetime.now() + timedelta(1)
        await key_storage.save_key("bob", key, now, expiry)
        session_key = await key_storage.get_key(key)
        self.assertTrue("userid" in session_key)
        if ("userid" in session_key):
            self.assertEqual(session_key["userid"], "bob")
        self.assertEqual(session_key["expires"], expiry)
        await key_storage.delete_key(key)
        exception : CrossauthError | None = None
        try:
            session_key = await key_storage.get_key(key)
        except CrossauthError as e:
            exception = e
        self.assertIsNotNone(exception)
        if (exception is not None):
            self.assertEqual(exception.code, ErrorCode.InvalidKey)

    async def test_deleteAllForUser(self):
        key1 = "ABCDEF123"
        key2 = "ABCDEF456"
        key_storage = InMemoryKeyStorage()
        now = datetime.now()
        expiry = datetime.now() + timedelta(1)
        await key_storage.save_key("bob", key1, now, expiry)
        await key_storage.save_key("bob", key2, now, expiry)
        await key_storage.delete_all_for_user("bob", "")

        with self.assertRaises(CrossauthError):
            await key_storage.get_key(key1)
        with self.assertRaises(CrossauthError):
            await key_storage.get_key(key2)

    async def test_deleteAllForUserExcept(self):
        key1 = "ABCDEF123"
        key2 = "ABCDEF456"
        key_storage = InMemoryKeyStorage()
        now = datetime.now()
        expiry = datetime.now() + timedelta(1)
        await key_storage.save_key("bob", key1, now, expiry)
        await key_storage.save_key("bob", key2, now, expiry)
        await key_storage.delete_all_for_user("bob", "", key1)

        try:
            await key_storage.get_key(key1)
        except:
            self.fail("key_storage.get_key(key1) unexpectedly raised an exception")

        with self.assertRaises(CrossauthError):
            await key_storage.get_key(key2)

    async def test_addData(self):
        key = "ABCDEF123"
        key_storage = InMemoryKeyStorage()
        now = datetime.now()
        expiry = datetime.now() + timedelta(1)
        await key_storage.save_key("bob", key, now, expiry)
        await key_storage.update_data(key, "name1", "abc")
        key1 = await key_storage.get_key(key)
        if ("data" not in key1): self.fail("data is not in key1")
        data1 = json.loads(key1["data"])
        if ("name1" not in data1): self.fail("name1 is not in data1")
        self.assertEqual(data1["name1"], "abc")

        await key_storage.update_data(key, "name2", {"name3": "xyz"})
        key1 = await key_storage.get_key(key)
        if ("data" not in key1): self.fail("data is not in key1")
        data1 = json.loads(key1["data"])
        self.assertEqual(data1["name2"]["name3"], "xyz")

    async def test_updateWithDots(self):
        key = "ABCDEF123"
        key_storage = InMemoryKeyStorage()
        now = datetime.now()
        expiry = datetime.now() + timedelta(1)
        await key_storage.save_key("bob", key, now, expiry, json.dumps({"part1": {"part2": "2"}}))
        await key_storage.update_data(key, "part1.part2", {"part3": "3", "part4": "4"})
        await key_storage.update_data(key, "part1.part5", "5")
        key1 = await key_storage.get_key(key)
        if ("data" not in key1): self.fail("data is not in key1")
        data1 = json.loads(key1["data"])
        self.assertEqual(data1["part1"]["part2"]["part3"], "3")
        self.assertEqual(data1["part1"]["part5"], "5")

    async def test_deleteWithDots(self):
        key = "ABCDEF123"
        key_storage = InMemoryKeyStorage()
        now = datetime.now()
        expiry = datetime.now() + timedelta(1)
        await key_storage.save_key("bob", key, now, expiry, json.dumps({"part1": {"part2": {"part3": "3", "part4": "4"}, "part5": "5"}}))
        await key_storage.delete_data(key, "part1.part2.part3")
        await key_storage.delete_data(key, "part1.part5")
        key1 = await key_storage.get_key(key)
        if ("data" not in key1): self.fail("data is not in key1")
        data1 = json.loads(key1["data"])
        self.assertTrue("part2" in data1["part1"])
        self.assertTrue("part4" in data1["part1"]["part2"])
        self.assertFalse("part3" in data1["part1"]["part2"])
        self.assertFalse("part5" in data1["part1"])

    async def test_getAllForUser(self):
        key1 = "ABCDEF123"
        key2 = "ABCDEF456"
        key3 = "XYZ123456"
        key_storage = InMemoryKeyStorage()
        now = datetime.now()
        expiry = datetime.now() + timedelta(1)
        await key_storage.save_key("bob", key1, now, expiry)
        await key_storage.save_key("bob", key2, now, expiry)
        await key_storage.save_key(None, key3, now, expiry)

        keys = await key_storage.get_all_for_user("bob")
        self.assertEqual(len(keys), 2)

        keys = await key_storage.get_all_for_user(None)
        self.assertEqual(len(keys), 1)

    async def test_getAllForUserWhenEmpty(self):
        key_storage = InMemoryKeyStorage()

        keys = await key_storage.get_all_for_user("bob")
        self.assertEqual(len(keys), 0)

        keys = await key_storage.get_all_for_user(None)
        self.assertEqual(len(keys), 0)

    async def test_deleteKeyForUser(self):
        key1 = "ABCDEF123"
        key2 = "ABCDEF456"
        key_storage = InMemoryKeyStorage()
        now = datetime.now()
        expiry = datetime.now() + timedelta(1)
        await key_storage.save_key("bob", key1, now, expiry)
        await key_storage.save_key("bob", key2, now, expiry)
        await key_storage.delete_matching({"userid": "bob", "value": key1})

        keys = await key_storage.get_all_for_user("bob")
        self.assertEqual(len(keys), 1)

async def test_data():
    user_storage = InMemoryUserStorage()
    await user_storage.create_user({
        "username": "bob",
        "email": "bob@bob.com",
        "state": "active",
        "factor1": "localpassword"}, {
        "password": "bobPass123"
    })
    await user_storage.create_user({
        "username": "alice",
        "email": "alice@alice.com",
        "state": "active",
        "factor1": "localpassword"}, {
        "password": "alicePass123"
    })
    return user_storage

class in_memory_user_storage_test(unittest.IsolatedAsyncioTestCase):

    async def test_createUser(self):
        user_storage = InMemoryUserStorage()
        user = await user_storage.create_user({
            "username": "bob",
            "email": "bob@bob.com",
            "state": "active",
            "factor1": "localpassword"}, {
            "password": "bobPass123"
        })
        self.assertEqual(user["username"], "bob")
        self.assertEqual(user["username_normalized"], "bob")
        self.assertEqual("email" in user and user["email"], "bob@bob.com")
        self.assertEqual("email_normalized" in user and user["email_normalized"], "bob@bob.com")


    async def test_getUserByUsername(self):
        user_storage = await test_data()
        user_and_secrets = await user_storage.get_user_by_username("bob")
        self.assertEqual(user_and_secrets["user"]["username"], "bob")
        self.assertEqual("secrets" in user_and_secrets and "password" in user_and_secrets["secrets"] and user_and_secrets["secrets"]["password"], "bobPass123")

    async def test_getUserById(self):
        user_storage = await test_data()
        user_and_secrets = await user_storage.get_user_by_id("bob")
        self.assertEqual(user_and_secrets["user"]["username"], "bob")
        self.assertEqual("secrets" in user_and_secrets and "password" in user_and_secrets["secrets"] and user_and_secrets["secrets"]["password"], "bobPass123")

    async def test_getUserByEmail(self):
        user_storage = await test_data()
        user_and_secrets = await user_storage.get_user_by_email("bob@bob.com")
        self.assertEqual(user_and_secrets["user"]["username"], "bob")
        self.assertEqual("secrets" in user_and_secrets and "password" in user_and_secrets["secrets"] and user_and_secrets["secrets"]["password"], "bobPass123")

    async def test_deleteUserByUsername(self):
        user_storage = await test_data()
        await user_storage.delete_user_by_username("bob")
        found = False
        try:
            await user_storage.get_user_by_username("bob")
            found = True
        except:
            pass
        self.assertEqual(found, False)

    async def test_updateUser(self):
        user_storage = await test_data()
        new_user : PartialUser = {
            "id": "bob",
            "email": "newbob@bob.com"
        }
        await user_storage.update_user(new_user)
        user_and_secrets = await user_storage.get_user_by_email("bob@bob.com")
        self.assertEqual(user_and_secrets["user"]["username"], "bob")
        self.assertEqual("secrets" in user_and_secrets and "password" in user_and_secrets["secrets"] and user_and_secrets["secrets"]["password"], "bobPass123")

    async def test_updatePassword(self):
        user_storage = await test_data()
        new_user : PartialUser = {
            "id": "bob",
        }
        new_password : PartialUserSecrets = {
            "password": "newpass",
        }
        await user_storage.update_user(new_user, new_password)
        user_and_secrets = await user_storage.get_user_by_email("bob@bob.com")
        self.assertEqual("secrets" in user_and_secrets and "password" in user_and_secrets["secrets"] and user_and_secrets["secrets"]["password"], "newpass")

######################
## UserStorage

class InMemoryUserStorageTest(unittest.IsolatedAsyncioTestCase):

    async def get_test_storage(self) -> InMemoryUserStorage:
        user_storage = InMemoryUserStorage()
        user : UserInputFields = {
            "username": "bob",
            "state": UserState.active,
            "email": "bob@bob.com",
            "factor1": "password"
        }
        secrets : UserSecretsInputFields = {
            "password": "bobPass123"
        }
        await user_storage.create_user(user, secrets)
        return user_storage
    
    async def test_get_user_by(self):
        user_storage = await self.get_test_storage()
        ret = await user_storage.get_user_by("username", "bob")
        self.assertEqual(ret["user"]["id"], "bob")
        self.assertEqual(ret["user"]["username"], "bob")
        self.assertEqual(ret["user"]["username_normalized"], "bob")
        self.assertEqual("email" in ret["user"] and ret["user"]["email"], "bob@bob.com")
        self.assertEqual("email_normalized" in ret["user"] and ret["user"]["email_normalized"], "bob@bob.com")
        self.assertEqual("password" in ret["secrets"] and ret["secrets"]["password"], "bobPass123")

    async def test_get_user_by_id(self):
        user_storage = await self.get_test_storage()
        ret = await user_storage.get_user_by_id("bob")
        self.assertEqual(ret["user"]["id"], "bob")

    async def test_get_user_by_username(self):
        user_storage = await self.get_test_storage()
        ret = await user_storage.get_user_by_username("Bob")
        self.assertEqual(ret["user"]["id"], "bob")

    async def test_get_user_by_email(self):
        user_storage = await self.get_test_storage()
        ret = await user_storage.get_user_by_email("Bob@bob.com")
        self.assertEqual(ret["user"]["id"], "bob")

    async def test_delete_user_by_username(self):
        user_storage = await self.get_test_storage()
        await user_storage.delete_user_by_username("Bob")
        found = False
        try:
            await user_storage.get_user_by_id("bob")
            found = True
        except:
            pass
        self.assertEqual(found, False)

    async def test_delete_user_by_id(self):
        user_storage = await self.get_test_storage()
        await user_storage.delete_user_by_id("bob")
        found = False
        try:
            await user_storage.get_user_by_id("bob")
            found = True
        except:
            pass
        self.assertEqual(found, False)

    async def test_create_user(self):
        user_storage = await self.get_test_storage()
        new_user : UserInputFields = {
            "username": "mary",
            "email": "mary@mary.com",
            "state": UserState.active,
            "factor1": "password"
        }
        created_user = await user_storage.create_user(new_user)
        self.assertEqual(created_user["username"], "mary")
        self.assertEqual(created_user["username_normalized"], "mary")
        self.assertEqual("email" in created_user and created_user["email"], "mary@mary.com")
        self.assertEqual("email_normalized" in created_user and created_user["email_normalized"], "mary@mary.com")
        self.assertEqual("state" in created_user and created_user["state"], UserState.active)

    async def test_create_user_and_secrets(self):
        user_storage = await self.get_test_storage()
        new_user : UserInputFields = {
            "username": "mary",
            "email": "mary@mary.com",
            "state": UserState.active,
            "factor1": "password"
        }
        new_secrets : UserSecretsInputFields = {
            "password": "maryPass123",
        }
        created_user = await user_storage.create_user(new_user, new_secrets)
        self.assertEqual(created_user["username"], "mary")
        self.assertEqual(created_user["username_normalized"], "mary")
        self.assertEqual("email" in created_user and created_user["email"], "mary@mary.com")
        self.assertEqual("email_normalized" in created_user and created_user["email_normalized"], "mary@mary.com")
        self.assertEqual("state" in created_user and created_user["state"], UserState.active)

        ret = await user_storage.get_user_by_id(created_user["id"])
        self.assertEqual("secrets" in ret and "password" in ret["secrets"] and ret["secrets"]["password"], "maryPass123")

######################
## OAuthClientStorage


class InMemoryClientStorageTest(unittest.IsolatedAsyncioTestCase):

    async def get_test_storage(self) -> InMemoryOAuthClientStorage:
        client_storage = InMemoryOAuthClientStorage()
        await client_storage.create_client({
            "client_id": "1",
            "client_name": "A",
            "confidential": False,
            "redirect_uri": ["http://localhost/1"],
            "valid_flow": [OAuthFlows.AuthorizationCode]
        })
        await client_storage.create_client({
            "client_id": "2",
            "client_name": "B",
            "confidential": True,
            "client_secret": "passB",
            "redirect_uri": ["http://localhost/1"],
            "valid_flow": [OAuthFlows.AuthorizationCode]
        })
        await client_storage.create_client({
            "client_id": "3",
            "client_name": "C",
            "confidential": True,
            "client_secret": "passC",
            "userid": "bob",
            "redirect_uri": ["http://localhost/1"],
            "valid_flow": [OAuthFlows.AuthorizationCode]
        })
        await client_storage.create_client({
            "client_id": "4",
            "client_name": "C",
            "confidential": True,
            "client_secret": "passC",
            "redirect_uri": ["http://localhost/1"],
            "valid_flow": [OAuthFlows.AuthorizationCode]
        })
        await client_storage.create_client({
            "client_id": "5",
            "client_name": "D",
            "confidential": False,
            "redirect_uri": ["http://localhost/1"],
            "valid_flow": [OAuthFlows.AuthorizationCode]
        })
        return client_storage
    
    async def test_get_client(self):
        client_storage = await self.get_test_storage()
        ret = await client_storage.get_client_by_id("1")
        self.assertEqual(ret["client_id"], '1')
        self.assertTrue("client_secret" in ret)
        self.assertIsNone("client_secret" in ret and ret["client_secret"])
        self.assertTrue("userid" in ret)
        self.assertIsNone("userid" in ret and ret["userid"])
        
    async def test_get_client_with_secret(self):
        client_storage = await self.get_test_storage()
        ret = await client_storage.get_client_by_id("2")
        self.assertEqual(ret["client_id"], '2')
        self.assertTrue("client_secret" in ret)
        self.assertEqual("client_secret" in ret and ret["client_secret"], "passB")
        self.assertTrue("userid" in ret)
        self.assertIsNone("userid" in ret and ret["userid"])

    async def test_get_client_with_secret_and_userid(self):
        client_storage = await self.get_test_storage()
        ret = await client_storage.get_client_by_id("3")
        self.assertEqual(ret["client_id"], '3')
        self.assertTrue("client_secret" in ret)
        self.assertEqual("client_secret" in ret and ret["client_secret"], "passC")
        self.assertTrue("userid" in ret)
        self.assertEqual("userid" in ret and ret["userid"], "bob")

    async def test_get_client_by_name(self):
        client_storage = await self.get_test_storage()
        ret = await client_storage.get_client_by_name("A")
        self.assertEqual(len(ret), 1)
        self.assertEqual(ret[0]["client_id"], '1')
        self.assertTrue("client_secret" in ret[0])
        self.assertIsNone("client_secret" in ret[0] and ret[0]["client_secret"])
        self.assertTrue("userid" in ret[0])
        self.assertIsNone("userid" in ret[0] and ret[0]["userid"])

    async def test_get_client_by_name_user_mitmatch(self):
        client_storage = await self.get_test_storage()
        ret = await client_storage.get_client_by_name("C", "mary")
        self.assertEqual(len(ret), 0)

    async def test_get_client_by_name_user_null(self):
        client_storage = await self.get_test_storage()
        ret = await client_storage.get_client_by_name("C", Null)
        self.assertEqual(len(ret), 1)

    async def test_get_client_with_uri_and_flow(self):
        client_storage = await self.get_test_storage()
        ret = await client_storage.get_client_by_id("5")
        self.assertEqual(ret["client_id"], '5')
        self.assertTrue("client_secret" in ret)
        self.assertIsNone("client_secret" in ret and ret["client_secret"])
        self.assertTrue("userid" in ret)
        self.assertIsNone("userid" in ret and ret["userid"])
        self.assertEqual(len(ret["redirect_uri"]), 1)
        self.assertEqual(ret["redirect_uri"][0], "http://localhost/1")
        self.assertEqual(len(ret["valid_flow"]), 1)
        self.assertEqual(ret["valid_flow"][0], OAuthFlows.AuthorizationCode)

    async def test_get_paginated(self):
        client_storage = await self.get_test_storage()
        ret = await client_storage.get_clients(0, 2)
        self.assertEqual(len(ret), 2)

    async def test_get_paginated_userid(self):
        client_storage = await self.get_test_storage()
        ret = await client_storage.get_clients(0, 2, "bob")
        self.assertEqual(len(ret), 1)

    async def test_create(self):
        client_storage = await self.get_test_storage()
        client : OAuthClient = {
            "client_id": "11",
            "client_name": "AA",
            "confidential": False,
            "redirect_uri": ["http://localhost/11"],
            "valid_flow": [OAuthFlows.AuthorizationCode]
        }
        ret = await client_storage.create_client(client)
        self.assertEqual(ret["client_id"], "11")
        self.assertEqual(ret["client_name"], "AA")
        self.assertEqual(ret["confidential"], False)
        self.assertEqual(len(ret["redirect_uri"]), 1)
        self.assertEqual(ret["redirect_uri"][0], "http://localhost/11")
        self.assertEqual(len(ret["valid_flow"]), 1)
        self.assertEqual(ret["valid_flow"][0], OAuthFlows.AuthorizationCode)

    async def test_update(self):
        client_storage = await self.get_test_storage()
        client : PartialOAuthClient = {
            "client_id": "5",
            "client_name": "BB",
            "confidential": True,
            "redirect_uri": ["http://localhost/2"],
            "valid_flow": [OAuthFlows.AuthorizationCodeWithPKCE]
        }
        await client_storage.update_client(client)
        ret = await client_storage.get_client_by_id("5")
        self.assertEqual(ret["client_name"], "BB")
        self.assertEqual(ret["confidential"], True)
        self.assertEqual(len(ret["redirect_uri"]), 1)
        self.assertEqual(ret["redirect_uri"][0], "http://localhost/2")
        self.assertEqual(len(ret["valid_flow"]), 1)
        self.assertEqual(ret["valid_flow"][0], OAuthFlows.AuthorizationCodeWithPKCE)

    async def test_delete(self):
        client_storage = await self.get_test_storage()
        await client_storage.delete_client("5")
        found = False
        try:
            await client_storage.get_client_by_id("5")
            found = True
        except:
            pass
        self.assertEqual(found, False)

######################
## OAuthAuthorizationtorage


class InMemoryOAuthAuthorizationStorageTest(unittest.IsolatedAsyncioTestCase):

    async def get_test_storage(self) -> InMemoryOAuthAuthorizationStorage:
        auth_storage = InMemoryOAuthAuthorizationStorage()
        await auth_storage.update_authorizations("1", None, ["read"])
        await auth_storage.update_authorizations("1", "bob", ["read1"])
        return auth_storage
    
    async def test_get_authorizations(self):
        auth_storage = await self.get_test_storage()
        ret = await auth_storage.get_authorizations("1")
        self.assertEqual(len(ret), 1)
        self.assertEqual(ret[0], "read")

    async def test_update_authorizations(self):
        auth_storage = await self.get_test_storage()
        await auth_storage.update_authorizations("1", None, ["write", "x"])
        ret = await auth_storage.get_authorizations("1")
        self.assertEqual(len(ret), 2)
        self.assertIn(ret[0], ["write", "x"])
        self.assertIn(ret[1], ["write", "x"])

    async def test_update_authorizations_user(self):
        auth_storage = await self.get_test_storage()
        await auth_storage.update_authorizations("1", "bob", ["write1", "x1"])
        ret = await auth_storage.get_authorizations("1", "bob")
        self.assertEqual(len(ret), 2)
        self.assertIn(ret[0], ["write1", "x1"])
        self.assertIn(ret[1], ["write1", "x1"])
