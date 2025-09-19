# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import unittest
from datetime import datetime, timedelta
from crossauth_backend.storageimpl.sqlalchemystorage import SqlAlchemyKeyStorage, SqlAlchemyUserStorage, \
    SqlAlchemyOAuthClientStorage, SqlAlchemyOAuthAuthorizationStorage, \
    register_sqlite_datetime
from crossauth_backend.common.error import CrossauthError, ErrorCode
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text, Row
from typing import Any, NamedTuple
import json
from sqlalchemy.ext.asyncio import AsyncEngine
from crossauth_backend.common.interfaces import PartialUser, UserInputFields, UserSecretsInputFields, PartialUserSecrets, UserState, \
    OAuthClient, PartialOAuthClient
import logging
from nulltype import Null
from crossauth_backend.oauth.client import OAuthFlows

register_sqlite_datetime()

class SqlAlchemyKeyStorageTest(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        logging.basicConfig()
        logging.getLogger("sqlalchemy.engine").setLevel(logging.ERROR)

    async def get_clean_conn(self):
        engine = create_async_engine(
            os.environ["SQLITE_URL"],
            echo=False
        )
        async with engine.begin() as conn:
            await conn.execute(text("DELETE from Key"))
        return engine
    
    async def test_createAndDeleteSession(self):
        engine = await self.get_clean_conn()
        key = "ABCDEF123"
        key_storage = SqlAlchemyKeyStorage(engine)
        now = datetime.now()
        expiry = datetime.now() + timedelta(1)
        await key_storage.save_key(None, key, now, expiry)
        session_key = await key_storage.get_key(key)
        self.assertTrue("userid" in session_key)
        if ("userid" in session_key):
            self.assertEqual(session_key["userid"], None)
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
        engine = await self.get_clean_conn()
        key_storage = SqlAlchemyKeyStorage(engine)
        key1 = "ABCDEF123"
        key2 = "ABCDEF456"
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
        engine = await self.get_clean_conn()
        key_storage = SqlAlchemyKeyStorage(engine)
        key1 = "ABCDEF123"
        key2 = "ABCDEF456"
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
        engine = await self.get_clean_conn()
        key_storage = SqlAlchemyKeyStorage(engine)
        key = "ABCDEF123"
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
        engine = await self.get_clean_conn()
        key_storage = SqlAlchemyKeyStorage(engine)
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
        engine = await self.get_clean_conn()
        key_storage = SqlAlchemyKeyStorage(engine)
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
        engine = await self.get_clean_conn()
        key_storage = SqlAlchemyKeyStorage(engine)
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
        engine = await self.get_clean_conn()
        key_storage = SqlAlchemyKeyStorage(engine)

        keys = await key_storage.get_all_for_user("bob")
        self.assertEqual(len(keys), 0)

        keys = await key_storage.get_all_for_user(None)
        self.assertEqual(len(keys), 0)

    # async def test_deleteKeyForUser(self):
    #     key1 = "ABCDEF123"
    #     key2 = "ABCDEF456"
    #     engine = await self.get_clean_conn()
    #     key_storage = SqlAlchemyKeyStorage(engine)
    #     now = datetime.now()
    #     expiry = datetime.now() + timedelta(1)
    #     await key_storage.save_key(1, key1, now, expiry)
    #     await key_storage.save_key(1, key2, now, expiry)
    #     await key_storage.delete_matching({"userid": 1, "value": key1})

    #     keys = await key_storage.get_all_for_user("bob")
    #     self.assertEqual(len(keys), 1)

def to_dict(row : Row[Any], with_relationships:bool=True) -> dict[str,Any]:
    return row._asdict() # type: ignore

###################################
# UserStorage

class EngineAndId(NamedTuple):
    engine: AsyncEngine
    id: int

class SqlAlchemyUserStorageTest(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        logging.basicConfig()
        logging.getLogger("sqlalchemy").setLevel(logging.ERROR)


    async def get_test_conn(self) -> EngineAndId:
        engine = create_async_engine(
            os.environ["SQLITE_URL"],
            echo=False
        )
        async with engine.begin() as conn:
            await conn.execute(text("DELETE from User"))
            await conn.execute(text("DELETE from UserSecrets"))
            await conn.execute(text("""
                INSERT INTO User (username, username_normalized, email, email_normalized) 
                    VALUES ('bob', 'bob', 'bob@bob.com', 'bob@bob.com')
            """))
            res = await conn.execute(text("SELECT id FROM User where username = 'bob'"))
            row = res.fetchone()
            if (row is None):
                raise Exception("Can't get User record I just created")
            row_dict = to_dict(row)
            await conn.execute(text(f"""
                INSERT INTO UserSecrets (userid, password) 
                    VALUES ({row_dict["id"]}, 'bobPass123')
            """))
            id : int = row_dict["id"]
        return EngineAndId(engine, id)
    
    async def test_get_user_by(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine)
        ret = await user_storage.get_user_by("username", "bob")
        self.assertEqual(ret["user"]["id"], conn.id)
        self.assertEqual(ret["user"]["username"], "bob")
        self.assertTrue("username_normalized" in ret["user"])
        if ("username_normalized" in ret["user"]):
            self.assertEqual(ret["user"]["username_normalized"], "bob")
        self.assertEqual("email" in ret["user"] and ret["user"]["email"], "bob@bob.com")
        self.assertEqual("email_normalized" in ret["user"] and ret["user"]["email_normalized"], "bob@bob.com")
        self.assertEqual("password" in ret["secrets"] and ret["secrets"]["password"], "bobPass123")

    async def test_get_user_by_id(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine)
        ret = await user_storage.get_user_by_id(conn.id)
        self.assertEqual(ret["user"]["id"], conn.id)

    async def test_get_user_by_username(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine)
        ret = await user_storage.get_user_by_username("Bob")
        self.assertEqual(ret["user"]["id"], conn.id)

    async def test_get_user_by_email(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine)
        ret = await user_storage.get_user_by_email("Bob@bob.com")
        self.assertEqual(ret["user"]["id"], conn.id)

    async def test_get_user_by_username_unnormalized(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine, {"normalize_username": False})
        ok = False
        try:
            await user_storage.get_user_by_username("Bob")
            ok = True
        except:
            pass
        self.assertFalse(ok)

    async def test_get_user_by_email_unnormalized(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine, {"normalize_email": False})
        ok = False
        try:
            await user_storage.get_user_by_email("Bob@bob.com")
            ok = True
        except:
            pass
        self.assertFalse(ok)

    async def test_delete_user_by_username(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine)
        await user_storage.delete_user_by_username("Bob")
        found = False
        try:
            await user_storage.get_user_by_id(conn.id)
            found = True
        except:
            pass
        self.assertEqual(found, False)

    async def test_delete_user_by_id(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine)
        await user_storage.delete_user_by_id(conn.id)
        found = False
        try:
            await user_storage.get_user_by_id(conn.id)
            found = True
        except:
            pass
        self.assertEqual(found, False)

    async def test_create_user(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine)
        new_user : UserInputFields = {
            "username": "mary",
            "email": "mary@mary.com",
            "state": UserState.active,
            "factor1": "password"
        }
        created_user = await user_storage.create_user(new_user)
        self.assertEqual(created_user["username"], "mary")
        self.assertTrue("username_normalized" in created_user)
        if ("username_normalized" in created_user):
            self.assertEqual(created_user["username_normalized"], "mary")
        self.assertEqual("email" in created_user and created_user["email"], "mary@mary.com")
        self.assertEqual("email_normalized" in created_user and created_user["email_normalized"], "mary@mary.com")
        self.assertEqual("state" in created_user and created_user["state"], UserState.active)

    async def test_create_user_and_secrets(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine)
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
        self.assertTrue("username_normalized" in created_user)
        if ("username_normalized" in created_user):
            self.assertEqual(created_user["username_normalized"], "mary")
        self.assertEqual("email" in created_user and created_user["email"], "mary@mary.com")
        self.assertEqual("email_normalized" in created_user and created_user["email_normalized"], "mary@mary.com")
        self.assertEqual("state" in created_user and created_user["state"], UserState.active)

        ret = await user_storage.get_user_by_id(created_user["id"])
        self.assertEqual("secrets" in ret and "password" in ret["secrets"] and ret["secrets"]["password"], "maryPass123")

    async def test_update_user(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine)

        user : PartialUser = {
            "id": conn.id,
            "email": "bob1@bob.com",
        }
        await user_storage.update_user(user)
        ret = await user_storage.get_user_by_id(conn.id)
        updated_user = ret["user"]
        self.assertEqual(updated_user["username"], "bob")
        self.assertEqual("email" in updated_user and updated_user["email"], "bob1@bob.com")
        self.assertEqual("email_normalized" in updated_user and updated_user["email_normalized"], "bob1@bob.com")

    async def test_update_user_and_secrets(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        user_storage = SqlAlchemyUserStorage(engine)

        user : PartialUser = {
            "id": conn.id,
            "email": "bob1@bob.com",
        }
        secrets: PartialUserSecrets = {
            "password": "xyz"
        }
        await user_storage.update_user(user, secrets)
        ret = await user_storage.get_user_by_id(conn.id)
        updated_user = ret["user"]
        updated_secrets = ret["secrets"]
        self.assertEqual(updated_user["username"], "bob")
        self.assertEqual("email" in updated_user and updated_user["email"], "bob1@bob.com")
        self.assertEqual("email_normalized" in updated_user and updated_user["email_normalized"], "bob1@bob.com")
        self.assertEqual("password" in updated_secrets and updated_secrets["password"], "xyz")

######################
## OAuthClientStorage

class SqlAlchemyClientStorageTest(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        logging.basicConfig()
        logging.getLogger("sqlalchemy").setLevel(logging.ERROR)


    async def get_test_conn(self) -> EngineAndId:
        engine = create_async_engine(
            os.environ["SQLITE_URL"],
            echo=False
        )
        async with engine.begin() as conn:
            await conn.execute(text("DELETE from User"))
            await conn.execute(text("DELETE from UserSecrets"))
            await conn.execute(text("DELETE from OAuthClient"))
            await conn.execute(text("DELETE from OAuthClientValidFlow"))
            await conn.execute(text("DELETE from OAuthClientRedirectUri"))

            # create user
            await conn.execute(text("""
                INSERT INTO User (username, username_normalized, email, email_normalized) 
                    VALUES ('bob', 'bob', 'bob@bob.com', 'bob@bob.com')
            """))
            res = await conn.execute(text("SELECT id FROM User where username = 'bob'"))
            row = res.fetchone()
            if (row is None):
                raise Exception("Can't get User record I just created")
            row_dict = to_dict(row)
            await conn.execute(text(f"""
                INSERT INTO UserSecrets (userid, password) 
                    VALUES ({row_dict["id"]}, 'bobPass123')
            """))
            id : int = row_dict["id"]

            # create client without secret or user id
            await conn.execute(text("""
                INSERT INTO OAuthClient (client_id, confidential, client_name) 
                    VALUES ('1', 0, 'A')
            """))

            # create client with secret and without user id
            await conn.execute(text("""
                INSERT INTO OAuthClient (client_id, confidential, client_name, client_secret) 
                    VALUES ('2', 1, 'B', 'passB')
            """))

            # create client with secret and user id
            await conn.execute(text(f"""
                INSERT INTO OAuthClient (client_id, confidential, client_name, client_secret, userid) 
                    VALUES ('3', 1, 'C', 'passC', {id})
            """))

            # create client with secret and user id
            await conn.execute(text(f"""
                INSERT INTO OAuthClient (client_id, confidential, client_name, client_secret) 
                    VALUES ('4', 1, 'C', 'passC')
            """))

            # create client with flows and redirect uris
            await conn.execute(text("""
                INSERT INTO OAuthClient (client_id, confidential, client_name) 
                    VALUES ('5', 1, 'D')
            """))
            await conn.execute(text("""
                INSERT INTO OAuthClientRedirectUri (client_id, uri) 
                    VALUES ('5', 'http://localhost/1')
            """))
            await conn.execute(text(f"""
                INSERT INTO OAuthClientValidFlow (client_id, flow) 
                    VALUES ('5', '{OAuthFlows.AuthorizationCode}')
            """))
        return EngineAndId(engine, id)
    
    async def test_get_client(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
        ret = await client_storage.get_client_by_id("1")
        self.assertEqual(ret["client_id"], '1')
        self.assertTrue("client_secret" in ret)
        self.assertIsNone("client_secret" in ret and ret["client_secret"])
        self.assertTrue("userid" in ret)
        self.assertIsNone("userid" in ret and ret["userid"])

    async def test_get_client_with_secret(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
        ret = await client_storage.get_client_by_id("2")
        self.assertEqual(ret["client_id"], '2')
        self.assertTrue("client_secret" in ret)
        self.assertEqual("client_secret" in ret and ret["client_secret"], "passB")
        self.assertTrue("userid" in ret)
        self.assertIsNone("userid" in ret and ret["userid"])

    async def test_get_client_with_secret_and_userid(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
        ret = await client_storage.get_client_by_id("3")
        self.assertEqual(ret["client_id"], '3')
        self.assertTrue("client_secret" in ret)
        self.assertEqual("client_secret" in ret and ret["client_secret"], "passC")
        self.assertTrue("userid" in ret)
        self.assertEqual("userid" in ret and ret["userid"], conn.id)

    async def test_get_client_by_name(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
        ret = await client_storage.get_client_by_name("A")
        self.assertEqual(len(ret), 1)
        self.assertEqual(ret[0]["client_id"], '1')
        self.assertTrue("client_secret" in ret[0])
        self.assertIsNone("client_secret" in ret[0] and ret[0]["client_secret"])
        self.assertTrue("userid" in ret[0])
        self.assertIsNone("userid" in ret[0] and ret[0]["userid"])

    async def test_get_client_by_name_user_mitmatch(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
        ret = await client_storage.get_client_by_name("C", conn.id+1)
        self.assertEqual(len(ret), 0)

    async def test_get_client_by_name_user_null(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
        ret = await client_storage.get_client_by_name("C", Null)
        self.assertEqual(len(ret), 1)

    async def test_get_client_with_uri_and_flow(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
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
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
        ret = await client_storage.get_clients(0, 2)
        self.assertEqual(len(ret), 2)

    async def test_get_paginated_userid(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
        ret = await client_storage.get_clients(0, 2, conn.id)
        self.assertEqual(len(ret), 1)

    async def test_create(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
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
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
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
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthClientStorage(engine)
        await client_storage.delete_client("5")
        found = False
        try:
            await client_storage.get_client_by_id("5")
            found = True
        except:
            pass
        self.assertEqual(found, False)

##############
## OAuthAuthorizations

######################
## OAuthClientStorage

class SqlAlchemyOAuthAutorizationsTest(unittest.IsolatedAsyncioTestCase):

    @classmethod
    def setUpClass(cls):
        logging.basicConfig()
        logging.getLogger("sqlalchemy").setLevel(logging.ERROR)


    async def get_test_conn(self) -> EngineAndId:
        engine = create_async_engine(
            os.environ["SQLITE_URL"],
            echo=False
        )
        async with engine.begin() as conn:
            await conn.execute(text("DELETE from User"))
            await conn.execute(text("DELETE from UserSecrets"))
            await conn.execute(text("DELETE from OAuthClient"))
            await conn.execute(text("DELETE from OAuthClientValidFlow"))
            await conn.execute(text("DELETE from OAuthClientRedirectUri"))
            await conn.execute(text("DELETE from OAuthAuthorization"))

            # create user
            await conn.execute(text("""
                INSERT INTO User (username, username_normalized, email, email_normalized) 
                    VALUES ('bob', 'bob', 'bob@bob.com', 'bob@bob.com')
            """))
            res = await conn.execute(text("SELECT id FROM User where username = 'bob'"))
            row = res.fetchone()
            if (row is None):
                raise Exception("Can't get User record I just created")
            row_dict = to_dict(row)
            await conn.execute(text(f"""
                INSERT INTO UserSecrets (userid, password) 
                    VALUES ({row_dict["id"]}, 'bobPass123')
            """))
            id : int = row_dict["id"]

            # create client without secret or user id
            await conn.execute(text("""
                INSERT INTO OAuthClient (client_id, confidential, client_name) 
                    VALUES ('1', 0, 'A')
            """))

            # create authorization
            await conn.execute(text("""
                INSERT INTO OAuthAuthorization (client_id, scope) 
                    VALUES ('1', 'read')
            """))

            # create authorization
            await conn.execute(text(f"""
                INSERT INTO OAuthAuthorization (client_id, scope, userid) 
                    VALUES ('1', 'read1', {id})
            """))

        return EngineAndId(engine, id)
    
    async def test_get_authorizations(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthAuthorizationStorage(engine)
        ret = await client_storage.get_authorizations("1")
        self.assertEqual(len(ret), 1)
        self.assertEqual(ret[0], "read")

    async def test_update_authorizations(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthAuthorizationStorage(engine)
        await client_storage.update_authorizations("1", None, ["write", "x"])
        ret = await client_storage.get_authorizations("1")
        self.assertEqual(len(ret), 2)
        self.assertIn(ret[0], ["write", "x"])
        self.assertIn(ret[1], ["write", "x"])

    async def test_get_authorizations_user(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthAuthorizationStorage(engine)
        ret = await client_storage.get_authorizations("1", conn.id)
        self.assertEqual(len(ret), 1)
        self.assertEqual(ret[0], "read1")

    async def test_update_authorizations_user(self):
        conn = await self.get_test_conn()
        engine = conn.engine
        client_storage = SqlAlchemyOAuthAuthorizationStorage(engine)
        await client_storage.update_authorizations("1", conn.id, ["write1", "x1"])
        ret = await client_storage.get_authorizations("1", conn.id)
        self.assertEqual(len(ret), 2)
        self.assertIn(ret[0], ["write1", "x1"])
        self.assertIn(ret[1], ["write1", "x1"])
