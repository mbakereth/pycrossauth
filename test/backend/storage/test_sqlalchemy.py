# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import unittest
from datetime import datetime, timedelta
from crossauth_backend.storageimpl.sqlalchemystorage import SqlAlchemyKeyStorage, SqlAlchemyUserStorage
from crossauth_backend.common.error import CrossauthError, ErrorCode
import os
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text, Row
from typing import Any
import json

class SqlAlchemyKeyStorageTest(unittest.IsolatedAsyncioTestCase):

    async def get_clean_conn(self):
        engine = create_async_engine(
            os.environ["SQLITE_URL"],
            echo=True
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

class SqlAlchemyUserStorageTest(unittest.IsolatedAsyncioTestCase):

    async def get_test_conn(self):
        engine = create_async_engine(
            os.environ["SQLITE_URL"],
            echo=True
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
        return engine
    
    async def test_get_user_by(self):
        engine = await self.get_test_conn()
        user_storage = SqlAlchemyUserStorage(engine)
        ret = await user_storage.get_user_by("username", "bob")
        print(ret)