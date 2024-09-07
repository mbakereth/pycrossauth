import unittest
from datetime import datetime, timedelta
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage
from crossauth_backend.common.error import CrossauthError, ErrorCode
import json
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

