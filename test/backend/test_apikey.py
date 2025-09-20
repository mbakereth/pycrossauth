import unittest
from crossauth_backend.apikey import ApiKeyManager
from crossauth_backend.storageimpl.inmemorystorage import InMemoryKeyStorage
import datetime
import json

class ApiKeyTest(unittest.IsolatedAsyncioTestCase):
    async def test_get_create_and_get_key(self):
        key_storage = InMemoryKeyStorage()
        manager = ApiKeyManager(key_storage, {"secret": "ABCCEFGHIJK"})
        now = datetime.datetime.now()
        expires = int((now.timestamp() + 60))

        ret = await manager.create_key("test", "bob", {"scope": "read"}, expires)
        data = json.loads(ret.key["data"] if "data" in ret.key else "")
        userid = ret.key["userid"] if "userid" in ret.key else ""
        self.assertEqual(data["scope"], "read")
        self.assertEqual(userid, "bob")
        new_key = await manager.get_key(ret.token)
        self.assertTrue("name" in new_key and new_key["name"] == "test")
