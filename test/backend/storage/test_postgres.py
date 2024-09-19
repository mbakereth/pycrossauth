# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import unittest
from datetime import datetime, timedelta
from crossauth_backend.storageimpl.postgresstorage import PostgresKeyStorage
from crossauth_backend.common.error import CrossauthError, ErrorCode
import os
import psycopg_pool

class postgres_key_storage_test(unittest.IsolatedAsyncioTestCase):

    async def get_clean_pool(self):
        pool = psycopg_pool.AsyncConnectionPool(os.environ['POSTGRES_CONNECTION'], open=False)
        await pool.open(True)
        async with pool.connection() as conn:
            async with conn.cursor() as cur:
                await cur.execute("DELETE from keys")
        return pool
    
    async def test_createAndDeleteSession(self):
        pool = await self.get_clean_pool()
        key = "ABCDEF123"
        key_storage = PostgresKeyStorage(pool)
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
