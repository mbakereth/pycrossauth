# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import unittest
from datetime import datetime, timedelta
from crossauth_backend.storageimpl.sqlalchemystorage import SqlAlchemyKeyStorage
from crossauth_backend.common.error import CrossauthError, ErrorCode
import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine, AsyncConnection
from sqlalchemy import text, Row

class SqlAlchemyKeyStorageTest(unittest.IsolatedAsyncioTestCase):

    async def get_clean_conn(self):
        engine = create_async_engine(
            os.environ["POSTGRES_URL"],
            echo=True
        )
        async with engine.connect() as conn:
            await conn.execute(text("DELETE from keys"))
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
