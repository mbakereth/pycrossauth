# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import unittest
from src.crossauth_backend import CrossauthError, ErrorCode

class CrossauthErrorTest(unittest.TestCase):

    def test_raise_CrossauthError(self):
        ce : CrossauthError | None = None
        try:
            raise CrossauthError(ErrorCode.Connection, "Test")
        except BaseException as e:
            ce = CrossauthError.as_crossauth_error(e)
        self.assertIsNotNone(ce)
        self.assertEqual(ce.code, ErrorCode.Connection)
        self.assertEqual(ce.message, "Test")

    def test_raise_other(self):
        ce : CrossauthError | None = None
        try:
            raise Exception("Test")
        except BaseException as e:
            ce = CrossauthError.as_crossauth_error(e)
        self.assertIsNotNone(ce)
        self.assertEqual(ce.code, ErrorCode.UnknownError)
        self.assertEqual(ce.message, "Test")
        self.assertEqual(str(ce), "Test")
