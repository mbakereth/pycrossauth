import unittest
from crossauth_backend.utils import set_parameter, ParamType
from typing import Any

class A:
    def __init__(self):
        self.a = "a"
        self._a = "aa"
        self.__a = "aaa"

    def private_a(self): return self.__a

class SessionManagerTest(unittest.TestCase):
    def test_default(self):
        a = A()
        options : dict[str,Any] = {}
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM__A", public=True)
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM__AA", protected=True)
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM__AAA")

        self.assertEqual(a.a, "a")
        self.assertEqual(a._a, "aa") # type: ignore
        self.assertEqual(a.private_a(), "aaa") # type: ignore

    def test_options(self):
        a = A()
        options : dict[str,Any] = {"a": "b"}
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM__A", public=True)
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM__AA", protected=True)
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM__AAA")

        self.assertEqual(a.a, "b")
        self.assertEqual(a._a, "b") # type: ignore
        self.assertEqual(a.private_a(), "b") # type: ignore

    def test_env(self):
        a = A()
        options : dict[str,Any] = {}
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM_A", public=True)
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM_AA", protected=True)
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM_AAA")

        self.assertEqual(a.a, "c")
        self.assertEqual(a._a, "cc") # type: ignore
        self.assertEqual(a.private_a(), "ccc") # type: ignore

    def test_options_and_env(self):
        a = A()
        options : dict[str,Any] = {"a": "b"}
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM_A", public=True)
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM_AA", protected=True)
        set_parameter("a", ParamType.String, a, options, "TEST_PARAM_AAA")

        self.assertEqual(a.a, "b")
        self.assertEqual(a._a, "b") # type: ignore
        self.assertEqual(a.private_a(), "b") # type: ignore

    def test_missing(self):
        a = A()
        options : dict[str,Any] = {"a": "b"}
        have = False
        try:
            set_parameter("b", ParamType.String, a, options, "TEST_PARAM_A", public=True)
            have = True
        except: pass
        self.assertFalse(have)

        have = False
        try:
            set_parameter("b", ParamType.String, a, options, "TEST_PARAM_AA", protected=True)
            have = True
        except: pass
        self.assertFalse(have)

        have = False
        try:
            set_parameter("b", ParamType.String, a, options, "TEST_PARAM_AAA")
            have = True
        except: pass
        self.assertFalse(have)



