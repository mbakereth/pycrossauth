# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import unittest
from src.crossauth_backend import MapGetter
from typing import TypedDict, Required


class TestDict(TypedDict, total = False):
    a: Required[str]
    b: str
    c: int

class TypedDictTest(unittest.TestCase):

    def test_mapgetter(self):

        my_dict1 : TestDict = {
            "a": "a",
        }

        my_dict2 : TestDict = {
            "a": "a",
            "b": "b",
            "c": 1
        }

        self.assertIs(MapGetter[str].get_or_none(my_dict1, "a"), "a")
        self.assertIsNone(MapGetter[str].get_or_none(my_dict1, "b"))
        self.assertIs(MapGetter[str].get(my_dict1, "b", "x"), "x")
        self.assertIs(MapGetter[str].get(my_dict2, "b", "x"), "b")
        self.assertIs(MapGetter[str].get_or_none(my_dict2, "b"), "b")
