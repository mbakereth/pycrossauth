# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.storage import KeyStorage, KeyDataEntry
from crossauth_backend.common.interfaces import Key, PartialKey
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j

import json
from typing import Dict, List, Optional, Union, Mapping, Any
from datetime import datetime
from nulltype import Null

###########################
# KeyStorage

class InMemoryKeyStorage(KeyStorage):
    """
    Implementation of :class:`KeyStorage` where keys stored in memory.  Intended for testing.
    """

    def __init__(self):
        super().__init__()
        self.__keys: Dict[str, Key] = {}
        self.__keys_by_user_id: Dict[str|int, List[Key]] = {}
        self.__non_user_keys: List[Key] = []

    async def get_key(self, key: str) -> Key:
        if key in self.__keys:
            return self.__keys[key]
        CrossauthLogger.logger().debug(j({"msg": "Key does not exist in key storage"}))
        err = CrossauthError(ErrorCode.InvalidKey)
        CrossauthLogger.logger().debug(j({"err": str(err)}))
        raise err

    async def save_key(self, userid: Optional[Union[str, int]], 
                       value: str, 
                       date_created: datetime, 
                       expires: Optional[datetime] = None, 
                       data: Optional[str] = None,
                       extra_fields: Optional[Mapping[str, Any]] = None) -> None:
        key : Key = {
            "value" : value,
            "created": date_created,
            "expires": expires or Null,
        }
        if (userid is not None): key["userid"] = userid
        if (data is not None): key["data"] = data
        if (extra_fields is not None):
            for name in extra_fields:
                if (name in Key.__annotations__):
                    key[name] = extra_fields[name]

        self.__keys[value] = key
        if userid is not None:
            if userid not in self.__keys_by_user_id:
                self.__keys_by_user_id[userid] = [key]
            else:
                self.__keys_by_user_id[userid].append(key)
        else:
            self.__non_user_keys.append(key)

    async def delete_key(self, value: str) -> None:
        if value in self.__keys:
            key = self.__keys[value]
            if "userid" in key:
                userid = key["userid"]
                if (userid != Null):
                    del self.__keys_by_user_id[userid] # type: ignore
            else:
                self.__non_user_keys = [v for v in self.__non_user_keys if v["value"] != value]
            del self.__keys[value]

    async def delete_all_for_user(self, userid: str|int|None, 
                                  prefix: str, except_key: Optional[str] = None) -> None:
        self.__keys = {k: v for k, v in self.__keys.items()
                     if ("userid" in v and v["userid"] != userid) or (except_key and k == except_key) or not k.startswith(prefix)}
        if userid:
            if userid in self.__keys_by_user_id:
                del self.__keys_by_user_id[userid]
        else:
            self.__non_user_keys = []

    async def get_all_for_user(self, userid: str|int|None = None) -> List[Key]:
        if not userid:
            return self.__non_user_keys
        return self.__keys_by_user_id.get(userid, [])

    async def delete_matching(self, key: PartialKey) -> None:
        delete_from : List[Key] = self.__non_user_keys
        if ("userid" in key and key["userid"] != None):
            if (key["userid"] not in self.__keys_by_user_id): return
            delete_from = self.__keys_by_user_id[key["userid"]]
        matches : list[Key] = []
        for entry in delete_from:
            is_a_match = True
            for field, value in key.items():
                if (field not in entry or entry[field] != value):
                    is_a_match = False
            if (is_a_match): matches.append(entry)
        for match in matches:
            delete_from.remove(match)
            del self.__keys[match["value"]]

    async def update_key(self, key: PartialKey) -> None:
        if 'value' in key and key['value'] in self.__keys:
            for field, value in key.items():
                setattr(self.__keys[key['value']], field, value)

    async def update_data(self, key_name: str, data_name: str, value: Any|None) -> None:
        await self.update_many_data(key_name, [{"data_name": data_name, "value": value}])

    async def update_many_data(self, key_name: str, 
                               data_array: List[KeyDataEntry]) -> None:
        key = await self.get_key(key_name)
        data : Dict[str, Any] = {}
        if ("data" in key and key["data"] != ""):
            data = json.loads(key["data"])
        for item in data_array:
            if ("value" in item):
                if self._update_data_internal(data, item["data_name"], item["value"]):
                    key["data"] = json.dumps(data)
                else:
                    raise CrossauthError(ErrorCode.BadRequest, f"parents of {item['data_name']} not found in key data")
            else:
                self._delete_data_internal(data, item["data_name"])

    async def delete_data(self, key_name: str, data_name: str) -> None:
        key = await self.get_key(key_name)
        if "data" not in key or key["data"] == "":
            return
        data = json.loads(key["data"])
        if self._delete_data_internal(data, data_name):
            key["data"] = json.dumps(data)
