# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.storage import KeyStorage, KeyDataEntry, UserStorage, \
    UserStorageOptions, UserStorageGetOptions, UserAndSecrets, \
    OAuthClientStorage, OAuthClientStorageOptions, \
        OAuthAuthorizationStorage, OAuthAuthorizationStorageOptions
from crossauth_backend.common.interfaces import Key, PartialKey, \
    User, UserInputFields, UserSecrets, UserSecretsInputFields, UserState, \
    PartialUser, PartialUserSecrets, \
    OAuthClient, PartialOAuthClient, \
    optional_not_equals
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j

import json
from typing import Dict, List, Optional, Union, Mapping, Any, cast
from datetime import datetime
from nulltype import Null, NullType

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

    def print(self):
        print("Key storage", self.__keys, self.__keys_by_user_id)

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
                for key in self.__keys_by_user_id[userid]:
                    new_keys : List[Key] = []
                    if (not key["value"].startswith(prefix)):
                        new_keys.append(key)
                    self.__keys_by_user_id[userid] = new_keys
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
            keyvalue = key["userid"]
            if (type(keyvalue) == NullType):
                return
            else:
                delete_from = self.__keys_by_user_id[keyvalue] # type: ignore
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

###########################
# UserStorage

class InMemoryUserStorageOptions(UserStorageOptions):
    pass

class InMemoryUserStorage(UserStorage):
    """
    Implementation of :class:`KeyStorage` where keys stored in memory.  Intended for testing.
    """

    def __init__(self, options : InMemoryUserStorageOptions = {}):
        super().__init__(options)
        self.__users_by_username: Dict[str, User] = {}
        self.__users_by_email: Dict[str, User] = {}
        self.__secrets_by_username: Dict[str, UserSecrets] = {}
        self.__secrets_by_email: Dict[str, UserSecrets] = {}

    async def get_user_by(self, field: str, value: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        field_value_normalized = UserStorage.normalize(value) if self._normalize_username else value
        users_by_field = self.__users_by_username
        secrets_by_field = self.__secrets_by_username

        if (field == "email"):
            users_by_field = self.__users_by_email
            secrets_by_field = self.__secrets_by_email

        if field_value_normalized in users_by_field:
            user = users_by_field[field_value_normalized]
            secrets = secrets_by_field[field_value_normalized]

            if (optional_not_equals(options, "skip_active_check", True) and user["state"]==UserState.password_change_needed):
                CrossauthLogger.logger().debug(j({"msg": "Password change required"}))
                raise CrossauthError(ErrorCode.PasswordChangeNeeded)
            
            if (optional_not_equals(options, "skip_active_check", True) and (user["state"]==UserState.password_reset_needed  or user["state"]==UserState.password_and_factor2_reset_needed)):
                CrossauthLogger.logger().debug(j({"msg": "Password reset required"}))
                raise CrossauthError(ErrorCode.PasswordResetNeeded)
            
            if (optional_not_equals(options, "skip_active_check", True) and user["state"]==UserState.factor2_reset_needed):
                CrossauthLogger.logger().debug(j({"msg": "2FA reset required"}))
                raise CrossauthError(ErrorCode.Factor2ResetNeeded)
            
            if (optional_not_equals(options, "skip_active_check", True) and user["state"]==UserState.awaiting_two_factor_setup):
                CrossauthLogger.logger().debug(j({"msg": "2FA setup is not complete"}))
                raise CrossauthError(ErrorCode.TwoFactorIncomplete);
            
            if (optional_not_equals(options, "skip_email_verified_check", True) and user['state'] == UserState.awaiting_email_verification):
                CrossauthLogger.logger().debug(j({"msg": "User email not verified"}))
                raise CrossauthError(ErrorCode.EmailNotVerified)
            
            if (optional_not_equals(options, "skip_active_check", True) and user['state'] == UserState.disabled):
                CrossauthLogger.logger().debug(j({"msg": "User is deactivated"}))
                raise CrossauthError(ErrorCode.UserNotActive)
            

        else:
            raise CrossauthError(ErrorCode.UserNotExist)


        return {
            "user": user,
            "secrets": secrets
        }

    async def get_user_by_username(self,
                    username: str,
                    options: UserStorageGetOptions = {}) -> UserAndSecrets:
        return await self.get_user_by("username", username, options)

    async def get_user_by_id(self,
                    id: str|int,
                    options: UserStorageGetOptions = {}) -> UserAndSecrets:
        if (type(id) == str):
            return await self.get_user_by("username", id, options)
        else:
            return await self.get_user_by("username", str(id), options)

    async def get_user_by_email(self,
                    email: str,
                    options: UserStorageGetOptions = {}) -> UserAndSecrets:
        return await self.get_user_by("email", email, options)

    async def create_user(self, 
                    user: UserInputFields, 
                    secrets: Optional[UserSecretsInputFields] = None) -> User:
        new_user : User = {
            **user,
            "id": user["username"],
        }
        if (self._normalize_username):
            new_user["username_normalized"] = UserStorage.normalize(user["username"])

        new_secrets : UserSecrets = {
            "userid": new_user["id"]
        }
        if (secrets is not None):
            new_secrets : UserSecrets = {
                **secrets,
                "userid": new_user["id"]
            }

        if (self._normalize_username and "username_normalized" in new_user and new_user["username_normalized"] in self.__users_by_username):
            raise CrossauthError(ErrorCode.UserExists)
        if (not self._normalize_username and new_user["username"] in self.__users_by_username):
            raise CrossauthError(ErrorCode.UserExists)
        
        if ("email" in new_user and self._normalize_email):
            new_user["email_normalized"] = UserStorage.normalize(new_user["email"])
            if (new_user["email_normalized"] in self.__users_by_email):
                raise CrossauthError(ErrorCode.UserExists)

        username_field = "username_normalized" if self._normalize_username else "username"
        email_field = "email_normalized" if self._normalize_email else "email"
        if (username_field not in new_user):
            raise CrossauthError(ErrorCode.Configuration, username_field + " not in user")
        self.__users_by_username[new_user[username_field]] = new_user # type: ignore
        self.__secrets_by_username[new_user[username_field]] = new_secrets # type: ignore
        if ("email" in new_user and email_field not in new_user):
            raise CrossauthError(ErrorCode.Configuration, email_field + " not in user")
        if (email_field in new_user):
            self.__users_by_email[new_user[email_field]] = new_user # type: ignore
            self.__secrets_by_email[new_user[email_field]] = new_secrets  # type: ignore
        
        return new_user


    async def delete_user_by_username(self, username: str) -> None:
        username_normalized = UserStorage.normalize(username) if self._normalize_username else username
        username_field = "username_normalized" if self._normalize_username else "username"
        email_field = "email_normalized" if self._normalize_username else "email"
        if username_normalized in self.__users_by_username:
            user = self.__users_by_username[username_normalized]
            if (username_field in user):
                email = user[email_field] # type: ignore
                del self.__users_by_email[email]
                del self.__secrets_by_email[email]
            del self.__users_by_username[username_normalized]
            del self.__secrets_by_username[username_normalized]

    async def delete_user_by_id(self, id: str|int) -> None:
        if (type(id) == str):
            await self.delete_user_by_username(id)
        else:
            await self.delete_user_by_username(str(id))

    async def get_users(self, skip: Optional[int] = None, take: Optional[int] = None) -> List[User]:
        keys : List[str] = list(self.__users_by_username.keys())
        keys.sort()
        users : List[User] = []
        if (skip is None):
            skip = 0
        last = take if (take is not None)  else len(keys)
        if (last >= len(keys)-skip):
            last = len(keys)-skip
        for i in range(skip, last):
            users.append(self.__users_by_username[keys[i]])
        

        return users
    
    async def update_user(self, user: PartialUser, secrets: Optional[PartialUserSecrets] = None) -> None:
        new_user : PartialUser = {**user}

        username_field = "username_normalized" if self._normalize_username else "username"
        if ("username" in new_user and self._normalize_username):
            new_user["username_normalized"] = UserStorage.normalize(new_user["username"])
        elif ("id" in new_user):
            id = new_user["id"]
            idstr = id if (type(id) == str) else str(id)
            if (self._normalize_username):
                new_user["username_normalized"] = UserStorage.normalize(idstr)
        if ("email" in new_user and self._normalize_email):
            new_user["email_normalized"] = UserStorage.normalize(new_user["email"])

        if (username_field in new_user and new_user[username_field] in self.__users_by_username): # type: ignore
            stored_user = self.__users_by_username[new_user[username_field]] # type: ignore
            for field in user:
                stored_user[field] = user[field]

        if (secrets is not None and username_field in new_user and new_user[username_field] in self.__secrets_by_username): # type: ignore
            stored_secrets = self.__secrets_by_username[new_user[username_field]] # type: ignore
            for field in secrets:
                stored_secrets[field] = secrets[field]

###########################
# OAuthClientStorage

class InMemoryOAuthClientStorage(OAuthClientStorage):
    """
    Implementation of :class:`KeyStorage` where keys stored in memory.  Intended for testing.
    """

    def __init__(self, options : OAuthClientStorageOptions = {}):
        super().__init__(options)
        self._clients_by_id : Dict[str, OAuthClient] = {}
        self._clients_by_name : Dict[str, List[OAuthClient]] = {}

    async def get_client_by_id(self, client_id: str) -> OAuthClient:
        return self._clients_by_id[client_id]
    
    async def get_client_by_name(self, name: str, userid: str|int|None|NullType = None) -> List[OAuthClient]:
        if (name not in self._clients_by_name):
            return []
        all_by_name = self._clients_by_name[name]
        ret : List[OAuthClient] = []
        for client in all_by_name:
            if (userid is None):
                ret.append(client)
            elif (userid == Null):
                if ("userid" in client and client["userid"] is None):
                    ret.append(client)
            else:
                if ("userid" in client and client["userid"] == userid):
                    ret.append(client)
        return ret
    
    async def get_clients(self, skip: Optional[int] = None, take: Optional[int] = None, userid: str|int|None|NullType = None) -> List[OAuthClient]:
        client_ids = list(self._clients_by_id)
        client_ids.sort()
        if skip is None:
            skip = 0
        if (take is None):
            take = 20
        ret : List[OAuthClient] = []
        skipped = 0
        matches = False
        for client_id in client_ids:
            client = self._clients_by_id[client_id]
            matches = False
            if (userid is None):
                matches = True
            elif (userid == Null and "userid" in client and client["userid"] == None):
                matches = True
            elif ("userid" in client and client["userid"] == userid):
                matches = True
            if (matches):
                if (skipped >= skip):
                    ret.append(client)
                    if (len(ret) >= take):
                        break
                else:
                    skipped += 1

        return ret

    async def create_client(self, client: OAuthClient) -> OAuthClient:
        new_client : OAuthClient = cast(OAuthClient, {
            "client_secret": None,
            "userid": None,
            **client,
        })
        self._clients_by_id[client["client_id"]] = new_client
        if (client["client_name"] not in self._clients_by_name):
            self._clients_by_name[client["client_name"]] = [new_client]
        else:
            l = self._clients_by_name[client["client_name"]]
            l.append(new_client)
        return new_client

    async def update_client(self, client: PartialOAuthClient) -> None:
        if ("client_id" not in client):
            raise CrossauthError(ErrorCode.InvalidClientId, "Must give client_id when updating client")
        existing_client = self._clients_by_id[client["client_id"]]
        for key in client.keys():
            existing_client[key] = client[key]

    async def delete_client(self, client_id: str) -> None:
        if (client_id not in self._clients_by_id):
            return
        client = self._clients_by_id[client_id]
        if (client["client_name"] in self._clients_by_name):
            client_list = self._clients_by_name[client["client_name"]]
            for i in range(len(client_list)):
                if client_list[i]["client_id"] == client_id:
                    del client_list[i]
                    break
        del self._clients_by_id[client_id]

###########################
# OAuthAuthorizationStorage

class InMemoryOAuthAuthorizationStorage(OAuthAuthorizationStorage):
    """
    Implementation of :class:`KeyStorage` where keys stored in memory.  Intended for testing.
    """

    def __init__(self, options : OAuthAuthorizationStorageOptions = {}):
        super().__init__(options)
        self._scopes_by_client_id : Dict[str, Dict[str, List[str|None]]] = {}

    async def get_authorizations(self, client_id: str, userid: str|int|None = None) -> List[Optional[str]]:
        if (client_id not in self._scopes_by_client_id):
            return []
        all_scopes = self._scopes_by_client_id[client_id]
        ret : List[str|None] = []
        if (userid is None):
            userid = ""
        else:
            userid = str(userid)
        if (userid in all_scopes):
            scopes = all_scopes[userid]
            ret = scopes

        return ret
    
    async def update_authorizations(self, client_id: str, userid: str|int|None, authorizations: List[str|None]) -> None:
        if (userid is None):
            userid = ""
        by_client_id : Dict[str, List[str|None]] = {}
        if (client_id not in self._scopes_by_client_id):            
            self._scopes_by_client_id[client_id] = by_client_id
        else:
            by_client_id = self._scopes_by_client_id[client_id]
        by_client_id[str(userid)] = authorizations
