# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.storage import UserStorage, \
    UserStorageOptions, UserStorageGetOptions, UserAndSecrets
from crossauth_backend.common.interfaces import User, UserInputFields, UserSecretsInputFields, UserState, \
    PartialUser, PartialUserSecrets, \
    LdapUser
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.utils import set_parameter, ParamType

from typing import Dict, List, Optional, Union, Any, cast, Callable
import ldap3
from ldap3 import Server, Connection, ALL, BASE
from ldap3.core.exceptions import LDAPInvalidCredentialsResult
import asyncio

def default_create_user_dn(user: UserInputFields, ldap_user: LdapUser) -> UserInputFields:
    
    if ("uid" not in ldap_user):
        raise CrossauthError(ErrorCode.InvalidUsername, "uid not found in ldap user record")
    uid : str = cast(str, ldap_user["uid"][0] if (type(ldap_user["uid"]) == list) else ldap_user["uid"])
    new_user : UserInputFields =  {"username": uid, "state": UserState.active, "factor1": "none", **user}
    return new_user


class LdapUserStorageOptions(UserStorageOptions, total=False):

    """
    Optional parameters for {@link LdapUserStorage}.
    """

    ldap_urls : List[str]
    """
    Utl running LDAP server. eg ldap://ldap.example.com or ldaps://ldap,example.com:1636 
    No default (required)
    """

    ldap_user_search_base : str
    """ Search base, for user queries, eg  `ou=users,dc=example,dc=com`.  Default empty """

    ldap_username_attribute : str
    """ Username attribute for searches.  Default "cn". """

    create_user_fn:  Callable[[UserInputFields, LdapUser], UserInputFields]
    """
    A function to create a user object given the entry in LDAP and additional fields.
    The additional fields might be useful for attributes that aren't in LDAP and the
    user needs to be prompted for, for example email address.
    The default function sets `username` to `uid` from `ldapUser`,
    `state` to `active` and takes every field for `user` (overriding `status`
    and `username` if present).
    """

class LdapUserWithState(LdapUser):
    state: str

class LdapUserStorage(UserStorage):
    """
    Wraps another user storage but with the authentication done in LDAP.
    
    This class still needs a user to be created in another database, with 
    for example a user id that can be referenced in key storage, and a state
    variable.
    
    An admin account is not used.  Searches are done as the user, with the user's
    password.
    """
    
    def __init__(self, local_storage: UserStorage, options: LdapUserStorageOptions = {}):
        """
        Constructor

        :param local_storage the underlying storage where users are kept (without passwords)
        :param options See :class:crossauth_backend.LdapUserStorageOptions
        """

        super().__init__()
        self._local_storage = local_storage
        self.__ldap_urls : List[str] = []
        self.__ldap_user_search_base = ""
        self.__ldap_username_attribute = "cn"
        self.__create_user_dn = default_create_user_dn

        set_parameter("ldap_urls", ParamType.JsonArray, self, options, "LDAP_URL", True)
        set_parameter("ldap_user_search_base", ParamType.String, self, options, "LDAP_USER_SEARCH_BASE")
        set_parameter("ldap_username_attribute", ParamType.String, self, options, "LDAP_USENAME_ATTRIBUTE")
        if ("create_user_dn" in options):
            self.__create_user_dn = options["create_user_dn"]

    async def get_user_by_username(self, username: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        return await self._local_storage.get_user_by_username(username, options)

    async def get_user_by_id(self, id: Union[str, int], options: UserStorageGetOptions = {}) -> UserAndSecrets:
        return await self._local_storage.get_user_by_id(id, options)

    async def get_user_by_email(self, email: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        return await self._local_storage.get_user_by_email(email, options)

    async def get_user_by(self, field: str, value: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        return await self._local_storage.get_user_by(field, value, options)

    async def create_user(self, user: UserInputFields, secrets: Optional[UserSecretsInputFields] = None) -> User:
        if (secrets is None or "password" not in secrets or secrets["password"] == ""):
            raise CrossauthError(ErrorCode.PasswordInvalid)
        ldap_user = await self.get_ldap_user(user["username"], secrets["password"])
        user = self.__create_user_dn(user, ldap_user)
        return await self._local_storage.create_user(user, {"password": "pbkdf2:sha256:32:600000:0:DISABLED:DISABLED"})

    async def update_user(self, user: PartialUser, secrets: Optional[PartialUserSecrets] = None) -> None:
        return await self._local_storage.update_user(user, None)

    async def delete_user_by_username(self, username: str) -> None:
        await self._local_storage.delete_user_by_username(username)

    async def delete_user_by_id(self, id: str|int) -> None:
        await self._local_storage.delete_user_by_id(id)

    async def get_users(self, skip: Optional[int] = None, take: Optional[int] = None) -> List[User]:
        return await self._local_storage.get_users(skip, take)

    async def get_ldap_user(self, username: str, password: str) -> LdapUser:
        """
        Gets the user from LDAP.  Does not check local storage.
        
        If the user doesn't exist or authentication fails, an exception is thrown
        :param username: the username to fetch
        :param password: the LDAP password
        :returns: the matching LdapUser
        :raises: CrossauthError with ErrorCode UsernameOrPasswordInvalid or Connection
        """
        ldap_client : Connection|None = None
        try:
            sanitized_username = LdapUserStorage.sanitize_ldap_dn_for_serach(username)
            user_dn = f"{self.__ldap_username_attribute}={sanitized_username},{self.__ldap_user_search_base}"
            if password == "":
                raise CrossauthError(ErrorCode.PasswordInvalid)
            
            CrossauthLogger.logger().debug(j({"msg": f"LDAP search {user_dn}"}))
            ldap_client = await self.ldap_bind(user_dn, password)
            return await self.search_user(ldap_client, user_dn)
              
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": str(e)}))
            ce = CrossauthError.as_crossauth_error(e)
            if isinstance(e, LDAPInvalidCredentialsResult) or "invalid credentials" in str(e).lower():
                raise CrossauthError(ErrorCode.UsernameOrPasswordInvalid)
            elif ce.code != ErrorCode.UnknownError:
                raise ce
            else:
                raise CrossauthError(ErrorCode.Connection, "LDAP error getting user")
        finally:
            if ldap_client is not None:
                ldap_client.unbind() # type: ignore

    async def ldap_bind(self, dn: str, password: str) -> Connection:
        """
        bind and return the ldap client
        from https://github.com/shaozi/ldap-authentication/blob/master/index.js
        """
        def _bind_sync():
            try:
                server = Server(cast(str, self.__ldap_urls[0] if type(self.__ldap_urls) == list else self.__ldap_urls), get_info=ALL)
                client = Connection(server, user=dn, password=password, auto_bind=True)
                return client
            except Exception as e:
                raise e
        
        # Run synchronous LDAP operation in thread pool to make it async
        loop = asyncio.get_event_loop()
        try:
            client = await loop.run_in_executor(None, _bind_sync)
            return client
        except Exception as e:
            if "invalidCredentials" in str(e) or "invalid credentials" in str(e).lower():
                raise LDAPInvalidCredentialsResult("Invalid credentials")
            raise e

    async def search_user(self, ldap_client: Connection, user_dn: str, attributes: Optional[List[str]] = None) -> LdapUser:
        """Search for user in LDAP"""
        def _search_sync():
            try:
                search_attributes = attributes if attributes else ldap3.ALL_ATTRIBUTES
                success = cast(bool, ldap_client.search( # type: ignore
                    search_base=user_dn,
                    search_filter='(objectClass=*)',
                    search_scope=BASE,
                    attributes=search_attributes
                ))
                
                if not success:
                    raise CrossauthError(ErrorCode.Connection, "LDAP connection failed")
                
                if not ldap_client.entries: # type: ignore
                    raise CrossauthError(ErrorCode.UsernameOrPasswordInvalid)
                
                # Convert the first entry to our user format
                entry = ldap_client.entries[0] # type: ignore
                user = LdapUserStorage.search_result_to_user({
                    "objectName": entry.entry_dn, # type: ignore
                    "attributes": [
                        {"type": attr, "values": entry[attr].values if hasattr(entry[attr], 'values') else [entry[attr].value]} # type: ignore
                        for attr in entry.entry_attributes_as_dict.keys() # type: ignore
                    ]
                })
                
                return user
                
            except CrossauthError:
                raise
            except Exception as e:
                raise CrossauthError(ErrorCode.Connection, f"LDAP search error: {str(e)}")
        
        # Run synchronous LDAP operation in thread pool to make it async
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _search_sync)
          
    @staticmethod
    def search_result_to_user(pojo: Dict[str, Any]) -> LdapUser:
        """Convert search result to user object"""
        user : LdapUserWithState = {
            "dn": cast(str,pojo["objectName"]),
            "state": UserState.active,
        }
        
        if "attributes" in pojo:
            for attribute in pojo["attributes"]:
                attr_type = attribute["type"]
                attr_values = attribute["values"]
                user[attr_type] = attr_values[0] if len(attr_values) == 1 else attr_values
        
        return user
      
    @staticmethod
    def sanitize_ldap_dn(dn: str) -> str:
        """
        Sanitises an LDAP dn for passing to bind (escaping special characters)
        :param dn: the dn to sanitise
        :returns: a sanitized dn
        """
        return (dn.replace("\\", "\\\\")
                 .replace(",", "\\,")
                 .replace("+", "\\+")
                 .replace('"', '\\"')
                 .replace("<", "\\<")
                 .replace(">", "\\>")
                 .replace("#", "\\#")
                 .strip())

    @staticmethod
    def sanitize_ldap_dn_for_serach(dn: str) -> str:
        """
        Sanitises an LDAP dn for passing to searches (escaping special characters)
        :param dn: the dn to sanitise
        :returns: a sanitized dn
        """
        return (LdapUserStorage.sanitize_ldap_dn(dn)
                 .replace("*", "\\*")
                 .replace("(", "\\(")
                 .replace(")", "\\)"))
