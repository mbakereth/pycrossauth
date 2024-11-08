# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.common.error import ErrorCode, CrossauthError
from abc import ABC, abstractmethod
from typing import TypedDict, List, Union, Optional, Any, Mapping, NotRequired, Dict
from datetime import datetime
import json
from nulltype import NullType
from crossauth_backend.common.interfaces import User, UserSecrets, \
    UserInputFields, PartialUser, UserSecretsInputFields, PartialUserSecrets, \
    Key, PartialKey, \
    OAuthClient
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.utils import set_parameter, ParamType

#############################
## UserStorage

class UserStorageGetOptions(TypedDict, total=False):
    """
    Passed to get methods :class: UserStorage.
    """

    skipEmailVerifiedCheck : bool
    """
    If true, a valid user will be returned even if state is set to `awaitingemailverification`
    """

    skipActiveCheck : bool
    """
    If true, a valid user will be returned even if state is not set to `active`
    """

    normalizeUsername : bool
    """
    If true, usernames will be matched as lowercase and with diacritics removed.
    Default true,
    
    Note: this doesn't apply to the ID column
    """

    normalizeEmail : bool
    """
    If true, email addresses (in the email column not in the username column) 
    will be matched as lowercase and with diacritics removed.
    Default true.
    """

class UserStorageOptions(TypedDict, total=False):
    """
    Options passed to :class: UserStorage constructor
    """

    userEditableFields : List[str]
    """
    Fields that users are allowed to edit.  Any fields passed to a create or
    update call that are not in this list will be ignored.
    """

    adminEditableFields : List[str]
    """
    Fields that admins are allowed to edit (in addition to `userEditableFields`)
    """

class UserAndSecrets(TypedDict):
    user : User
    secrets: UserSecrets

class UserStorage(ABC):
    """
    Base class for place where user details are stored.

    This class is subclassed for various types of user storage,
    e.g. PrismaUserStorage is for storing username and password in a database table,
    managed by the Prisma ORM.

    Username and email searches should be case insensitive, as should their
    unique constraints. ID searches need not be case insensitive.
    """

    @property 
    def user_editable_fields(self):
        return self._user_editable_fields
    
    @property
    def admin_editable_fields(self):
        return self._admin_editable_fields

    @property
    def normalize_username(self):
        return self._normalize_username
    
    @property
    def normalize_email(self):
        return self._normalize_email
    
    def __init__(self, options: UserStorageOptions = {}):
        """
        Constructor

        :param UserStorageOptions options: See :class:`UserStorageOptions`

        """

        self._user_editable_fields: List[str] = []
        self._admin_editable_fields: List[str] = []
        self._normalize_username: bool = True
        self._normalize_email: bool = True

        set_parameter("user_editable_fields", ParamType.String, self, options, "USER_EDITABLE_FIELDS", protected=True)
        set_parameter("admin_editable_fields", ParamType.String, self, options, "USER_EDITABLE_FIELDS", protected=True)
        set_parameter("normalize_username", ParamType.String, self, options, "USER_EDITABLE_FIELDS", protected=True)
        set_parameter("normalize_email", ParamType.String, self, options, "USER_EDITABLE_FIELDS", protected=True)

    @abstractmethod
    async def get_user_by_username(self, username: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        """
        Returns user matching the given username, or throws an exception.

        If `normalize_username` is true, the username should be matched normalized and
        lowercased (using normalize())

        :param str username: the username to return the user of
        :param UserStorageGetOptions options: optionally turn off checks. Used internally
        :raises :class:`crossauth_backend.CrossauthError`: with :class:`ErrorCode` either UserNotExist or Connection
        """
        pass

    @abstractmethod
    async def get_user_by_id(self, id: Union[str, int], options: UserStorageGetOptions = {}) -> UserAndSecrets:
        """
        Returns user matching the given user id, or throws an exception.

        Note that implementations are free to define what the user ID is. It can be a number or string,
        or can simply be `username`.

        :param str|int id: the user id to return the user of
        :param UserStorageGetOptions options: optionally turn off checks. Used internally
        :raises :class:`crossauth_backend.CrossauthError` with :class:`ErrorCode` either UserNotExist or Connection
        """
        pass

    @abstractmethod
    async def get_user_by_email(self, email: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        """
        Returns user matching the given email address, or throws an exception.

        If `normalize_email` is true, email should be matched normalized and lowercased (using normalize())
        If the email field doesn't exist, username is assumed to be the email column

        :param email: the email address to return the user of
        :param options: optionally turn off checks. Used internally
        :raises crossauth_backend.CrossauthError: with ErrorCode either UserNotExist or Connection
        """
        pass

    @abstractmethod
    async def get_user_by(self, field: str, value: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        """
        Returns user matching the given field, or throws an exception.

        This does no normalisation.  Currently it is only used for the OAuth
        client if you set user_creation_type to "merge", "embed" or "custom".

        :param str field: the field to match
        :param str value: the value to match
        :param UserStorageGetOptions options: optionally turn off checks. Used internally
        :raises :class:`crossauth_backend.CrossauthError`: with :class:`ErrorCode` either UserNotExist or Connection
        """
        pass

    async def create_user(self, user: UserInputFields, secrets: Optional[UserSecretsInputFields] = None) -> User:
        """
        Creates a user with the given details and secrets.

        :param crossauth_backend.UserInputFields user: will be put in the User table
        :param crossauth_backend.UserSecretsInputFields|None secrets: will be put in the UserSecrets table

        :return: the new user as a User object

        :raises :class:`crossauth_backend.CrossauthError` with :class:`ErrorCode` Configuration
        """
        raise CrossauthError(ErrorCode.Configuration)

    @abstractmethod
    async def update_user(self, user: PartialUser, secrets: Optional[PartialUserSecrets] = None) -> None:
        """
        Updates an existing user with the given details and secrets.

        If the given user exists in the database, update it with the passed values.
        If it doesn't exist, throw a CrossauthError with ErrorCode InvalidKey.

        :param crossauth_backend.PartialUser user: The 'id' field must be set, but all others are optional.
                     Any parameter not set (or None) will not be updated.
                     If you want to set something to None in the database, pass
                     the value as None, not undefined.
        :param crossauth_backend.PartialUserSecrets|None secrets: Optional secrets to update

        """
        pass

    @abstractmethod
    async def delete_user_by_username(self, username: str) -> None:
        """
        If the storage supports this, delete the named user from storage.

        :param str username: username to delete

        """
        pass

    @abstractmethod
    async def delete_user_by_id(self, id: str|int) -> None:
        """
        If the storage supports this, delete the user with the given ID from storage.

        :param str|int id: id of user to delete

        """
        pass

    @abstractmethod
    async def get_users(self, skip: Optional[int] = None, take: Optional[int] = None) -> List[User]:
        """
        Returns all users in the storage, in a fixed order defined by
        the storage (e.g. alphabetical by username)

        :param int|None skip: skip this number of records from the start of the set
        :param int|None take: only return at most this number of records

        :return: an array of User objects
        """
        pass

    @staticmethod
    def normalize(string: str) -> str:
        """
        By default, usernames and emails are stored in lowercase, normalized format.
        This function returns that normalization.

        :param str string: the string to normalize

        :return: the normalized string, in lowercase with diacritics removed
        """
        import unicodedata
        return ''.join(c for c in unicodedata.normalize('NFD', string) if unicodedata.category(c) != 'Mn').lower()

class KeyDataEntry(TypedDict):
    data_name : str
    value : NotRequired[Any]

###########################################
## KeyStorage

class KeyStorage(ABC):
    """
    Base class for storing session and API keys.

    This class is subclassed for various types of session key storage. For example,
    PrismaKeyStorage is for storing sessions in a database table, managed by the Prisma ORM.
    """

    @abstractmethod
    async def get_key(self, key: str) -> Key:
        """
        Returns the matching key in the session storage or raises an exception if it doesn't exist.

        :param ster key: The key to look up, as it will appear in this storage 
            (typically unsigned, hashed)

        :return: The matching Key record.
        """
        pass

    @abstractmethod
    async def save_key(self, userid: Optional[Union[str, int]], 
                       value: str, 
                       date_created: datetime, 
                       expires: Optional[datetime] = None, 
                       data: Optional[str] = None,
                       extra_fields: Optional[Mapping[str, Any]] = None) -> None:
        """
        Saves a session key in the session storage (e.g., database).

        :param int|str|None userid: The ID of the user. This matches the primary key in the 
                UserStorage implementation.
        :param str value: The key value to store.
        :param datetime date_created: The date/time the key was created.
        :param datetime|None expires: The date/time the key expires.
        :padam str|None data: An optional value, specific to the type of key, e.g., new 
                email for email change tokens
        :param Mapping[str, Any]|None extra_fields: These will also be saved in the key record

        """
        pass

    @abstractmethod
    async def update_key(self, key: PartialKey) -> None:
        """
        If the given session key exists in the database, update it with the 
        passed values. If it doesn't exist, raise a CrossauthError with 
        ErrorCode 'InvalidKey'.

        :param crossauth_backend.PartialKey key: The fields defined in this will be updated. 'id' must
                be present and it will not be updated.
        """
        pass

    @abstractmethod
    async def delete_key(self, value: str) -> None:
        """
        Deletes a key from storage (e.g., the database).

        :param str value: The key to delete

        """
        pass

    @abstractmethod
    async def delete_all_for_user(self, userid: str|int|None, 
                                  prefix: str, except_key: Optional[str] = None) -> None:
        """
        Deletes all keys from storage for the given user ID

        :param int|str|None userid: User ID to delete keys for
        :param str prefix: Only keys starting with this prefix will be deleted
        :param str|None except_key: If defined, the key with this value will not be deleted

        """
        pass

    @abstractmethod
    async def delete_matching(self, key: PartialKey) -> None:
        """
        Deletes all matching the given specs

        :param crossauth_backend.PartialKey key: Any key matching all defined values in this object will
            be deleted
        """
        pass

    @abstractmethod
    async def get_all_for_user(self, userid: str|int|None = None) -> List[Key]:
        """
        Return all keys matching the given user ID

        :param str|int|None userid: User to return keys for

        :return: List[Key]: An array of keys
        """
        pass

    @abstractmethod
    async def update_data(self, key_name: str, data_name: str, value: Any|None) -> None:
        """
        The 'data' field in a key entry is a JSON string. This method should
        atomically update a field in it.

        :param str key_name: The name of the key to update, as it appears in the table.
        :param str data_name: The field name to update. This can contain dots, e.g.,
                    'part1.part2', which means 'part2' within 'part1' is updated.
        :param Any|None value: The new value.

        """
        pass

    @abstractmethod
    async def update_many_data(self, key_name: str, 
                               data_array: List[KeyDataEntry]) -> None:
        """
        Same as 'update_data' but updates several keys.

        Ensure it is done as a single transaction.

        :param str key_name: The key to update
        :param List[crossauth_backend.KeyDataEntry data_array: dataName and value pairs

        """
        pass

    @abstractmethod
    async def delete_data(self, key_name: str, data_name: str) -> None:
        """
        The 'data' field in a key entry is a JSON string. This method should
        atomically delete a field in it.

        :param str key_name: The name of the key to update, as it appears in the table.
        :param str data_name: The field name to delete. This can contain dots, e.g.,
                    'part1.part2', which means 'part2' within 'part1' is deleted.
        """
        pass

    @staticmethod
    def decode_data(data: Optional[str]) -> Dict[str, Any]:
        """
        Returns an object decoded from the data field as a JSON string

        :param str|None data: The JSON string to decode

        :return: The parsed JSON object

        :raises json.JSONDecodeError: If data is not a valid JSON string
        """
        if data is None or data == "":
            return {}
        return json.loads(data)

    @staticmethod
    def encode_data(data: Optional[Dict[str, Any]] = None) -> str:
        """
        Returns a JSON string encoded from the given object

        :param Dict[str, Any]|None data: The object to encode

        :return: A JSON string
        """
        if not data:
            return "{}"
        return json.dumps(data)

    def _update_data_internal(self, data: Dict[str, Any], data_name: str, value: Any) -> Optional[Dict[str, Any]]:
        """
        Helper function for implementing 'update_data'

        :param Dict[str, Any] data: Parsed data string extracted from the key.
        :param str data_name: Name of field to update (may contain dots)
        :param Any value: The value to set it to

        :return: New data object if changes were made, None otherwise
        """
        if "." in data_name:
            parts = data_name.split(".")
            data1 = data
            for i in range(len(parts) - 1):
                if data1 is None:
                    break
                data1 = data1.get(parts[i])
            if data1 is not None:
                data1[parts[-1]] = value
                return data
        else:
            data[data_name] = value
            return data

    def _delete_data_internal(self, data: Dict[str, Any], data_name: str) -> bool:
        """
        Helper function for implementing 'delete_data'

        :param Dict[str, Any] data: Parsed data string extracted from the key. Results will be
                written back to this
        :param str data_name: Name of field to delete (may contain dots)

        :return: True if modifications were made, False otherwise
        """
        if "." in data_name:
            parts = data_name.split(".")
            data1 = data
            for i in range(len(parts) - 1):
                if data1 is None:
                    break
                data1 = data1.get(parts[i])
            if data1 is not None and parts[-1] in data1:
                del data1[parts[-1]]
                return True
            return False
        else:
            if data_name in data:
                del data[data_name]
                return True
            return False

####################################
## OAuthClient

class OAuthClientStorageOptions(TypedDict, total=False):
    pass

class OAuthClientStorage(ABC):
    """
    Base class for storing OAuth clients.

    This class is subclassed for various types of client storage. For example, PrismaOAuthClientStorage
    is for storing clients in a database table, managed by the Prisma ORM.
    """

    def __init__(self, options: OAuthClientStorageOptions = {}):
        """
        Constructor

        :param crossauth_backend.OAuthClientStorageOptions options: see OAuthClientStorageOptions

        """
        pass

    @abstractmethod
    async def get_client_by_id(self, client_id: str) -> OAuthClient:
        """
        Returns the matching client by its auto-generated id in the storage or
        throws an exception if it doesn't exist.

        :param str client_id: the client_id to look up

        :return: he matching OAuthClient object.
        """
        pass

    @abstractmethod
    async def get_client_by_name(self, name: str, userid: str|int|None = None) -> List[OAuthClient]:
        """
        Returns the matching client in the storage by friendly name or
        throws an exception if it doesn't exist.

        :param str name: the client name to look up
        :param str|int|None userid: if defined, only return clients belonging to this user.
            if None, return only clients with a null userid.
            if not provided, return all clients with this name.

        :return: A list of OAuthClient objects.

        :raises :class:`crossauth_backend.CrossauthError`: with :class:`ErrorCode` of 'InvalidSessionId' if a match was not found in session storage.
        """
        pass

    @abstractmethod
    async def get_clients(self, skip: Optional[int] = None, take: Optional[int] = None, userid: str|int|None = None) -> List[OAuthClient]:
        """
        Returns all clients in alphabetical order of client name.

        :param int|None skip: skip this number of records from the start in alphabetical order
        :param int|None take: return at most this number of records
        :param str|int|None userid: if defined, only return clients belonging to this user.
                if None, return only clients with a null userid.
                if not provided, return all clients.

        :return: A list of OAuthClient objects.
        """
        pass

    @abstractmethod
    async def create_client(self, client: OAuthClient) -> OAuthClient:
        """
        Creates and returns a new client with random ID and optionally secret.

        Saves in the database.

        :param crossauth_backend.OAuthClient client: the client to save.

        :return: The new client.
        """
        pass

    @abstractmethod
    async def update_client(self, client: OAuthClient) -> None:
        """
        If the given session key exists in the database, update it with the
        passed values. If it doesn't exist, throw a CrossauthError with
        'InvalidClient'.

        :param crossauth_backend.OAuthClient client: all fields to update (client_id must be set but will not be updated)

        :raises :class:`crossauth_backend.CrossauthError`: with 'InvalidClient' if the client doesn't exist.
        """
        pass

    @abstractmethod
    async def delete_client(self, client_id: str) -> None:
        """
        Deletes a key from storage.

        :param str client_id: the client to delete

        """
        pass

###########################################
## OAuthAuthorizationStorage

class OAuthAuthorizationStorageOptions(TypedDict, total=False):
    pass

from abc import ABC, abstractmethod
from typing import List, Union, Optional

class OAuthAuthorizationStorage(ABC):
    """
    Base class for storing scopes that have been authorized by a user 
    (or for client credentials, for a client).

    This class is subclassed for various types of storage. For example,
    PrismaOAuthAuthorizationStorage is for storing in a database table,
    managed by the Prisma ORM.
    """

    def __init__(self, options: OAuthAuthorizationStorageOptions = {}):
        """
        Constructor

        :param OAuthAuthorizationStorageOptions options: see :class:`OAuthAuthorizationStorageOptions`

        """
        pass

    @abstractmethod
    async def get_authorizations(self, client_id: str, userid: str|int|None = None) -> List[Optional[str]]:
        """
        Returns the matching all scopes authorized for the given client and optionally user.

        :param str client_id: the client_id to look up
        :param int|str|None userid: the userid to look up, None for a client authorization not user authorization

        :return: The authorized scopes as a list.
        """
        pass

    @abstractmethod
    async def update_authorizations(self, client_id: str, userid: str|int|NullType, authorizations: List[str|NullType]) -> None:
        """
        Saves a new set of authorizations for the given client and optionally user.

        Deletes the old ones.

        :param str client_id: the client_id to look up
        :param str|int|None userid: the userid to look up, None for a client authorization not user authorization
        :param List[str|None]authorizations: new set of authorized scopes, which may be empty

        """
        pass
