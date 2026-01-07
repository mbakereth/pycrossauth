# Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file

from crossauth_backend.auth import PasswordAuthenticator, AuthenticationOptions, AuthenticationParameters
from crossauth_backend.storageimpl.ldapstorage import LdapUserStorage
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.interfaces import UserInputFields, UserSecretsInputFields, User, UserState, Key
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j

from typing import List, Optional, Dict, Any

class LdapAuthenticatorOptions(AuthenticationOptions, total=False):
    """
    Optional parameters for :class: LdapAuthenticator.

    See :func: LdapAuthenticator__init__ for details
    """

    ldap_auto_create_account : bool
    """ 
    If true, an account will automatically be created (with factor1 taken
    from `ldap_auto_create_factor1` when a user logs in with LDAP)
    """

    ldap_auto_create_factor1 : str
    """ See :class:crossauth_backend.LdapAuthenticatorOptions """

class LdapAuthenticator(PasswordAuthenticator):


    def __init__(self, ldap_storage: LdapUserStorage, options: LdapAuthenticatorOptions = {}):
        """
        Constructor

        :param the storage that defines the LDAP server and databse for storing users locally
        :param options see :class:`crossauth_backend.LocalPasswordAuthenticatorOptions`  

        """

        super().__init__({"friendly_name": "LDAP", **options})

        self.__ldap_auto_create_account : bool = False
        self.__ldap_storage : LdapUserStorage = ldap_storage
        self.__ldap_auto_create_factor1 = "ldap"

        set_parameter("ldap_auto_create_account", ParamType.Boolean, self, options, "LDAP_AUTO_CREATE_ACCOUNT")
        set_parameter("ldap_auto_create_factor1", ParamType.String, self, options, "LDAP_AUTO_CREATE_FACTOR1")

    async def authenticate_user(self, user: UserInputFields|None, secrets: UserSecretsInputFields, params: AuthenticationParameters) -> None:
        """
        Authenticates the user, returning a the user as a {@link User} object.
        
        @param user the `username` field is required and this is used for LDAP authentication.  
                    If `ldapAutoCreateAccount` is true, these attributes as used for user creation (see {@link LdapUserStorage.createUser}).
        @param _secrets Ignored as secrets are stored in LDAP
        @param params the `password` field is expected to contain the LDAP password.
        @throws {@link @crossauth/common!CrossauthError} with {@link @crossauth/common!ErrorCode} of `Connection`, `UsernameOrPasswordInvalid`.
        """
        if ("password" not in params or params["password"] == ""):
            raise CrossauthError(ErrorCode.PasswordInvalid, "Password not provided")
        if (user is None):
            raise CrossauthError(ErrorCode.InvalidUsername, "Must provide a user")
        await self.__ldap_storage.get_ldap_user(user["username"], params["password"])
        local_user: User

        try:
            if self.__ldap_auto_create_account:
                try:
                    resp = await self.__ldap_storage.get_user_by_username(user["username"])
                    local_user = resp["user"]
                    local_user["factor1"] = self.__ldap_auto_create_factor1
                except:
                    CrossauthLogger.logger().debug(j({"msg": "Creating user", "user": user["username"]}))
                    local_user = await self.__ldap_storage.create_user(
                        {"factor1": self.__ldap_auto_create_factor1, **user}, 
                        params
                    )
            else:
                resp = await self.__ldap_storage.get_user_by_username(user["username"])
                local_user = resp["user"]
                
            if local_user["state"] == UserState.awaiting_two_factor_setup:
                raise CrossauthError(ErrorCode.TwoFactorIncomplete)
            if local_user["state"] == UserState.awaiting_email_verification:
                raise CrossauthError(ErrorCode.EmailNotVerified)
            if local_user["state"] == UserState.disabled:
                raise CrossauthError(ErrorCode.UserNotActive)
            
        except Exception as e1:
            CrossauthLogger.logger().debug(j({"err": e1}))
            raise e1

    def validate_secrets(self, params: AuthenticationParameters) -> List[str]:
        """
        Does nothing as LDAP is responsible for password format (this class doesn't create password entries)
        """
        return []

    async def create_persistent_secrets(self, 
        username: str, 
        params: AuthenticationParameters, 
        repeat_params: AuthenticationParameters|None = None) -> UserSecretsInputFields:
        """
        Does nothing in this class
        """
        return {}
    
    async def create_one_time_secrets(self, user: User) -> UserSecretsInputFields:
        """
        Does nothing in this class
        """
        return {}
    
    def can_create_user(self) -> bool:
        """
        Returns true
        """
        return True

    def can_update_secrets(self) -> bool:
        """
        Returns false
        """
        return False

    def can_update_user(self) -> bool:
        """
        Returns true
        """
        return True

    def skip_email_verification_on_signup(self) -> bool:
        """
        Returns false
        """
        return False
    
    async def prepare_configuration(self, user: UserInputFields) -> Optional[Dict[str, Dict[str, Any]]]:
        """ Nothing to do in this class """
        return None
    
    async def reprepare_configuration(self, username: str, session_key: Key) -> Optional[Dict[str, Dict[str, Any] | Optional[Dict[str, Any]]]]:
        """ Nothing to do in this class """
        return None
