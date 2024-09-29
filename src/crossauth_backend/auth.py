# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, TypedDict, Any
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.interfaces import Key, User, UserSecretsInputFields, UserInputFields

class AuthenticationParameters(UserSecretsInputFields, total=False):
    """ Parameters needed for this this class to authenticator a user (besides username)
        An example is `password`
    """

    otp: str

class AuthenticationOptions(TypedDict, total=False):
    """
    Options to pass to the constructor.
    """

    friendly_name: str
    """ If passed, this is what will be displayed to the user when selecting
        an authentication method.
    """

class AuthenticatorCapabilities(TypedDict, total=True):
    can_create_user: bool
    can_update_user: bool
    can_update_secrets: bool

class Authenticator(ABC):
    """
    Base class for username/password authentication.

    Subclass this if you want something other than PBKDF2 password hashing.
    """

    friendly_name: str
    factor_name: str = ""

    def __init__(self, options: AuthenticationOptions = {}):
        """
        Constructor.
        :param AuthenticationOptions options:  see :class:`AuthenticationOptions`
        
        """

        if "friendly_name" not in options:
            raise CrossauthError(ErrorCode.Configuration, "Authenticator must have a friendly name")
        self.friendly_name = options["friendly_name"]

    @abstractmethod
    def skip_email_verification_on_signup(self) -> bool:
        pass

    @abstractmethod
    async def prepare_configuration(self, user: UserInputFields) -> Optional[Dict[str, Dict[str, Any]]]:
        pass

    @abstractmethod
    async def reprepare_configuration(self, username: str, session_key: Key) -> Optional[Dict[str, Dict[str, Any] | Optional[Dict[str, Any]]]]:
        pass

    @abstractmethod
    def mfa_type(self) -> str:
        pass

    @abstractmethod
    def mfa_channel(self) -> str:
        pass

    @abstractmethod
    async def authenticate_user(self, user: UserInputFields|None, secrets: UserSecretsInputFields, params: AuthenticationParameters) -> None:
        pass

    @abstractmethod
    async def create_persistent_secrets(self, 
        username: str, 
        params: AuthenticationParameters, 
        repeat_params: AuthenticationParameters|None = None) -> Dict[str, Any]:
        pass

    @abstractmethod
    async def create_one_time_secrets(self, user: User) -> Dict[str, Any]:
        pass

    @abstractmethod
    def can_create_user(self) -> bool:
        pass

    @abstractmethod
    def can_update_secrets(self) -> bool:
        pass

    @abstractmethod
    def can_update_user(self) -> bool:
        pass

    @abstractmethod
    def secret_names(self) -> List[str]:
        pass

    @abstractmethod
    def transient_secret_names(self) -> List[str]:
        pass

    @abstractmethod
    def validate_secrets(self, params: AuthenticationParameters) -> List[str]:
        pass

    def capabilities(self) -> AuthenticatorCapabilities:
        return AuthenticatorCapabilities(
            can_create_user=self.can_create_user(),
            can_update_user=self.can_update_user(),
            can_update_secrets=self.can_update_secrets()
        )

class PasswordAuthenticator(Authenticator):
    """
    base class for authenticators that validate passwords
    """

    def secret_names(self) -> List[str]:
        return ["password"]

    def transient_secret_names(self) -> List[str]:
        return []

    def mfa_type(self) -> str:
        return "none"

    def mfa_channel(self) -> str:
        return "none"

