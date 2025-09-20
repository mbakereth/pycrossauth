from crossauth_backend.auth import Authenticator, AuthenticationOptions, AuthenticationParameters
from crossauth_backend.common.interfaces import UserInputFields, UserSecretsInputFields, User, Key
from crossauth_backend.common.error import CrossauthError, ErrorCode

from typing import List, Optional, Dict, Any, Literal

class OidcAuthenticatorOptions(AuthenticationOptions, total=False):
    pass

class OidcAuthenticator(Authenticator):
    """
    OIDC AUthenticator class
    """

    def __init__(self, options: OidcAuthenticatorOptions = {}):
        """
        Constructor

        :param options see :class:`crossauth_backend.EmailAuthenticatorOptions`  

        """

        super().__init__({"friendly_name": "OIDC", **options})

    def secret_names(self) -> List[str]:
        """@returns empty array"""
        return []
    
    def transient_secret_names(self) -> List[str]:
        """@returns an empty array"""
        return []
    
    def mfa_type(self) -> Literal["none", "oob", "otp"]:
        """@returns `none`"""
        return "none"
    
    def mfa_channel(self) -> Literal["none", "email", "sms"]:
        """@returns `none`"""
        return "none"
        
    async def authenticate_user(self, user: UserInputFields|None, secrets: UserSecretsInputFields, params: AuthenticationParameters) -> None:
        """
        Authenticates the user, returning a the user as a {@link User} object.
        
        If you set `extraFields` when constructing the {@link UserStorage} instance passed to the constructor,
        these will be included in the returned User object.  `hashedPassword`, if present in the User object,
        will be removed.
        
        :param user the `username` field should contain the username
        :param secrets from the `UserSecrets` table.  `password` is expected to be present
        :param params the user input.  `password` is expected to be present
        :raise :class: croassuth_backend.CrossauthError with
                :class: crossauth_backend.ErrorCode of`Connection`, 
                `UserNotExist`or `PasswordInvalid`, `TwoFactorIncomplete`,
                `EmailNotVerified` or `UserNotActive`.
        """
        raise CrossauthError(ErrorCode.PasswordInvalid, "Please use OpenID Connect to log in")
    
    async def create_persistent_secrets(self, 
        username: str, 
        params: AuthenticationParameters, 
        repeat_params: AuthenticationParameters|None = None) -> UserSecretsInputFields:
        """
        This will return p hash of the passed password.
        :param _username ignored
        :param params expected to contain `password`
        :param repeat_params if defined, this is expected to also contain 
               `password` and is checked to match the one in `params`
        :return the newly created password in the `password` field.
        """
        return {}
    
    async def create_one_time_secrets(self, user: User) -> UserSecretsInputFields:
        """
        Does nothing for this class.
        """
        return {}
    
    def can_create_user(self) -> bool:
        """
        @returns true - this class can create users
        """
        return True
    
    def can_update_user(self) -> bool:
        """
        @returns true - this class can update users
        """
        return True
    
    def can_update_secrets(self) -> bool:
        """
        @returns true - users can update secrets
        """
        return True
    
    def skip_email_verification_on_signup(self) -> bool:
        """
        @returns false, if email verification is enabled, it should be for this authenticator too
        """
        return False
    
    async def prepare_configuration(self, user: UserInputFields) -> Optional[Dict[str, Dict[str, Any]]]:
        """
        Does nothing for this class.
        """
        return None
    
    async def reprepare_configuration(self, username: str, session_key: Key) -> Optional[Dict[str, Dict[str, Any] | Optional[Dict[str, Any]]]]:
        """
        Does nothing for this class.
        """
        return None
    
    def validate_secrets(self, params: AuthenticationParameters) -> List[str]:
        """
        Does nothing for this class
        """
        return []
