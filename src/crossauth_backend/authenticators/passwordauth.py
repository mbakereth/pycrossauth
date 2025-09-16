
from crossauth_backend.auth import PasswordAuthenticator, AuthenticationOptions, AuthenticationParameters
from crossauth_backend.storage import UserStorage
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.interfaces import UserInputFields, UserSecretsInputFields, User, Key
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.crypto import Crypto, HashOptions
from crossauth_backend.common.logger import CrossauthLogger, j

from typing import List, Callable, Optional, Dict, Any
import re

def default_password_validator(params: AuthenticationParameters) -> List[str]:
    errors : List[str] = []
    if ("password" not in params):
        errors.append("Password not provided")
    else:
        password = params["password"]
        if (len(password) < 8):
            errors.append("Password must be at least 8 characters")
        if (re.match(r'.*[a-z].*', password) == None):
            errors.append("Password must contain at least one lowercase character")
        if (re.match(r'.*[A-Z].*', password) == None):
            errors.append("Password must contain at least one uppercase character")
        if (re.match(r'.*[0-9].*', password) == None):
            errors.append("Password must contain at least one digit")
    
    return errors

class LocalPasswordAuthenticatorOptions(AuthenticationOptions, total=False):
    """
    Optional parameters for :class: LocalPasswordAuthenticator.

    See :func: LocalPasswordAuthenticator__init__ for details
    """

    secret : str
    """ Application secret.  If defined, it is used as the secret in PBKDF2 to hash passwords """

    enable_secret_for_password_hash : bool
    """ If true, the `secret` will be concatenated to the salt when generating a hash for storing the password """

    pbkdf2_digest: str
    """ Digest method for PBKDF2 hasher.. Default `sha256` """

    pbkdf2_iterations : int
    """ Number of PBKDF2 iterations.  Default 600_000 """

    pbkdf2_salt_length: int
    """ Number of characters for salt, before base64-enoding.  Default 16 """

    pbkdf2_key_length: int
    """ Length the PBKDF2 key to generate, before bsae64-url encoding.  Default 32 """

    validate_password_fn: Callable[[AuthenticationParameters], List[str]]
    """
    Function that throws a {@link @crossauth/common!CrossauthError} with 
    :class:`crossauth_backend.CrossauthError` with :class:`crossauth_backend.ErrorCode`
     `PasswordFormat` if the password 
    doesn't confirm to local rules (eg number of charafters)  */
    """

class LocalPasswordAuthenticator(PasswordAuthenticator):

    NoPassword = "********"

    def __init__(self, user_storage: UserStorage, options: LocalPasswordAuthenticatorOptions = {}):
        """
        Constructor

        :param user_storage: not used by this class
        :param options see :class:`crossauth_backend.LocalPasswordAuthenticatorOptions`  

        """

        super().__init__({"friendly_name": "Local password", **options})

        self.__secret : str|None = None
        self.enable_secret_for_password_hash = False
        self.pbkdf2_digest = "sha256"
        self.pbkdf2_iterations = 600_000
        self.pbkdf2_salt_length = 16
        self.pbkdf2_key_length = 32
        self.validate_password_fn = default_password_validator
        
        set_parameter("secret", ParamType.String, self, options, "HASHER_SECRET")
        set_parameter("enable_secret_for_password_hash", ParamType.Boolean, self, options, "ENABLE_SECRET_FOR_PASSWORDS", False, True)
        set_parameter("pbkdf2_digest", ParamType.String, self, options, "PASSWORD_PBKDF2_DIGEST", False, True)
        set_parameter("pbkdf2_iterations", ParamType.String, self, options, "PASSWORD_PBKDF2_ITERATIONS", False, True)
        set_parameter("pbkdf2_salt_length", ParamType.String, self, options, "PASSWORD_PBKDF2_SALTLENGTH", False, True)
        set_parameter("pbkdf2_key_length", ParamType.String, self, options, "PASSWORD_PBKDF2_KEYLENGTH", False, True)
        if ("validate_password_fn" in options):
            self.validate_password_fn = options["validate_password_fn"]

    async def authenticate_user(self, user: UserInputFields|None, secrets: UserSecretsInputFields, params: AuthenticationParameters) -> None:
        """
        Authenticates the user, returning a the user as a {@link User} object.
        
        If you set `extraFields` when constructing the {@link UserStorage} instance passed to the constructor,
        these will be included in the returned User object.  `hashedPassword`, if present in the User object,
        will be removed.
        
        :param user the `username` field should contain the username
        :param secrets from the `UserSecrets` table.  `password` is expected to be present
        :param params the user input.  `password` is expected to be present
        :raises :class:`crossauth_backend.CrossauthError` with :class:`crossauth_backend.ErrorCode`
                of `Connection`, `UserNotExist`or `PasswordInvalid`, `TwoFactorIncomplete`,
                `EmailNotVerified` or `UserNotActive`.
        """
        if "password" not in params:
            raise CrossauthError(ErrorCode.PasswordInvalid, "Password not provided")
        if "password" not in secrets:
            raise CrossauthError(ErrorCode.PasswordInvalid)
        if "password" in params and not await Crypto.passwords_equal(params['password'], secrets['password'], self.__secret):
            username = user["username"] if user is not None else "Unknown"
            CrossauthLogger.logger().debug(j({"msg": "Invalid password hash", "user": username}))
            raise CrossauthError(ErrorCode.PasswordInvalid)
        if user is not None and user['state'] == "awaitingtwofactorsetup":
            raise CrossauthError(ErrorCode.TwoFactorIncomplete)
        if user is not None and user['state'] == "awaitingemailverification":
            raise CrossauthError(ErrorCode.EmailNotVerified)
        if user is not None and user['state'] == "deactivated":
            raise CrossauthError(ErrorCode.UserNotActive)

    def validate_secrets(self, params: AuthenticationParameters) -> List[str]:
        """
        Calls the implementor-provided `validatePasswordFn` 
        
        This function is called to apply local password policy (password length,
        uppercase/lowercase etc)
        
        :param params the password should be in `password`
            
        :return an array of errors
        """
        return self.validate_password_fn(params)

    async def create_password_hash(self, password: str, salt: Optional[str] = None, encode: bool = True) -> str:
        """
        Creates and returns a hash of the passed password, with the hashing parameters encoded ready
        for storage.
        
        If salt is not provided, a random one is created. If secret was passed to the constructor 
        or in the .env, and enableSecretInPasswords was set to true, it is used as the pepper.
        used as the pepper.
        
        :param password: the password to hash
        :param salt: the salt to use. If None, a random one will be generated.
        :param encode: fi true, a hash suitable for DB storage is created (algorithm etc prefixed to the hash)

            
        :return the encoded hash string.
        """
        
        hash_options : HashOptions = {
            'iterations': self.pbkdf2_iterations,
            'key_len': self.pbkdf2_key_length,
            'digest': self.pbkdf2_digest,
            "encode": encode,
        }
        if salt is not None: hash_options["salt"] = salt 
        if (self.enable_secret_for_password_hash and self.__secret is None):
            raise CrossauthError(ErrorCode.Configuration, "enable_secret_for_passwords is true but secret not given")
        if self.enable_secret_for_password_hash: hash_options["secret"] = self.__secret  if self.__secret is not None else ""
        return await Crypto.password_hash(password,hash_options)

    async def create_password_for_storage(self, password : str) -> str:
        """
        Just calls createPasswordHash with encode set to true
        @param password the password to hash
        @returns a string for storing in storage
        """
        return await self.create_password_hash(password)
    
    async def password_matches_hash(self, password : str, passwordHash : str, secret : Optional[str] = None):
        """
        A static version of the password hasher, provided for convenience
        
        :param password : unhashed password
        :param passwordHash : hashed password
        :param secret secret, if used when hashing passwords, or undefined if not
        :return true if match, false otherwise
        """
        if (passwordHash == LocalPasswordAuthenticator.NoPassword):
            return False
        return await Crypto.passwords_equal(password, passwordHash, secret)
    
    """
    This will return p hash of the passed password.
    
    :param username ignored
    :param params expected to contain `password`
    :param repeatParams if defined, this is expected to also contain 
           `password` and is checked to match the one in `params`
    :return the newly created password in the `password` field.
    """
    async def create_persistent_secrets(self, 
        username: str, 
        params: AuthenticationParameters, 
        repeat_params: AuthenticationParameters|None = None) -> Dict[str, Any]:

        if ("password" not in params or "password"):
            raise CrossauthError(ErrorCode.Unauthorized, "No password provided")
        if (repeat_params is not None and ("password" not in params or "password" not in repeat_params or repeat_params["password"] != params["password"])):
            raise CrossauthError(ErrorCode.PasswordMatch)
                
        return {"password": await self.create_password_hash(params["password"])}

    async def create_one_time_secrets(self, user: User) -> Dict[str, Any]:
        """ Does nothing for this class. """
        return {}
    
    def skip_email_verification_on_signup(self) -> bool:
        """ false, if email verification is enabled, it should be for this authenticator too """
        return False
    
    async def prepare_configuration(self, user: UserInputFields) -> Optional[Dict[str, Dict[str, Any]]]:
        """ Does nothing for this class """
        return None

    async def reprepare_configuration(self, username: str, session_key: Key) -> Optional[Dict[str, Dict[str, Any] | Optional[Dict[str, Any]]]]:
        """ Does nothing for this class """
        return None
    
    def can_create_user(self) -> bool:
        """ Returns true """
        return True

    def can_update_user(self) -> bool:
        """ Returns true """
        return True

    def can_update_secrets(self) -> bool:
        """ Returns true """
        return True

