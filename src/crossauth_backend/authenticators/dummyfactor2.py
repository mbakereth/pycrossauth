from crossauth_backend.auth import PasswordAuthenticator, AuthenticationOptions, AuthenticationParameters
from crossauth_backend.storage import KeyStorage
from crossauth_backend.common.interfaces import UserInputFields, UserSecretsInputFields, User, Key
from crossauth_backend.common.error import CrossauthError, ErrorCode

from typing import List, Optional, Dict, Any
from datetime import timedelta, datetime
import time

class DummyFactor2AuthenticatorOptions(AuthenticationOptions, total=False):
    """
    Optional parameters for :class: DummyFactor2Authenticator.

    See :func: DummyFactor2Authenticator__init__ for details
    """

    pass

class DummyFactor2Authenticator(PasswordAuthenticator):
    """
    This authenticator creates fixed one-time code
    """

    @property
    def code(self):
        return self._code

    def __init__(self, code: str, options: DummyFactor2AuthenticatorOptions = {}):
        """
        Constructor

        :param code to accept as valid second factor
        :param options see :class:`crossauth_backend.DummyFactor2AuthenticatorOptions`  

        """

        super().__init__({"friendly_name": "Dummy Factor2", **options})

        self._code = code

    def skip_email_verification_on_signup(self) -> bool:
        """
        :return false 
        """
        return False
    
    async def prepare_configuration(self, user: UserInputFields) -> Optional[Dict[str, Dict[str, Any]]]:
        now = datetime.now()
        expiry = int((now.timestamp() + 60) * 1000)
        user_data = {
            "username": user["username"],
            "factor2": self.factor_name
        }
        session_data : Dict[str,str|int] = {
            "username": user["username"],
            "factor2": self.factor_name,
            "expiry": expiry,
            "otp": self.code,
        }
        return {"userData": user_data, "sessionData": session_data}


    async def reprepare_configuration(self, username: str, session_key: Key) -> Optional[Dict[str, Dict[str, Any] | Optional[Dict[str, Any]]]]:
        """
        Reprepare configuration for 2FA authentication
        
        :param username: Username (unused parameter indicated by underscore prefix)
        :param session_key: Key object containing session data
            
        :return Dictionary with user_data, secrets, and new_session_data, or None
        """

        if ("data" not in session_key):
            raise CrossauthError(ErrorCode.InvalidKey, "2FA data not found in session")
        # const data = getJsonData(sessionKey)["2fa"];
        # const data = KeyStorage.decodeData(sessionKey.data)["2fa"];
        data = KeyStorage.decode_data(session_key["data"])["2fa"]
        
        # const otp = this.code;
        otp = self.code
        
        # const now = new Date();
        now = datetime.now()
        
        # const expiry = new Date(now.getTime() + 1000*60).getTime();
        expiry = int((now + timedelta(minutes=1)).timestamp() * 1000)
        
        # return { 
        #     userData: {factor2: data.factor2, otp: otp}, 
        #     secrets: {},
        #     newSessionData: {...data, otp: otp, expiry: expiry},
        # }
        return {
            "userData": {"factor2": data["factor2"], "otp": otp},
            "secrets": {},
            "newSessionData": {**data, "otp": otp, "expiry": expiry}
        }
    
    def mfa_type(self) -> str:
        """ Returns `oob` """
        return "oob"

    def mfa_channel(self) -> str:
        """ Returns `email` """
        return "email"

    async def authenticate_user(self, user: UserInputFields|None, secrets: UserSecretsInputFields, params: AuthenticationParameters) -> None:
        """
        Authenticates the user by comparing the user-provided otp with the one 
        in secrets.
        
        Validation fails if the otp is incorrect or has expired.
        
        :param user: ignored
        :param secrets: taken from the session and should contain `otp` and 
                    `expiry`
        :param params: user input and should contain `otp`
                    
        :raise CrossauthError: with ErrorCode `InvalidToken` or `Expired`.
        """
        if ("otp" not in params or params["otp"] == "" or "otp" not in secrets or secrets["otp"] == ""):
            raise CrossauthError(ErrorCode.InvalidToken, "Missing code")
        if params["otp"] != secrets["otp"]:
            raise CrossauthError(ErrorCode.InvalidToken, "Invalid code")
        
        now = int(time.time() * 1000)  # Get current time in milliseconds
        if "expiry" not in secrets or now > secrets["expiry"]:
            raise CrossauthError(ErrorCode.Expired, "Token has expired")

    async def create_persistent_secrets(self, 
        username: str, 
        params: AuthenticationParameters, 
        repeat_params: AuthenticationParameters|None = None) -> UserSecretsInputFields:
        """ Does nothing for this class """
        return {} 

    async def create_one_time_secrets(self, user: User) -> UserSecretsInputFields:
        """
        Creates and emails a new one-time code.
        
        :param user: ignored
            
        :return Dictionary with 'otp' and 'expiry' as a Unix time (number).
        """
        otp = self.code
        now = datetime.now()
        expiry = int((now + timedelta(minutes=1)).timestamp() * 1000)
        
        return {"otp": otp, "expiry": expiry}


    def can_create_user(self) -> bool:
        """ returns false """
        return False

    def can_update_secrets(self) -> bool:
        """ returns false """
        return False

    def can_update_user(self) -> bool:
        """ returns false """
        return False

    def secret_names(self) -> List[str]:
        """ Returns emty list """
        return [] 

    def transient_secret_names(self) -> List[str]:
        """ Returns `otp`"""
        return ["otp"]
    
    def validate_secrets(self, params: AuthenticationParameters) -> List[str]:
        """ Nothing to do for this class.  Returns empty set """
        return []
