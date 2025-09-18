from crossauth_backend.auth import Authenticator, AuthenticationOptions, AuthenticationParameters
from crossauth_backend.storage import KeyStorage
from crossauth_backend.common.interfaces import UserInputFields, UserSecretsInputFields, User, Key
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j

from typing import List, Optional, Dict, Any
import secrets

import base64
import pyotp
import qrcode
import io

def random_int(max_val: int) -> int:
    """Generate a random integer between 0 and max_val (inclusive)"""
    return secrets.randbelow(max_val + 1)

class TotpAuthenticator(Authenticator):
    """
    This authenticator sends a one-time code by email
    """

    def __init__(self, app_name: str, options: AuthenticationOptions = {}):
        """
        Constructor

        :param app_name this forms part of the QR code that users scan into 
               their authenticator app.  The name will appear in their app
        :param options see :class:`crossauth_backend.AuthenticationOptions`  

        """

        super().__init__({"friendly_name": "Email OTP", **options})

        self._app_name = app_name 

    def mfa_type(self) -> str:
        """
        Used by the OAuth password_mfa grant type.
        """
        return "otp"
    
    def mfa_channel(self) -> str:
        """
        Used by the OAuth password_mfa grant type.
        """
        return "none"
    
    async def _create_secret(self, username: str, secret: Optional[str] = None) -> Dict[str, str]:
        """
        Creates a TOTP secret and generates QR code URL
        
        Args:
            username: The username for the TOTP secret
            secret: Optional existing secret, if None a new one is generated
            
        Returns:
            Dictionary containing qr_url and secret
        """
        if not secret:
            secret = pyotp.random_base32()
        
        qr_url = ""
        try:
            # Create TOTP object
            totp = pyotp.TOTP(secret)
            
            # Generate provisioning URI
            provisioning_uri = totp.provisioning_uri(
                name=username,
                issuer_name=self._app_name
            )
            
            qr = qrcode.QRCode(version=1, box_size=10, border=5) 
            qr.add_data(provisioning_uri)
            qr.make(fit=True) 
            img = qr.make_image(fill_color="black", back_color="white") 
            img1 = img.get_image()
            buffered = io.BytesIO()
            img1.save(buffered, format="PNG")
            qr_url = "data:image/png;base64, " + base64.b64encode(buffered.getvalue()).decode("utf-8")
            
            #img_str = base64.b64encode(buffered.getvalue()).decode()
            #qr_url = f"data:image/png;base64,{img_str}"
            
        except Exception as err:
            CrossauthLogger.logger().debug(j({"err": str(err)}))
            raise CrossauthError(ErrorCode.UnknownError, 
                "Couldn't generate 2FA URL")
        
        return {"qr_url": qr_url, "secret": secret}
    
    async def _get_secret_from_session(
        self, 
        username: str, 
        session_key: Key
    ) -> Dict[str, str]:
        """
        Retrieves TOTP secret and other data from session
        
        Args:
            username: The username
            session_key: The session key containing TOTP data
            
        Returns:
            Dictionary containing qr_url, secret, and factor2
        """
        if ("data" not in session_key):
            raise CrossauthError(ErrorCode.InvalidKey, "No data found in session")
        data = KeyStorage.decode_data(session_key["data"])
        if data and "2fa" in data:
            data = data["2fa"]
        
        # const data = getJsonData(sessionKey);
        if "totpsecret" not in data:
            raise CrossauthError(ErrorCode.Unauthorized, 
                "TOTP data not in session")
        
        if "factor2" not in data:
            raise CrossauthError(ErrorCode.Unauthorized, 
                "TOTP factor name not in session")
        
        saved_secret = data["totpsecret"]
        secret_data = await self._create_secret(username, saved_secret)
        qr_url = secret_data["qr_url"]
        secret = secret_data["secret"]
        
        return {
            "qr_url": qr_url, 
            "secret": secret, 
            "factor2": data["factor2"]
        }
    
    async def prepare_configuration(self, user: UserInputFields) -> Optional[Dict[str, Dict[str, Any]]]:
        """
        Creates a shared secret and returns it, along with image data for the QR
        code to display.
        
        Args:
            user: the `username` is expected to be present. All other fields 
                  are ignored.
                  
        Returns:
            Dictionary containing:
            - `userData` containing `username`, `totpsecret`, `factor2` and `qr`.
            - `sessionData` containing the same except `qr`.
        """
        if not self.factor_name:
            raise CrossauthError(ErrorCode.Configuration,
                "Please set factor_name on TotpAuthenticator before using")
        
        secret_data = await self._create_secret(user["username"])
        qr_url = secret_data["qr_url"]
        secret = secret_data["secret"]
        
        userData = {
            "username": user["username"],
            "qr": qr_url,
            "totpsecret": secret,
            "factor2": self.factor_name
        }
        sessionData = {
            "username": user["username"],
            "totpsecret": secret,
            "factor2": self.factor_name
        }
        return {"userData": userData, "sessionData": sessionData}
    
    async def reprepare_configuration(
        self, 
        username: str, 
        session_key: Key
    ) -> Optional[Dict[str, Any]]:
        """
        For cases when the 2FA page was closed without completing. Returns the 
        same data as `prepare_configuration`, without generating a new secret.
        
        Args:
            username: user to return this for
            session_key: the session key, which should contain the 
                        `sessionData` from `prepare_configuration`
                        
        Returns:
            Dictionary containing:
            - `userData` containing `totpsecret`, `factor2` and `qr`.
            - `secrets` containing `totpsecret`.
            - `newSessionData` containing the same except `qr`.
        """
        sessionData = await self._get_secret_from_session(username, session_key)
        qr_url = sessionData["qr_url"]
        secret = sessionData["secret"]
        factor2 = sessionData["factor2"]
        
        return {
            "userData": {"qr": qr_url, "totpsecret": secret, "factor2": factor2},
            "secrets": {"totpsecret": secret},
            "newSessionData": None
        }
    
    async def authenticate_user(self, user: UserInputFields|None, secrets: UserSecretsInputFields, params: AuthenticationParameters) -> None:
        """
        Authenticates the user using the saved TOTP parameters and the passed 
        code.
        
        Args:
            _user: ignored
            secrets: should contain `totpsecret` that was saved in the session data
            params: should contain `otp`
        """
        if "totpsecret" not in secrets or "otp" not in params:
            raise CrossauthError(ErrorCode.InvalidToken, 
                "TOTP secret or code not given")
        
        code = params["otp"]
        secret = secrets["totpsecret"]
        
        # Verify TOTP code
        totp = pyotp.TOTP(secret)
        if not totp.verify(code):
            raise CrossauthError(ErrorCode.InvalidToken, 
                "Invalid TOTP code")
    
    async def create_persistent_secrets(self, 
        username: str, 
        params: AuthenticationParameters, 
        repeat_params: AuthenticationParameters|None = None) -> Dict[str, Any]:
        """
        Creates and returns a `totpsecret`
        
        `allow_empty_secrets` is ignored.
        
        Args:
            username: the user to create these for
            _params: ignored
            _repeat_params: ignored
            
        Returns:
            Dictionary where the `totpsecret` field will be populated.
        """
        secret_data = await self._create_secret(username)
        secret = secret_data["secret"]
        return {"totpsecret": secret}
    
    async def create_one_time_secrets(self, user: User) -> Dict[str, Any]:
        """
        Does nothing for this class
        """
        return {}
    
    def can_create_user(self) -> bool:
        """
        Returns:
            true - this class can create users
        """
        return True
    
    def can_update_user(self) -> bool:
        """
        Returns:
            true - this class can update users
        """
        return True
    
    def can_update_secrets(self) -> bool:
        """
        Returns:
            false - users cannot update secrets
        """
        return False
    
    def secret_names(self) -> List[str]:
        """
        Returns:
            List containing `totpsecret`
        """
        return ["totpsecret"]
    
    def transient_secret_names(self) -> List[str]:
        """
        Returns:
            List containing `otp`
        """
        return ["otp"]
    
    def validate_secrets(self, params: AuthenticationParameters) -> List[str]:
        """
        Does nothing for this class
        """
        return []
    
    def skip_email_verification_on_signup(self) -> bool:
        """
        Returns:
            false - if email verification is enabled, it should be used 
                   for this class
        """
        return False

