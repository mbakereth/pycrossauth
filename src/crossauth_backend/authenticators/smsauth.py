from crossauth_backend.auth import Authenticator, AuthenticationOptions, AuthenticationParameters
from crossauth_backend.storage import KeyStorage
from crossauth_backend.common.interfaces import UserInputFields, UserSecretsInputFields, User, Key
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.logger import CrossauthLogger, j

from typing import List, Optional, Dict, Any, Callable, cast
from datetime import timedelta, datetime
import re
import secrets
from abc import abstractmethod
from jinja2 import Template

class SMSUser(UserInputFields):
    phone : str

class SmsAuthenticatorOptions(AuthenticationOptions, total=False):
    """
    Optional parameters for :class: EmailAuthenticator.

    See :func: EmailAuthenticator__init__ for details
    """

    views : str
    """ The directory containing views (by default, Jinja2 templates) """

    sms_authenticator_body: str
    """ 
    Template file containing text for producing SMS messages. Default `smsauthenticationbody.njk`
    """

    sms_authenticator_from: str
    """ Sender for SMSs """

    sms_authenticator_token_expires: int
    """ Number of seconds before otps should expire.  Default 5 minutes """

    render : Callable[[str, Dict[str,Any]], str]
    """ if passed, use this instead of the default jinja2 renderer """

class SmsAuthenticator(Authenticator):
    """
    Abstract base class for sending OTP by SMS
    """

    def __init__(self, options: SmsAuthenticatorOptions = {}):
        """
        Constructor

        :param options see :class:`crossauth_backend.SmsAuthenticatorOptions`  

        """

        super().__init__({"friendly_name": "SMS OTP", **options})

        self._views: str = "views"
        self._sms_authenticator_body: str|None = "smsauthenticationbody.njk"
        self._sms_authenticator_from : str = ""
        self._sms_authenticator_token_expires: int = 60*5
        self._render : Callable[[str, Dict[str,Any]], str]|None = None

        set_parameter("views", ParamType.String, self, options, "VIEWS", False, False, True)
        set_parameter("sms_authenticator_body", ParamType.String, self, options, "SMS_AUTHENTICATOR_BODY", False, False, True)
        set_parameter("sms_authenticator_from", ParamType.String, self, options, "SMS_AUTHENTICATOR_FROM", True, False, True)
        set_parameter("sms_authenticator_token_expires", ParamType.Integer, self, options, "SMS_AUTHENTICATOR_TOKEN_EXPIRES", False, False, True)

        if ("render" in options):
            self._render = options["render"]

    def mfa_type(self) -> str:
        """
        Used by the OAuth password_mfa grant type.
        """
        return "oob"

    def mfa_channel(self) -> str:
        """
        Used by the OAuth password_mfa grant type.
        """
        return "sms"

    @abstractmethod
    async def _send_sms(self, to: str, body: str) -> str:
        """
        Send an SMS 
        
        Args:
            to: number to send SMS to (starting with `+`)
            body: text to send
        
        Returns:
            the send message ID
        """
        pass

    async def prepare_configuration(self, user: UserInputFields) -> Optional[Dict[str, Dict[str, Any]]]:
        """
        Creates and sends the one-time code
        
        Args:
            user: the user to create it for. Uses the `phone` field which
                  is expected to be a phone number starting with `+`
        
        Returns:
            `userData` containing `username`, `phone`, `factor2`
            `sessionData` containing the same plus `otp` and `expiry` which 
             is a Unix time (number).
        """
        if not self.factor_name:
            raise CrossauthError(ErrorCode.Configuration,
                "Please set factorName on SmsAuthenticator before using")

        otp = SmsAuthenticator.zero_pad(secrets.randbelow(1000000), 6)
        if ("phone" not in user):
            raise CrossauthError(ErrorCode.InvalidPhoneNumber, "For sending SMS, phone must be present in user")
        number = cast(str, user["phone"])
        SmsAuthenticator.validate_phone(number)
        now = datetime.now()
        expiry = int((now + timedelta(seconds=self._sms_authenticator_token_expires)).timestamp() * 1000)
        
        user_data : SMSUser = {
            "username": user.get("username"),
            "phone": number,
            "factor2": self.factor_name
        }
        
        session_data = {
            "username": user.get("username"),
            "factor2": self.factor_name,
            "expiry": expiry,
            "phone": number,
            "otp": otp
        }
        
        data = {"otp": otp}
        
        body = ""
        if self._render:
            body = self._render(self._sms_authenticator_body, data)
        else:
            template = Template(self._views + "/" + self._email_authenticator_body)
            body = template.render(data)
            
        message_id = await self._send_sms(number, body)
        
        CrossauthLogger.logger().info(j({
            "msg": "Sent factor otp sms",
            "smsMessageId": message_id,
            "phone": number
        }))
        
        return {"userData": user_data, "sessionData": session_data}

    async def reprepare_configuration(self, username: str, session_key: Key) -> Optional[Dict[str, Dict[str, Any] | Optional[Dict[str, Any]]]]:
        """
        Creates and sends a new one-time code.
        
        Args:
            _username: ignored
            session_key: the session containing the previously created data.
        
        Returns:
            Dictionary containing userData, secrets, and newSessionData
        """
        if ("data" not in session_key or "2fa" not in session_key["data"]):
            raise CrossauthError(ErrorCode.InvalidKey, "2FA data not present in session")
        data = KeyStorage.decode_data(session_key["data"])["2fa"]
        otp = SmsAuthenticator.zero_pad(secrets.randbelow(1000000), 6)
        now = datetime.now()
        expiry = int((now + timedelta(seconds=self._sms_authenticator_token_expires)).timestamp() * 1000)
        
        message_id = await self._send_sms(data["phone"], otp)
        
        CrossauthLogger.logger().info(j({
            "msg": "Sent factor otp sms",
            "smsMessageId": message_id,
            "phone": data["phone"]
        }))
        
        return {
            "userData": {"phone": data["phone"], "factor2": data["factor2"], "otp": otp},
            "secrets": {},
            "newSessionData": {**data, "otp": otp, "expiry": expiry}
        }

    async def authenticate_user(self, user: UserInputFields|None, secrets: UserSecretsInputFields, params: AuthenticationParameters) -> None:
        """
        Authenticates the user by comparing the user-provided otp with the one 
        in secrets.
        
        Validation fails if the otp is incorrect or has expired.
        
        Args:
            _user: ignored
            secrets: taken from the session and should contain `otp` and `expiry`
            params: user input and should contain `otp`
            
        Raises:
            CrossauthError: with ErrorCode `InvalidToken` or `Expired`.
        """
        if params.get("otp") != secrets.get("otp"):
            raise CrossauthError(ErrorCode.InvalidToken, "Invalid code")
            
        now = int(datetime.now().timestamp() * 1000)
        if "expiry" not in secrets or now > secrets["expiry"]:
            raise CrossauthError(ErrorCode.Expired, "Token has expired")

    async def create_persistent_secrets(self, 
        username: str, 
        params: AuthenticationParameters, 
        repeat_params: AuthenticationParameters|None = None) -> Dict[str, Any]:
        """
        Does nothing for this class
        """
        return {}

    async def create_one_time_secrets(self, user: User) -> Dict[str, Any]:
        """
        Creates and sends a new one-time code.
        
        Args:
            user: the user to create it for. Uses the `phone` field which
                  should start with `+`
        
        Returns:
            `otp` and `expiry` as a Unix time (number).
        """
        otp = SmsAuthenticator.zero_pad(secrets.randbelow(1000000), 6)
        now = datetime.now()
        expiry = int((now + timedelta(seconds=self._sms_authenticator_token_expires)).timestamp() * 1000)
        
        if ("phone" not in user):
            raise CrossauthError(ErrorCode.InvalidPhoneNumber, "To send SMSs, phone must be present in user data")
        phone = user["phone"]
        message_id = await self._send_sms(phone, otp)
        
        CrossauthLogger.logger().info(j({
            "msg": "Sent factor otp sms",
            "smsMessageId": message_id,
            "phone": phone
        }))
        
        return {"otp": otp, "expiry": expiry}

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
            empty - this authenticator has no persistent secrets
        """
        return []

    def transient_secret_names(self) -> List[str]:
        """
        Returns:
            otp
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
            false - doesn't replace email verification
        """
        return False

    @staticmethod
    def is_phone_valid(number: str) -> bool:
        """
        Returns whether or not the passed phone number has a valid form.
        
        Args:
            number: the phone number to validate
            
        Returns:
            true if it is valid, false otherwise
        """
        pattern = r'^\+[1-9][0-9]{7,14}$'
        return bool(re.match(pattern, str(number)))

    @staticmethod
    def validate_phone(number: Optional[str]) -> None:
        """
        Throws an exception if a phone number doesn't have a valid form.
        
        It must start with a `+` and be 8 to 15 digits
        
        Args:
            number: the phone number to validate
            
        Raises:
            CrossauthError: with ErrorCode `InvalidPhoneNumber`.
        """
        if number is None or not SmsAuthenticator.is_phone_valid(number):
            raise CrossauthError(ErrorCode.InvalidPhoneNumber)

    @staticmethod
    def zero_pad(num: int, places: int) -> str:
        """
        Takes a number and turns it into a zero-padded string
        
        Args:
            num: number to pad
            places: total number of required digits
            
        Returns:
            zero-padded string
        """
        zero = places - len(str(num)) + 1
        return ("0" * max(0, zero - 1)) + str(num) if zero > 0 else str(num)
