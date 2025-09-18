from crossauth_backend.auth import Authenticator, AuthenticationOptions, AuthenticationParameters
from crossauth_backend.storage import KeyStorage
from crossauth_backend.common.interfaces import UserInputFields, UserSecretsInputFields, User, Key
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.logger import CrossauthLogger, j

from typing import List, Optional, Dict, Any, Callable, Literal
from datetime import timedelta, datetime
import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from jinja2 import Template
import secrets

class EmailAuthenticatorOptions(AuthenticationOptions, total=False):
    """
    Optional parameters for :class: EmailAuthenticator.

    See :func: EmailAuthenticator__init__ for details
    """

    views : str
    """ The directory containing views (by default, Jinja2 templates) """

    email_authenticator_text_bod: str
    """ 
    Template file containing page for producing the text version of the 
    email verification email body
    """

    email_authenticator_html_body: str
    """
    Template file containing page for producing the HTML version of the 
    email verification email body
    """

    email_authenticator_subject: str
    """ Subject for the the email verification email """

    email_from: str
    """ Sender for emails """

    smtp_host: str
    """ Hostname of the SMTP server.  No default - required parameter """

    smtp_port: int
    """ Port the SMTP server is running on.  Default 25 """

    smtp_use_tls: bool
    """ Whether or not TLS is used by the SMTP server.  Default false """

    smtp_username: str
    """ Username for connecting to SMTP servger.  Default undefined """

    smtp_password: str
    """ Password for connecting to SMTP servger.  Default undefined """

    email_authenticator_token_expires: int
    """ Number of seconds before otps should expire.  Default 5 minutes """

    render : Callable[[str, Dict[str,Any]], str]
    """ if passed, use this instead of the default nunjucks renderer """

def random_int(max_val: int) -> int:
    """Generate a random integer between 0 and max_val (inclusive)"""
    return secrets.randbelow(max_val + 1)

class EmailAuthenticator(Authenticator):
    """
    This authenticator sends a one-time code by email
    """

    def __init__(self, options: EmailAuthenticatorOptions = {}):
        """
        Constructor

        :param code to accept as valid second factor
        :param options see :class:`crossauth_backend.DummyFactor2AuthenticatorOptions`  

        """

        super().__init__({"friendly_name": "Email OTP", **options})

        self.__views: str = "views"
        self.__email_authenticator_text_body: str|None = "emailauthenticationtextbody.njk"
        self.__email_authenticator_html_body: str|None = None
        self.__email_authenticator_subject: str = "Login code"
        self.__email_from : str = ""
        self.__smtp_host: str = ""
        self.__smtp_port: int = 587
        self.__smtp_use_tls: bool = True
        self.__smtp_username: str|None = None
        self.__smtp_password: str|None = None
        self.__email_authenticator_token_expires: int = 60*5
        self.__render : Callable[[str, Dict[str,Any]], str]|None = None

        set_parameter("views", ParamType.String, self, options, "VIEWS")
        set_parameter("email_authenticator_text_body", ParamType.String, self, options, "EMAIL_AUTHENTICATOR_TEXT_BODY")
        set_parameter("email_authenticator_html_body", ParamType.String, self, options, "EMAIL_AUTHENTICATOR_HTML_BODY")
        set_parameter("email_authenticator_subject", ParamType.String, self, options, "EMAIL_AUTHENTICATOR_SUBJECT")
        set_parameter("email_from", ParamType.String, self, options, "EMAIL_FROM", True)
        set_parameter("smtp_host", ParamType.String, self, options, "SMTP_HOST", True)
        set_parameter("smtp_port", ParamType.Integer, self, options, "SMTP_PORT")
        set_parameter("smtp_username", ParamType.String, self, options, "SMTP_USERNAME")
        set_parameter("smtp_password", ParamType.String, self, options, "SMTP_PASSWORD")
        set_parameter("smtp_use_tls", ParamType.Boolean, self, options, "SMTP_USE_TLS")
        set_parameter("email_authenticator_token_expires", ParamType.Integer, self, options, "EMAIL_AUTHENTICATOR_TOKEN_EXPIRES")

        if ("render" in options):
            self.__render = options["render"]

    def mfa_type(self) -> Literal["none", "oob", "otp"]:
        """Used by the OAuth password_mfa grant type."""
        return "oob"

    def mfa_channel(self) -> Literal["none", "email", "sms"]:
        """Used by the OAuth password_mfa grant type."""
        return "email"

    def _create_emailer(self) -> smtplib.SMTP:
        """Create SMTP connection for sending emails"""
        if self.__smtp_use_tls:
            server = smtplib.SMTP_SSL(self.__smtp_host, self.__smtp_port)
        else:
            server = smtplib.SMTP(self.__smtp_host, self.__smtp_port)
            
        if self.__smtp_username is not None and self.__smtp_password is not None and self.__smtp_username != "" and self.__smtp_password != "":
            server.login(self.__smtp_username, self.__smtp_password)
            
        return server

    async def _send_token(self, to: str, otp: str) -> str:
        """Send OTP token via email"""
        EmailAuthenticator.validate_email(to)
        
        msg = MIMEMultipart('alternative')
        msg['From'] = self.__email_from
        msg['To'] = to
        msg['Subject'] = self.__email_authenticator_subject
        
        data = {"otp": otp}
        
        if self.__email_authenticator_text_body is not None and self.__email_authenticator_text_body != "":
            if self.__render:
                text_body = self.__render(self.__views + "/" + self.__email_authenticator_text_body, data)
            else:
                template = Template(self.__views + "/" + self.__email_authenticator_text_body)
                text_body = template.render(data)
            
            text_part = MIMEText(text_body, 'plain')
            msg.attach(text_part)
            
        if self.__email_authenticator_html_body is not None and self.__email_authenticator_html_body != "":
            if self.__render is not None:
                html_body = self.__render(self.__views + "/" + self.__email_authenticator_html_body, data)
            else:
                template = Template(self.__views + "/" + self.__email_authenticator_html_body)
                html_body = template.render(data)
            
            html_part = MIMEText(html_body, 'html')
            msg.attach(html_part)
        
        server = self._create_emailer()
        try:
            server.sendmail(self.__email_from, to, msg.as_string())
            # Generate a message ID similar to nodemailer
            message_id = f"<{secrets.token_hex(16)}@{self.__smtp_host}>"
            return message_id
        finally:
            server.quit()

    async def prepare_configuration(self, user: UserInputFields) -> Optional[Dict[str, Dict[str, Any]]]:
        """
        Creates and emails the one-time code
        @param user the user to create it for.  Uses the `email` field if 
                   present, `username` otherwise (which in this case is 
                   expected to contain an email address)
         :return `userData` containing `username`, `email`, `factor2`
                `sessionData` containing the same plus `otp` and `expiry` which 
                 is a Unix time (number).
        """
        if not self.factor_name:
            raise CrossauthError(ErrorCode.Configuration,
                "Please set factorName on EmailAuthenticator before using")

        otp = EmailAuthenticator.zero_pad(random_int(999999), 6)
        email = user["email"] if "email" in user else  user["username"]
        EmailAuthenticator.validate_email(email)
        now = datetime.now()
        expiry = int((now + timedelta(seconds=self.__email_authenticator_token_expires)).timestamp() * 1000)
        
        user_data = {
            "username": user["username"],
            "email": email,
            "factor2": self.factor_name
        }
        
        session_data : Dict[str,int|str] = {
            "username": user["username"],
            "factor2": self.factor_name,
            "expiry": expiry,
            "email": email,
            "otp": otp,
        }
        
        message_id = await self._send_token(email, otp)
        CrossauthLogger.logger().info(j({
            "msg": "Sent factor otp email",
            "emailMessageId": message_id,
            "email": email
        }))
        
        return {"userData": user_data, "sessionData": session_data}

    async def reprepare_configuration(self, username: str, session_key: Key) -> Optional[Dict[str, Dict[str, Any] | Optional[Dict[str, Any]]]]:
        """
        Creates and emails a new one-time code.
        :param _username ignored
        :param sessionKey the session containing the previously created data.
        :return dict 
        """
        if ("data" not in session_key):
            raise CrossauthError(ErrorCode.InvalidKey, "2FA not found in session")
        data = KeyStorage.decode_data(session_key["data"])["2fa"]
        otp = EmailAuthenticator.zero_pad(random_int(999999), 6)
        now = datetime.now()
        expiry = int((now + timedelta(seconds=self.__email_authenticator_token_expires)).timestamp() * 1000)
        
        message_id = await self._send_token(data["email"], otp)
        CrossauthLogger.logger().info(j({
            "msg": "Sent factor otp email",
            "emailMessageId": message_id,
            "email": data["email"]
        }))
        
        return {
            "userData": {"email": data["email"], "factor2": data["factor2"], "otp": otp},
            "secrets": {},
            "newSessionData": {**data, "otp": otp, "expiry": expiry}
        }

    async def authenticate_user(self, user: UserInputFields|None, secrets: UserSecretsInputFields, params: AuthenticationParameters) -> None:
        """
        Authenticates the user by comparing the user-provided otp with the one 
        in secrets.
        
        Validation fails if the otp is incorrect or has expired.
        
        :param _user ignored
        :param secrets taken from the session and should contain `otp` and 
                      `expiry`
        :param params user input and should contain `otp`
        :raise CrossauthError with ErrorCode `InvalidToken` or `Expired`.
        """

        if "otp" not in params or "otp" not in secrets:
            raise CrossauthError(ErrorCode.InvalidToken, "Code not given or stored")
        if params["otp"] != secrets["otp"]:
            raise CrossauthError(ErrorCode.InvalidToken, "Invalid code")
        
        now = int(datetime.now().timestamp() * 1000)
        if "expiry" not in secrets or now > secrets["expiry"]:
            raise CrossauthError(ErrorCode.Expired, "Token has expired")

    async def create_persistent_secrets(self, 
        username: str, 
        params: AuthenticationParameters, 
        repeat_params: AuthenticationParameters|None = None) -> Dict[str, Any]:
        """Does nothing for this class"""
        return {}

    async def create_one_time_secrets(self, user: User) -> Dict[str, Any]:
        """
        Creates and emails a new one-time code.
        @param user the user to create it for.  Uses the `email` field if 
                   present, `username` otherwise (which in this case is 
                   expected to contain an email address)
         :return `otp` and `expiry` as a Unix time (number).
        """
        otp = EmailAuthenticator.zero_pad(random_int(999999), 6)
        now = datetime.now()
        expiry = int((now + timedelta(seconds=self.__email_authenticator_token_expires)).timestamp() * 1000)
        
        email = user["email"] if "email" in user else user["username"]
        message_id = await self._send_token(email, otp)
        CrossauthLogger.logger().info(j({
            "msg": "Sent factor otp email",
            "emailMessageId": message_id,
            "email": email
        }))
        
        return {"otp": otp, "expiry": expiry}

    def can_create_user(self) -> bool:
        """ :return true - this class can create users"""
        return True

    def can_update_user(self) -> bool:
        """ :return true - this class can update users"""
        return True

    def can_update_secrets(self) -> bool:
        """ :return false - users cannot update secrets"""
        return False

    def secret_names(self) -> List[str]:
        """ :return empty - this authenticator has no persistent secrets"""
        return []

    def transient_secret_names(self) -> List[str]:
        """ :return otp"""
        return ["otp"]

    def validate_secrets(self, params: AuthenticationParameters) -> List[str]:
        """Does nothing for this class"""
        return []

    def skip_email_verification_on_signup(self) -> bool:
        """
         :return true - as a code is sent to the registers email address, no 
                additional email verification is needed
        """
        return True

    @staticmethod
    def is_email_valid(email: str) -> bool:
        """
        Returns whether or not the passed email has a valid form.
        @param email the email address to validate
         :return true if it is valid. false otherwise
        """
        # https://stackoverflow.com/questions/46155/how-can-i-validate-an-email-address-in-javascript
        email = str(email).lower()
        pattern = r'^(([^<>()[\]\.,;:\s@"]+(\.[^<>()[\]\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$'
        return re.match(pattern, email) is not None

    @staticmethod
    def validate_email(email: Optional[str]) -> None:
        """
        Throws an exception if an email address doesn't have a valid form.
        @param email the email address to validate
        @throws CrossauthError with ErrorCode `InvalidEmail`.
        """
        if email is None or not EmailAuthenticator.is_email_valid(email):
            raise CrossauthError(ErrorCode.InvalidEmail)

    @staticmethod
    def zero_pad(num: int, places: int) -> str:
        """
        Takes a number and turns it into a zero-padded string
        @param num number to pad
        @param places total number of required digits
         :return zero-padded string
        """
        zero = places - len(str(num)) + 1
        return "0" * max(0, zero - 1) + str(num) if zero > 0 else str(num)
