
from typing import TypedDict, NotRequired, Callable, Dict, Any, cast
from jinja2 import Environment, FileSystemLoader
import smtplib
import ssl
import re
import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from nulltype import Null

from crossauth_backend.common.interfaces import KeyPrefix, User, UserState
from crossauth_backend.crypto import Crypto
from crossauth_backend.storage import UserStorage, KeyStorage
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j

TOKEN_LENGTH = 16; # in bytes, before base64url

class TokenEmailerOptions(TypedDict):
    """ Configuration options for TokenEmailer """

    site_url: NotRequired[str]
    """  The site url, used to create a link, eg "https://mysite.com:3000".  No default - required parameter """

    prefix: NotRequired[str]
    """  The prefix between the site url and the email verification/password reset link.  Default "/" """

    views: NotRequired[str]
    """  The directory containing views (by default, Nunjucks templates) """

    email_verification_text_body: NotRequired[str]
    """  Template file containing page for producing the text version of the email verification email body """

    email_verification_html_body: NotRequired[str]
    """  Template file containing page for producing the HTML version of the email verification email body """

    email_verification_subject: NotRequired[str]
    """  Subject for the the email verification email """

    password_reset_text_body: NotRequired[str]
    """  Template file containing page for producing the text version of the password reset email body """

    password_reset_html_body: NotRequired[str]
    """  Template file containing page for producing the HTML version of the password reset email body """

    password_reset_subject: NotRequired[str]
    """  Subject for the the password reset email """

    email_from: NotRequired[str]
    """  Sender for emails """

    smtp_host: NotRequired[str]
    """  Hostname of the SMTP server.  No default - required parameter """

    smtp_port: NotRequired[int]
    """  Port the SMTP server is running on.  Default 25 """

    smtp_use_tls: NotRequired[bool]
    """  Whether or not TLS is used by the SMTP server.  Default false """

    smtp_username: NotRequired[str]
    """  Username for connecting to SMTP servger.  Default undefined """

    smtp_password: NotRequired[str]
    """  Password for connecting to SMTP servger.  Default undefined """

    verify_email_expires: NotRequired[int]
    """  Number of seconds befire email verification tokens should expire.  Default 1 day """

    password_reset_expires: NotRequired[int]
    """  Number of seconds befire password reset tokens should expire.  Default 1 day """

    render: NotRequired[Callable[[str, Dict[str, Any]], str]]
    """  if passed, use this instead of the default nunjucks renderer """


class TokenEmailer:
    """
    Sends password reset and email verification tokens to an email address
    """
    
    def __init__(self, user_storage: UserStorage, key_storage: KeyStorage, options: TokenEmailerOptions = {}):
        """
        Construct a new EmailVerifier.
        
        This emails tokens for email verification and password reset
        
        Args:
            user_storage: where to retrieve and update user details
            key_storage: where to store email verification tokens
            options: see TokenEmailerOptions
        """
        self.user_storage = user_storage
        self.key_storage = key_storage
                
        # Set default values
        self.__views = "views"
        self.__site_url: str = ""
        self.__prefix = "/"
        self.__email_verification_text_body: str|None = "emailverificationtextbody.njk"
        self.__email_verification_html_body: str|None = None
        self.__email_verification_subject = "Please verify your email"
        self.__password_reset_text_body: str|None = "passwordresettextbody.njk"
        self.__password_reset_html_body: str|None = None
        self.__password_reset_subject = "Password reset"
        self.__email_from = ""
        self.__smtp_host = ""
        self.__smtp_port = 587
        self.__smtp_use_tls: bool = True
        self.__smtp_username: str|None = None
        self.__smtp_password: str|None = None
        self.__verify_email_expires = 60*60*24
        self.__password_reset_expires = 60*60*24
        self.__render: Callable[[str, Dict[str, Any]], str]|None = None
        
        # Set parameters using options and environment variables
        set_parameter("site_url", ParamType.String, self, options, "SITE_URL", required=True)
        set_parameter("prefix", ParamType.String, self, options, "SITE_URL")
        set_parameter("views", ParamType.String, self, options, "VIEWS")
        set_parameter("email_verification_text_body", ParamType.String, self, options, "EMAIL_VERIFICATION_TEXT_BODY")
        set_parameter("email_verification_html_body", ParamType.String, self, options, "EMAIL_VERIFICATION_HTML_BODY")
        set_parameter("email_verification_subject", ParamType.String, self, options, "EMAIL_VERIFICATION_SUBJECT")
        set_parameter("password_reset_text_body", ParamType.String, self, options, "PASSWORD_RESET_TEXT_BODY")
        set_parameter("password_reset_html_body", ParamType.String, self, options, "PASSWORD_RESET_HTML_BODY")
        set_parameter("password_reset_subject", ParamType.String, self, options, "PASSWORD_RESET_SUBJECT")
        set_parameter("email_from", ParamType.String, self, options, "EMAIL_FROM")
        set_parameter("smtp_host", ParamType.String, self, options, "SMTP_HOST")
        set_parameter("smtp_port", ParamType.Integer, self, options, "SMTP_PORT")
        set_parameter("smtp_username", ParamType.String, self, options, "SMTP_USERNAME")
        set_parameter("smtp_username", ParamType.String, self, options, "SMTP_USERNAME")
        set_parameter("smtp_password", ParamType.String, self, options, "SMTP_PASSWORD")
        set_parameter("smtp_use_tls", ParamType.Boolean, self, options, "SMTP_USE_TLS")
        set_parameter("verify_email_expires", ParamType.String, self, options, "VERIFY_EMAIL_EXPIRES")
        set_parameter("password_reset_expires", ParamType.String, self, options, "PASSWORD_RESET_EXPIRES")

        
        if "render" in options:
            self.__render = options["render"]
        else:
            self.jinja_env = Environment(loader=FileSystemLoader(self.__views), autoescape=True)

    def create_emailer(self) -> smtplib.SMTP:
        """Create SMTP emailer"""
        if self.__smtp_use_tls:
            server = smtplib.SMTP(self.__smtp_host, self.__smtp_port)
            server.starttls(context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(self.__smtp_host, self.__smtp_port)
        
        if self.__smtp_username and self.__smtp_password:
            server.login(self.__smtp_username, self.__smtp_password)
        
        return server

    @staticmethod
    def hash_email_verification_token(token: str) -> str:
        """
        Produces a hash of the given email verification token with the
        correct prefix for inserting into storage.
        """
        return KeyPrefix.email_verification_token + Crypto.hash(token)

    @staticmethod
    def hash_password_reset_token(token: str) -> str:
        """
        Produces a hash of the given password reset token with the
        correct prefix for inserting into storage.
        """
        return KeyPrefix.password_reset_token + Crypto.hash(token)

    async def create_and_save_email_verification_token(self, userid: str|int, new_email: str = "") -> str:
        """Create and save email verification token"""
        max_tries = 10
        try_num = 0
        now = datetime.datetime.now()
        expiry = datetime.datetime.fromtimestamp(now.timestamp() + self.__verify_email_expires)
        
        while try_num < max_tries:
            token = Crypto.random_value(TOKEN_LENGTH)
            hash_key = TokenEmailer.hash_email_verification_token(token)
            try:
                await self.key_storage.save_key(userid, hash_key, now, expiry, new_email)
                return token
            except:
                token = Crypto.random_value(TOKEN_LENGTH)
                hash_key = TokenEmailer.hash_email_verification_token(token)
                try_num += 1
        
        raise CrossauthError(ErrorCode.Connection, "failed creating a unique key")

    async def _send_email_verification_token(self, token: str, email: str, extra_data: Dict[str, Any]) -> str:
        """
        Separated out for unit testing/mocking purposes
        """
        msg = MIMEMultipart('alternative')
        msg['From'] = self.__email_from
        msg['To'] = email
        msg['Subject'] = self.__email_verification_subject

        data : Dict[str, Any]= {'token': token, 'siteUrl': self.__site_url, 'prefix': self.__prefix}
        if extra_data:
            data = {**data, **extra_data}
        
        if self.__email_verification_text_body:
            if self.__render:
                text_content = self.__render(self.__email_verification_text_body, data)
            else:
                template = self.jinja_env.get_template(self.__email_verification_text_body)
                text_content = template.render(**data)
            part1 = MIMEText(text_content, 'plain')
            msg.attach(part1)
        
        html_content : str = ""
        if self.__email_verification_html_body:
            if self.__render:
                html_content = self.__render(self.__email_verification_html_body, data)
            else:
                template = self.jinja_env.get_template(self.__email_verification_html_body)
                html_content = template.render(**data)
            part2 = MIMEText(html_content, 'html')
            msg.attach(part2)
        
        server = self.create_emailer()
        try:
            result = server.send_message(msg)
            return str(hash(result))  # Simple message ID implementation
        finally:
            server.quit()

    async def send_email_verification_token(self, userid: str|int, new_email: str = "", extra_data: Dict[str, Any] = {}) -> None:
        """
        Send an email verification email using the Jinja2 templates.
        
        The email address to send it to will be taken from the user's record in 
        user storage.  It will 
        first be validated, throwing a CrossauthError with ErrorCode of
        `InvalidEmail` if it is not valid.
        
        :param userid: userid to send it for
        :param new_email: if this is a token to verify email for account 
                    activation, leave this empty.
                    If it is for changing an email, this will be the field it is 
                    being changed do.
        :param extra_data: these extra variables will be passed to the Jinja2 
                    templates
        """
            
        if not self.__email_verification_text_body and not self.__email_verification_html_body:
            error = CrossauthError(ErrorCode.Configuration, 
                "Either emailVerificationTextBody or emailVerificationHtmlBody must be set to send email verification emails")
            raise error
        
        result = await self.user_storage.get_user_by_id(userid, {'skip_email_verified_check': True})
        user = result['user']
        email = new_email
        
        if email != "":
            # this message is to validate a new email (email change)
            TokenEmailer.validate_email(email)
        else:
            email = user["email"] if "email" in user else user["username"]
            if email:
                TokenEmailer.validate_email(email)
            else:
                email = getattr(user, 'username')
                TokenEmailer.validate_email(email)
        
        TokenEmailer.validate_email(email)
        token = await self.create_and_save_email_verification_token(userid, new_email)
        message_id = await self._send_email_verification_token(token, email, extra_data)
        
        CrossauthLogger.logger().info(j({'msg': "Sent email verification email", 'emailMessageId': message_id, 'email': email}))

    async def verify_email_verification_token(self, token: str) -> Dict[str, str|int]:
        """
        Validates an email verification token.
        
        The following must match:
             * expiry date in the key storage record must be less than current time
             * userid in the token must match the userid in the key storage
             * email address in user storage must match the email in the key.  If there is no email address,
               the username field is set if it is in email format.
             * expiry time in the key storage must match the expiry time in the key
        
        Looks the token up in key storage and verifies it matches and has not expired.
        
        :param token: the token to validate
            
        Retu:returns:
            the userid of the user the token is for and the email
            address the user is validating
        """
        hash_key = TokenEmailer.hash_email_verification_token(token)
        stored_token = await self.key_storage.get_key(hash_key)
        
        try:
            if "userid" not in stored_token or stored_token["userid"] == Null or "expires" not in stored_token:
                raise CrossauthError(ErrorCode.InvalidKey, "userid or expires missing from token")
            
            userid = cast(str|int, stored_token["userid"])
            expires = cast(datetime.datetime, stored_token["expires"])
            result = await self.user_storage.get_user_by_id(userid, {'skip_email_verified_check': True})
            user = result['user']
            email = (getattr(user, 'email', None) or getattr(user, 'username')).lower()
            
            if email:
                TokenEmailer.validate_email(email)
            else:
                email = getattr(user, 'username').lower()
                TokenEmailer.validate_email(email)
            
            now = datetime.datetime.now().timestamp()
            if now > expires.timestamp():
                raise CrossauthError(ErrorCode.Expired)
            
            return {'userid': userid, 'newEmail': stored_token["data"] if "data" in stored_token else ""}
        finally:
            # Commented out as in original
            # try:
            #     await self.key_storage.delete_key(hash_key)
            # except:
            #     CrossauthLogger.logger.error("Couldn't delete email verification hash " + Crypto.hash(hash_key))
            pass

    async def delete_email_verification_token(self, token: str):
        """Delete email verification token"""
        try:
            hash_key = TokenEmailer.hash_email_verification_token(token)
            await self.key_storage.delete_key(hash_key)
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({'err': ce}))

    async def create_and_save_password_reset_token(self, userid: str|int) -> str:
        """Create and save password reset token"""
        max_tries = 10
        try_num = 0
        now = datetime.datetime.now()
        expiry = datetime.datetime.fromtimestamp(now.timestamp() + self.__password_reset_expires)
        
        while try_num < max_tries:
            token = Crypto.random_value(TOKEN_LENGTH)
            hash_key = TokenEmailer.hash_password_reset_token(token)
            try:
                await self.key_storage.save_key(userid, hash_key, now, expiry)
                return token
            except:
                token = Crypto.random_value(TOKEN_LENGTH)
                hash_key = TokenEmailer.hash_password_reset_token(token)
                try_num += 1
        
        raise CrossauthError(ErrorCode.Connection, "failed creating a unique key")

    async def verify_password_reset_token(self, token: str) -> User:
        """
        Validates a password reset token
        
        The following must match:
             * expiry date in the key storage record must be less than current time
             * userid in the token must match the userid in the key storage
             * the email in the token matches either the email or username field in user storage
             * the password in user storage must match the password in the key
             * expiry time in the key storage must match the expiry time in the key
        Looks the token up in key storage and verifies it matches and has not expired.  Also verifies
        the user exists and password has not changed in the meantime.
        
        :param token: the token to validate
            
        :return
            the user that the token is for
        """
        hash_key = TokenEmailer.hash_password_reset_token(token)
        CrossauthLogger.logger().debug("verifyPasswordResetToken " + token + " " + hash_key)
        stored_token = await self.key_storage.get_key(hash_key)
        

        if "userid" not in stored_token or stored_token["userid"] == Null :
            raise CrossauthError(ErrorCode.InvalidKey, "userid not present in session key")
        if "expires" not in stored_token or stored_token["expires"] == Null :
            raise CrossauthError(ErrorCode.InvalidKey, "expires not present in session key")
        
        userid = cast(int|str, stored_token["userid"])
        expires = cast(datetime.datetime, stored_token["expires"])
        
        result = await self.user_storage.get_user_by_id(userid, {'skip_active_check': True})
        user = result['user']
        
        if (user["state"] != UserState.active and 
            user["state"] != UserState.password_reset_needed and 
            user["state"] != UserState.password_and_factor2_reset_needed):
            raise CrossauthError(ErrorCode.UserNotActive)
        
        now = datetime.datetime.now().timestamp()
        if now > expires.timestamp():
            raise CrossauthError(ErrorCode.Expired)
        
        return user

    async def _send_password_reset_token(self, token: str, email: str, extra_data: Dict[str, Any]) -> str:
        """
        Separated out for unit testing/mocking purposes
        """
        if not self.__email_verification_text_body and not self.__email_verification_html_body:
            error = CrossauthError(ErrorCode.Configuration, 
                "Either emailVerificationTextBody or emailVerificationHtmlBody must be set to send email verification emails")
            raise error

        msg = MIMEMultipart('alternative')
        msg['From'] = self.__email_from
        msg['To'] = email
        msg['Subject'] = self.__password_reset_subject

        data : Dict[str, Any] = {'token': token, 'siteUrl': self.__site_url, 'prefix': self.__prefix}
        if extra_data:
            data = {**data, **extra_data}
        
        if self.__password_reset_text_body:
            if self.__render:
                text_content = self.__render(self.__password_reset_text_body, data)
            else:
                template = self.jinja_env.get_template(self.__password_reset_text_body)
                text_content = template.render(data)
            part1 = MIMEText(text_content, 'plain')
            msg.attach(part1)
        
        if self.__password_reset_html_body:
            if self.__render:
                html_content = self.__render(self.__password_reset_html_body, data)
            else:
                template = self.jinja_env.get_template(self.__password_reset_html_body)
                html_content = template.render(data)
            part2 = MIMEText(html_content, 'html')
            msg.attach(part2)
        
        server = self.create_emailer()
        try:
            result = server.send_message(msg)
            return str(hash(result))  # Simple message ID implementation
        finally:
            server.quit()

    async def send_password_reset_token(self, userid: int|str, extra_data: Dict[str, Any] = {}, as_admin: bool = False) -> None:
        """
        Send a password reset token email using the Jinja2 templates
        
        :param userid: userid to send it for
        :param extra_data: these extra variables will be passed to the Jinja2 
                    templates
        :param as_admin: whether this is being sent by an admin
        """
            
        if not self.__password_reset_text_body and not self.__password_reset_html_body:
            error = CrossauthError(ErrorCode.Configuration, 
                "Either passwordResetTextBody or passwordResetTextBody must be set to send email verification emails")
            raise error
        
        result = await self.user_storage.get_user_by_id(userid, {'skip_active_check': True})
        user = result['user']
        
        if (not as_admin and 
            (user["state"] != UserState.active and 
             user["state"] != UserState.password_reset_needed and 
             user["state"] != UserState.password_and_factor2_reset_needed)):
            raise CrossauthError(ErrorCode.UserNotActive)
        
        email = user["email"] if "email" in user else user["username"].lower()
        TokenEmailer.validate_email(email)
        
        token = await self.create_and_save_password_reset_token(userid)
        message_id = await self._send_password_reset_token(token, email, extra_data)
        CrossauthLogger.logger().info(j({'msg': "Sent password reset email", 'emailMessageId': message_id, 'email': email}))

    @staticmethod
    def is_email_valid(email: str) -> bool:
        """
        Returns true if the given email has a valid format, false otherwise.
        
        Args:
            email: the email to validate
            
        Returns:
            true or false
        """
        # https://stackoverflow.com/questions/46155/how-can-i-validate-an-email-address-in-javascript
        pattern = r'^(([^<>()[\]\.,;:\s@"]+(\.[^<>()[\]\.,;:\s@"]+)*)|.(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$'
        return re.match(pattern, email.lower()) is not None

    @staticmethod
    def validate_email(email: str|None) -> None:
        """
        Returns if the given email has a valid format.  Throws a 
        CrossauthError with ErrorCode `InvalidEmail` otherwise.
        
        :param email: the email to validate
        """
        if email is None or not TokenEmailer.is_email_valid(email):
            raise CrossauthError(ErrorCode.InvalidEmail)

