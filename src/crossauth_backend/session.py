from crossauth_backend.storage import UserStorage, KeyStorage, KeyDataEntry
from crossauth_backend.cookieauth import DoubleSubmitCsrfTokenOptions, DoubleSubmitCsrfToken
from crossauth_backend.cookieauth import SessionCookieOptions, SessionCookie, Cookie
from crossauth_backend.crypto import Crypto
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.common.interfaces import User, UserSecrets
from crossauth_backend.auth import Authenticator, AuthenticationParameters
from typing import TypedDict, List, Mapping, NamedTuple, Any, Dict
from datetime import datetime
import json

class SessionManagerOptions(TypedDict, total=False):
    """
    Options for SessionManager
    """

    user_storage: UserStorage
    """
    If user login is enabled, you must provide the object where users
    are stored.
    """

    double_submit_cookie_options : DoubleSubmitCsrfTokenOptions
    """Options for csrf cookie manager"""

    session_cookie_options : SessionCookieOptions
    """options for session cookie manager """

    enable_email_verification : bool
    """
    If true, users will have to verify their email address before account is created or when changing their email address.
    See class description for details. Default True
    """

    enable_password_reset : bool
    """
    If true, allow password reset by email token.
    See class description for details. Default True
    """

    secret : str
    """Server secret. Needed for emailing tokens and for csrf tokens"""

    email_token_storage : KeyStorage
    """
    Store for password reset and email verification tokens. If not passed, the same store as
    for sessions is used.
    """

    site_url : str
    """
    Base URL for the site.
    
    This is used when constructing URLs, eg for sending password reset
    tokens.
    """

    allowed_factor2 : List[str]
    """
    Set of 2FA factor names a user is allowed to set.
    
    The name corresponds to the key you give when adding authenticators.
    See `authenticators` in SessionManager.constructor.
    """
class AnonymousSession(NamedTuple):
    session_cookie: Cookie
    csrf_cookie: Cookie
    csrf_form_or_header_value: str

class Csrf(NamedTuple):
    csrf_cookie: Cookie
    csrf_form_or_header_value: str

class SessionManager:
    """
    Class for managing sessions.
    """

    @property
    def user_storage(self):
        return self._user_storage

    @property
    def key_storage(self):
        return self._key_storage

    @property
    def email_token_storage(self):
        return self._email_token_storage
    
    @property
    def csrf_tokens(self):
        return self._csrf_tokens

    @property
    def session(self):
        return self._session

    @property
    def authenticators(self):
        return self._authenticators

    @property
    def allowed_factor2(self):
        return self._allowed_factor2

    def __init__(self, key_storage : KeyStorage, authenticators : Mapping[str, Authenticator] , options : SessionManagerOptions = {}):
        """
        Constructor
        :param crossauth_backend.KeyStorage key_storage:  the :class:`KeyStorage` instance to use, eg :class:`PrismaKeyStorage`.
        :param Mapping[str, Authenticator] authenticators: authenticators used to validate users, eg :class:`LocalPasswordAuthenticatorOptions`.
        :param SessionManagerOptions options: optional parameters for authentication. See :class:`SessionManagerOptions`.

        """
        self._user_storage = options.get('userStorage', None)
        self._key_storage = key_storage
        self._email_token_storage : KeyStorage | None = None
        self._authenticators = authenticators
        for authentication_name in self._authenticators:
            self._authenticators[authentication_name].factor_name = authentication_name

        soptions : SessionCookieOptions = {}
        if "secret" in options:
            soptions["secret"] = options["secret"]
        if ("session_cookie_options" in options):
            soptions = {**soptions, **options["session_cookie_options"]}
        self._session = SessionCookie(self._key_storage, soptions)
        coptions : DoubleSubmitCsrfTokenOptions = {}
        if "secret" in options:
            coptions["secret"] = options["secret"]
        if ("double_submit_cookie_options" in options):
            coptions = {**coptions, **options["double_submit_cookie_options"]}
        self._csrf_tokens = DoubleSubmitCsrfToken(coptions)

        self._allowed_factor2 : List[str] = []
        self.__enable_email_verification : bool = False
        self.__enable_password_reset : bool = False
        self.__token_emailer = None

        set_parameter("allowed_factor2", ParamType.JsonArray, self, options, "ALLOWED_FACTOR2", protected=True)
        set_parameter("enable_email_verification", ParamType.Boolean, self, options, "ENABLE_EMAIL_VERIFICATION")
        set_parameter("enable_password_reset", ParamType.Boolean, self, options, "ENABLE_PASSWORD_RESET")
        self._email_token_storage = self._key_storage
        if self._user_storage and (self.__enable_email_verification or self.__enable_password_reset):
            raise CrossauthError(ErrorCode.NotImplemented, "email verification is not supported in this version")

    async def login(self, username : str, params : AuthenticationParameters, extra_fields : Mapping[str,Any]|None=None, persist : bool=False, user : User|None=None, bypass_2fa : bool=False):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "login not implemented in this version")
    
    async def create_anonymous_session(self, extra_fields: Mapping[str,Any]|None=None) -> AnonymousSession:
        if extra_fields is None:
            extra_fields = {}
        key = await self._session.create_session_key(None, extra_fields)
        session_cookie = self._session.make_cookie(key, False)
        csrf_data = await self.create_csrf_token()
        return AnonymousSession(session_cookie, csrf_data.csrf_cookie, csrf_data.csrf_form_or_header_value)
        

    async def logout(self, session_id : str):
        """ Not implemented """
        key = await self._session.get_session_key(session_id)
        return await self._key_storage.delete_key(SessionCookie.hash_session_id(key["value"]))

    async def logout_from_all(self, userid : str|int, except_id : str|None=None):
        """ Not implemented """
        return await self._session.delete_all_for_user(userid, except_id)

    async def user_for_session_id(self, session_id : str):
        """ Not implemented """
        return await self._session.get_user_for_session_id(session_id)

    async def data_string_for_session_id(self, session_id : str) -> str|None:
        """
        Returns the data object for a session key, or undefined, as a JSON string 
        (which is how it is stored in the session table)
        
        If the user is undefined, or the key has expired, returns undefined.
        
        :param str session_id: the session id to look up in session storage

        :return: a string from the data field

        :raise :class:`crossauth_backend.CrossauthError`: with 
            :class:`ErrorCode` of `Connection`,  `InvalidSessionId`
            `UserNotExist` or `Expired`.
        """
        try:
            key_data = await self._session.get_user_for_session_id(session_id)
            return key_data.key["data"] if "data" in key_data.key else None
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            if ce.code == ErrorCode.Expired:
                return None
            raise ce

    async def data_for_session_id(self, session_id : str) -> Dict[str,Any]|None:
        """
        Returns the data object for a session id, or undefined, as an object.
        
        If the user is undefined, or the key has expired, returns undefined.
        
        :param str session_id: the session key to look up in session storage

        :return: a string from the data field

        :raise :class:`crossauth_backend.CrossauthError`: with 
            :class:`ErrorCode` of `Connection`,  `InvalidSessionId`
            `UserNotExist` or `Expired`.
        """
        str_data = await self.data_string_for_session_id(session_id)
        if not str_data:
            return None
        return json.loads(str_data)

    async def create_csrf_token(self) -> Csrf:
        """
        Creates and returns a signed CSRF token based on the session ID

        :return: a CSRF cookie and value to put in the form or CSRF header
        """
        csrf_token = self._csrf_tokens.create_csrf_token()
        csrf_form_or_header_value = self._csrf_tokens.make_csrf_form_or_header_token(csrf_token)
        csrf_cookie = self._csrf_tokens.make_csrf_cookie(csrf_token)
        return Csrf(csrf_cookie,csrf_form_or_header_value)

    async def create_csrf_form_or_header_value(self, csrf_cookie_value: str):
        """
        Validates the signature on the CSRF cookie value and returns a
        value that can be put in the form or CSRF header value.
        
        :param str csrf_cookie_value: the value from the CSRF cookie

        :return: the value to put in the form or CSRF header
        """
        csrf_token = self._csrf_tokens.unsign_cookie(csrf_cookie_value)
        return self._csrf_tokens.make_csrf_form_or_header_token(csrf_token)

    def get_session_id(self, session_cookie_value: str):
        """
        Returns the session ID from the signed session cookie value
        
        :param str session_cookie_value: value from the session ID cookie

        :return: the usigned cookie value.

        :raises :class:`crossauth_backend.CrossauthError` with `InvalidKey`
            if the signature is invalid.
        """
        return self._session.unsign_cookie(session_cookie_value)

    def validate_double_submit_csrf_token(self, csrf_cookie_value : str, csrf_form_or_header_value: str):
        """
        Throws :class:`crossauth_backend.CrossauthError` with 
        `InvalidKey` if the passed CSRF token is not valid for the given
        session ID.  Otherwise returns without error
        
        :param strcsrf_cookie_value: the CSRF cookie value
        :param str csrf_form_or_header_value: the value from the form field or
               CSRF header
        """
        if not csrf_cookie_value or not csrf_form_or_header_value:
            raise CrossauthError(ErrorCode.InvalidCsrf, "CSRF missing from either cookie or form/header value")
        self._csrf_tokens.validate_double_submit_csrf_token(csrf_cookie_value, csrf_form_or_header_value)

    def validate_csrf_cookie(self, csrf_cookie_value : str):
        """
        Throws :class:`crossauth_backend.CrossauthError` with `InvalidKey` if 
        the passed CSRF cookie value is not valid (ie invalid signature)
        :param str csrf_cookie_value: the CSRF cookie value 

        """
        self._csrf_tokens.validate_csrf_cookie(csrf_cookie_value)

    async def update_session_activity(self, session_id : str):
        """
        If session_idle_timeout is set, update the last activcity time in key 
        storage to current time.
        
        :param str session_id: the session Id to update.

        """
        key_data = await self._session.get_session_key(session_id)
        if self._session.idle_timeout > 0:
            await self._session.update_session_key({
                'value': key_data['value'],
                'lastactive': datetime.now(),
            })

    async def update_session_data(self, session_id: str, name: str, value: Mapping[str, Any]) -> None:
        """
        Update a field in the session data.
        
        The `data` field in the session entry is assumed to be a JSON string.
        The field with the given name is updated or set if not already set.
        :param str session_id: the session Id to update.
        :param str name: of the field.
        :param Mapping[str, Any] value: new value to store

        """
        hashed_session_key = self._session.hash_session_id(session_id)
        CrossauthLogger.logger().debug(j({"msg": f"Updating session data value{name}", "hashedSessionCookie": Crypto.hash(session_id)}))
        await self._key_storage.update_data(hashed_session_key, name, value)

    async def update_many_session_data(self, session_id: str, data_array: List[KeyDataEntry]) -> None:
        """
        Update field sin the session data.
        
        The `data` field in the session entry is assumed to be a JSON string.
        The field with the given name is updated or set if not already set.
        :param str session_id: the session Id to update.
        :param  List[crossauth_backend.KeyDataEntry] data_array: names and values.

        """
        hashed_session_key = self._session.hash_session_id(session_id)
        CrossauthLogger.logger().debug(j({"msg": f"Updating session data", "hashedSessionCookie": Crypto.hash(session_id)}))
        await self._key_storage.update_many_data(hashed_session_key, data_array)

    async def delete_session_data(self, session_id: str, name: str) -> None:
        """
        Deletes a field from the session data.
        
        The `data` field in the session entry is assumed to be a JSON string.
        The field with the given name is updated or set if not already set.
        :param str session_id; the session Id to update.

        """
        hashed_session_key = self._session.hash_session_id(session_id)
        CrossauthLogger.logger().debug(j({"msg": f"Updating session data value{name}", "hashedSessionCookie": Crypto.hash(session_id)}))
        await self._key_storage.delete_data(hashed_session_key, name)

    async def delete_session(self, session_id: str) -> None:
        """
        Deletes the given session ID from the key storage (not the cookie)
        
        :param str session_id: the session Id to delete

        """
        return await self._key_storage.delete_key(self._session.hash_session_id(session_id))

    async def create_user(self, user: User, params: UserSecrets, repeat_params: UserSecrets|None = None, skip_email_verification: bool = False, empty_password: bool = False) -> User:
        """ Not implemented """
        if not self._user_storage:
            raise Exception("Cannot call createUser if no user storage provided")

        if user['factor1'] not in self._authenticators:
            raise Exception("Authenticator cannot create users")

        if self._authenticators[user['factor1']].skip_email_verification_on_signup():
            skip_email_verification = True

        secrets = await self._authenticators[user['factor1']].create_persistent_secrets(user['username'], params, repeat_params) if not empty_password else None
        new_user = await self._user_storage.create_user(user, secrets) if not empty_password else await self._user_storage.create_user(user)

        if not skip_email_verification and self.__enable_email_verification and self.__token_emailer:
            raise CrossauthError(ErrorCode.NotImplemented, "Email verification is not supported in this version")
            #await self.token_emailer.send_email_verification_token(new_user['id'], None)

        return new_user

    async def delete_user_by_username(self, username: str) -> None:
        """ Not implemented """
        if not self._user_storage:
            raise Exception("Cannot call deleteUser if no user storage provided")
        self._user_storage.delete_user_by_username(username)

    async def initiate_two_factor_signup(self, user: User, params: UserSecrets, session_id: str, repeat_params: UserSecrets|None):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "Factor2 not implemented in this version")

    async def initiate_two_factor_setup(self, user: User, new_factor2: str|None, session_id: str) -> Mapping[str, Any]:
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "Factor2 not implemented in this version")

    async def repeat_two_factor_signup(self, session_id: str) -> Mapping[str, Any]:
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "2FA is not implemented in this version")

    async def complete_two_factor_setup(self, params: AuthenticationParameters, session_id: str) -> User:
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "2FA is not implemented in this version")

    async def initiate_two_factor_login(self, user: User) -> Mapping[str, Any]:
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "2FA is not implemented in this version")

    async def initiate_two_factor_page_visit(self, user: User, session_id: str, request_body: Mapping[str, Any], url: str|None=None, content_type: str|None = None):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "2FA is not implemented in this version")

    async def complete_two_factor_page_visit(self, params : AuthenticationParameters, session_id : str):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "2FA is not implemented in this version")

    async def cancel_two_factor_page_visit(self, session_id : str):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "2FA is not implemented in this version")

    async def complete_two_factor_login(self, params : AuthenticationParameters, session_id : str, extra_fields:Mapping[str, Any]|None=None, persist:bool=False):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "Login is not implemented in this version")

    async def request_password_reset(self, email : str):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "Password reset is not implemented in this version")

    async def apply_email_verification_token(self, token : str):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "Email verification is not implemented in this version")

    async def user_for_password_reset_token(self, token : str):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "Password reset  is not implemented in this version")

    async def update_user(self, current_user : User, new_user : User, skip_email_verification:bool=False, as_admin:bool=False):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "User update is not implemented in this version")

    async def reset_secret(self, token : str, factor_number:int, params:AuthenticationParameters, repeat_params:AuthenticationParameters|None=None):
        """ Not implemented """
        raise CrossauthError(ErrorCode.NotImplemented, "Password reset is not implemented in this version")


    @property
    def session_cookie_name(self):
        """ Returns the name used for session ID cookies. """
        return self._session.cookie_name
    
    @property
    def session_cookie_path(self):
        """ Returns the name used for session ID cookies """
        return self._session.path
    
    @property
    def csrf_cookie_name(self):
        """ Returns the name used for CSRF token cookies. """
        return self._csrf_tokens.cookie_name
    
    @property
    def csrf_cookie_path(self):
        """ Returns the name used for CSRF token cookies. """
        return self._csrf_tokens.path
    
    @property
    def csrf_header_name(self):
        """ Returns the name used for CSRF token cookies """
        return self._csrf_tokens.header_name
    