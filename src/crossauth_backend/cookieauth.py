from crossauth_backend.crypto import Crypto
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.common.interfaces import Key, PartialKey, KeyPrefix
from crossauth_backend.storage import KeyStorage, UserStorage, UserAndSecrets
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.storage import UserStorage, UserStorageGetOptions
from typing import Mapping, Any, TypedDict, Literal, NotRequired, Optional, Callable, NamedTuple
from datetime import datetime, timedelta
from nulltype import NullType, Null
CSRF_LENGTH = 16
SESSIONID_LENGTH = 16

class CookieOptions(TypedDict, total=False):
    """
    Optional parameters when setting cookies,

    These match the HTTP cookie parameters of the same name.
    """

    domain : str
    expires : datetime
    maxAge : int
    httpOnly : bool
    path : str
    secure : bool
    sameSite : bool | Literal["lax", "strict", "none"]

def to_cookie_serialize_options(options: CookieOptions) -> Mapping[str, Any]:
    return {
        **vars(options),
        'path': options["path"] if "path" in options else "/"
    }

class Cookie(TypedDict, total=True):
    """ Object encapsulating a cookie name, value and options. """

    name : str
    value : str
    options : CookieOptions

class DoubleSubmitCsrfTokenOptions(CookieOptions):
    """ Options for double-submit csrf tokens """

    cookie_name : NotRequired[str]
    header_name : NotRequired[str]
    secret: NotRequired[str]

class DoubleSubmitCsrfToken:
    """
    Class for creating and validating CSRF tokens according to the double-submit cookie pattern.
    
    CSRF token is send as a cookie plus either a header or a hidden form field.
    """

    @property
    def header_name(self):
        return self._header_name
    
    @property
    def cookie_name(self):
        return self._cookie_name
    
    @property
    def domain(self):
        return self._domain

    @property
    def httpOnly(self):
        return self._httpOnly
    
    @property
    def path(self):
        return self._path

    @property
    def secure(self):
        return self._secure
    
    @property
    def sameSite(self):
        return self._sameSite
        
    def __init__(self, options: DoubleSubmitCsrfTokenOptions = DoubleSubmitCsrfTokenOptions()):
        """
        Constructor

        :param DoubleSubmitCsrfTokenOptions options: See :class:`DoubleSubmitCsrfTokenOptions`

        """

        self._header_name = "X-CROSSAUTH-CSRF"
        self._cookie_name = options["cookie_name"] if "cookie_name" in options else "CSRFTOKEN"
        self._domain = options["domain"] if "domain" in options else None
        self._httpOnly = options["httpOnly"] if "httpOnly" in options else False
        self._path = options["path"] if "path" in options else "/"
        self._secure = options["secure"] if "secure" in options else True
        self._sameSite = options["sameSite"] if "sameSite" in options else "lax"

        self.__secret = ""
        
        # header options
        set_parameter("header_name", ParamType.String, self, options, "CSRF_HEADER_NAME", protected=True)

        # cookie options
        set_parameter("cookie_name", ParamType.String, self, options, "CSRF_COOKIE_NAME", protected=True)
        set_parameter("domain", ParamType.String, self, options, "CSRF_COOKIE_DOMAIN", protected=True)
        set_parameter("httpOnly", ParamType.Boolean, self, options, "CSRF_COOKIE_HTTPONLY", protected=True)
        set_parameter("path", ParamType.String, self, options, "CSRF_COOKIE_PATH", protected=True)
        set_parameter("secure", ParamType.Boolean, self, options, "CSRF_COOKIE_SECURE", protected=True)
        set_parameter("sameSite", ParamType.String, self, options, "CSRF_COOKIE_SAMESITE", protected=True)

        # hasher options
        set_parameter("secret", ParamType.String, self, options, "SECRET", True)

    def create_csrf_token(self) -> str:
        """
        Creates a session key and saves in storage
        
        Date created is the current date/time on the server.
        
        :return: a random CSRF token.
        """
        return Crypto.random_value(CSRF_LENGTH)

    def make_csrf_cookie(self, token: str) -> Cookie:
        """
        Returns a :class:`Cookie` object with the given session key.
        
        :param str token: the value of the csrf token, with signature

        :return a :class:`Cookie` object,
        """
        cookie_value = Crypto.sign_secure_token(token, self.__secret)
        options : CookieOptions = {
            "path": self.path,
            "secure": self.secure,
            "httpOnly": self.httpOnly}
        if (self.domain is not None): options["domain"] = self.domain
        options["sameSite"] = self.sameSite

        return Cookie(name=self.cookie_name, value=cookie_value, options=options)

    def make_csrf_form_or_header_token(self, token: str) -> str:
        return self.mask_csrf_token(token)

    def unsign_cookie(self, cookie_value: str) -> str:
        return Crypto.unsign_secure_token(cookie_value, self.__secret)

    def make_csrf_cookie_string(self, cookie_value: str) -> str:
        """
        Takes a session ID and creates a string representation of the cookie (value of the HTTP `Cookie` header).
         
        :param str cookie_value the value to put in the cookie

        :return: a string representation of the cookie and options.
        """

        cookie = f"{self.cookie_name}={cookie_value}; SameSite={self.sameSite}"
        if self.domain:
            cookie += f"; {self.domain}"
        if self.path:
            cookie += f"; {self.path}"
        if self.httpOnly:
            cookie += "; httpOnly"
        if self.secure:
            cookie += "; secure"
        return cookie

    def mask_csrf_token(self, token: str) -> str:
        mask = Crypto.random_value(CSRF_LENGTH)
        masked_token = Crypto.xor(token, mask)
        return f"{mask}.{masked_token}"

    def unmask_csrf_token(self, mask_and_token: str) -> str:
        parts = mask_and_token.split(".")
        if len(parts) != 2:
            raise CrossauthError(ErrorCode.InvalidCsrf, "CSRF token in header or form not in correct format")
        mask = parts[0]
        masked_token = parts[1]
        return Crypto.xor(masked_token, mask)

    def validate_double_submit_csrf_token(self, cookie_value: str, form_or_header_name: str) -> None:
        """
        Validates the passed CSRF token.  
        
        To be valid:
            - The signature in the cookie must match the token in the cookie
            - The token in the cookie must matched the value in the form or header after unmasking
        
        :param str cookie_value: the CSRF cookie value to validate.
        :param str form_or_header_name the value from the csrf_token form header or the X-CROSSAUTH-CSRF header.

        :raises :class:`crossauth_backend.CrossauthError` with :class:`ErrorCode` of `InvalidKey`
        """
        form_or_header_token = self.unmask_csrf_token(form_or_header_name)
        try:
            cookie_token = Crypto.unsign_secure_token(cookie_value, self.__secret)
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            raise CrossauthError(ErrorCode.InvalidCsrf, "Invalid CSRF cookie")

        if cookie_token != form_or_header_token:
            CrossauthLogger.logger().warn(j({"msg": "Invalid CSRF token received - form/header value does not match", 
                                          "csrfCookieHash": Crypto.hash(cookie_value)}))
            raise CrossauthError(ErrorCode.InvalidCsrf)

    def validate_csrf_cookie(self, cookie_value: str) -> str:
        """
        Validates the passed CSRF cookie (doesn't check it matches the token, just that the cookie is valid).  
        
        To be valid:
            - The signature in the cookie must match the token in the cookie
            - The token in the cookie must matched the value in the form or header after unmasking
        
        :param str cookie_value: the CSRF cookie value to validate.

        :raises :class:`crossauth_backend.CrossauthError` with :class:`ErrorCode` of `InvalidKey`
        """
        try:
            return Crypto.unsign_secure_token(cookie_value, self.__secret)
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            raise CrossauthError(ErrorCode.InvalidCsrf, "Invalid CSRF cookie")

class UserAndKey(NamedTuple):
    user: UserAndSecrets|None
    key: Key

class SessionCookieOptions(CookieOptions, total=False): # Also inherit from TokenEmailerOptions
    """
    Options for double-submit csrf tokens
    """
    
    user_storage: UserStorage
    """
    If user login is enabled, you must provide the user storage class
    """
    
    cookie_name: str
    """Name of cookie. Defaults to "CSRFTOKEN" """
    
    hash_session_id: bool
    """If true, session IDs are stored in hashed form in the key storage. Default False."""
    
    idle_timeout: int
    """
    If non zero, sessions will time out after self number of seconds have elapsed without activity.
    Default 0 (no timeout)
    """
    
    persist: bool
    """If true, sessions cookies will be persisted between browser sessions. Default True"""
    
    secret: str
    """App secret"""
    
    filter_function: Callable[[Key], bool]
    """
    self will be called with the session key to filter sessions 
    before returning. Function should return true if the session is valid or false otherwise.
    """

class CookieReturn(NamedTuple):
    userid: str|int|None
    value: str
    created: datetime
    expires: datetime | None

class SessionCookie:
    """
    Class for session management using a session id cookie.
    """

    @property
    def idle_timeout(self):
        return self._idle_timeout
    
    @property 
    def cookie_name(self):
        return self._cookie_name

    @property 
    def maxAge(self):
        return self._maxAge
    
    @property
    def domain(self):
        return self._domain
    
    @property
    def httpOnly(self):
        return self._httpOnly
    
    @property
    def path(self):
        return self._path
    
    @property
    def secure(self):
        return self._secure
    
    @property
    def sameSite(self):
        return self._sameSite

    def __init__(self, key_storage : KeyStorage, options: SessionCookieOptions = {}):
        """
        Constructor

        :param crossauth_backend.KeyStorage key_storage: where to store session keys

        """
        self.__persist : bool = True
        self._idle_timeout : int = 0
        self.__filter_function : Callable[[Key], bool] | None = None

        ## cookie settings
        self._cookie_name : str = "SESSIONID"
        self._maxAge : int = 60*60*24*4; # 4 weeks
        self._domain : str | None = None
        self._httpOnly : bool = False
        self._path : str = "/"
        self._secure : bool = True
        self._sameSite : bool | Literal["lax", "strict", "none"] | None = "lax"

        ## hasher settings
        self.__secret : str = ""

        self.__user_storage = options["user_storage"] if "user_storage" in options else None
        self.key_storage = key_storage
        set_parameter("idle_timeout", ParamType.Number, self, options, "SESSION_IDLE_TIMEOUT", protected=True)
        set_parameter("persist", ParamType.Number, self, options, "PERSIST_SESSION_ID")
        self.filter_function = options['filterFunction'] if 'filterFunction' in options else None

        # cookie settings
        set_parameter("cookie_name", ParamType.String, self, options, "SESSION_COOKIE_NAME", protected=True)
        set_parameter("maxAge", ParamType.String, self, options, "SESSION_COOKIE_maxAge", protected=True)
        set_parameter("domain", ParamType.String, self, options, "SESSION_COOKIE_DOMAIN", protected=True)
        set_parameter("httpOnly", ParamType.Boolean, self, options, "SESSIONCOOKIE_HTTPONLY", protected=True)
        set_parameter("path", ParamType.String, self, options, "SESSION_COOKIE_PATH", protected=True)
        set_parameter("secure", ParamType.Boolean, self, options, "SESSION_COOKIE_SECURE", protected=True)
        set_parameter("sameSite", ParamType.String, self, options, "SESSION_COOKIE_SAMESITE", protected=True)

        # hasher settings
        self.__secret = options["secret"] if "secret" in options else ""

    def _expiry(self, date_created: datetime) -> datetime | None:
        expires = None
        if self.maxAge > 0:
            expires = date_created + timedelta(0, self.maxAge)
        return expires

    @staticmethod
    def hash_session_id(session_id: str) -> str:
        """
        Returns a hash of a session ID, with the session ID prefix for storing
        in the storage table.
        :param str session_id the session ID to hash

        :return: a base64-url-encoded string that can go into the storage
        """
        return KeyPrefix.session + Crypto.hash(session_id)

    async def create_session_key(self, userid: str | int | None, extra_fields: Mapping[str, Any] = {}) -> Key:
        """
        Creates a session key and saves in storage
        
        Date created is the current date/time on the server.
        
        In the unlikely event of the key already existing, it is retried up to 10 times before throwing
        an error with ErrorCode.KeyExists
        
        :param str | int | None userid: the user ID to store with the session key.
        :param Dict[str, Any]|None extra_fields: Any fields in here will also be added to the session
               record

        :return: the new session key

        :raises :class:`crossauth_backend.CrossauthError`: with 
                :class:`ErrorCode` `KeyExists` if maximum
                 attempts exceeded trying to create a unique session id
        """
        max_tries = 10
        num_tries = 0
        session_id = Crypto.random_value(SESSIONID_LENGTH)
        date_created = datetime.now()
        expires = self._expiry(date_created)
        succeeded = False

        extra_fields_copy = {**extra_fields}
        while num_tries < max_tries and not succeeded:
            hashed_session_id = self.hash_session_id(session_id)
            try:
                if self.idle_timeout > 0 and userid:
                    extra_fields_copy['lastActivity'] = datetime.now()
                data : str|None = None
                if ("data" in extra_fields):
                    data = extra_fields["data"]
                    extra_fields = {**extra_fields}
                    del extra_fields["data"]
                await self.key_storage.save_key(userid, hashed_session_id, date_created, expires, data, extra_fields)
                succeeded = True
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                if ce.code in (ErrorCode.KeyExists, ErrorCode.InvalidKey):
                    num_tries += 1
                    session_id = Crypto.random_value(SESSIONID_LENGTH)
                    if num_tries > max_tries:
                        CrossauthLogger.logger().error({"msg": "Max attempts exceeded trying to create session ID"})
                        raise CrossauthError(ErrorCode.KeyExists)
                else:
                    CrossauthLogger.logger().debug(j({"err": ce}))
                    raise e

        key : Key = {
            "value": session_id,
            "created": date_created,
            "expires": expires or Null,
        }
        if (userid is not None): key["userid"] = userid
        return key

    def make_cookie(self, session_key: Key, persist: Optional[bool] = None) -> Cookie:
        """
        Returns a :class:`Cookie` object with the given session key.
        
        This class is compatible, for example, with Express.
        
        :param crossauth_backend.Key session_key: the value of the session key
        :param bool|None persist: if passed, overrides the persistSessionId setting

        :return: a :class:`Cookie` object,

        """
        signed_value = Crypto.sign_secure_token( session_key['value'], self.__secret)
        options : CookieOptions = {}
        if persist is None:
            persist = self.__persist
        if self.domain:
            options['domain'] = self.domain
        if 'expires' in session_key and type(session_key['expires']) != NullType and persist:
            options['expires'] = session_key['expires'] # type: ignore
        if self.path:
            options['path'] = self.path
        options['sameSite'] = self.sameSite
        if self.httpOnly:
            options['httpOnly'] = self.httpOnly
        if self.secure:
            options['secure'] = self.secure
        return {
            'name': self.cookie_name,
            'value': signed_value,
            'options': options
        }

    def make_cookie_string(self, cookie: Cookie) -> str:
        """
        Takes a session ID and creates a string representation of the cookie
        (value of the HTTP `Cookie` header).
        
        :param Cookie cookie: the cookie vlaues to make a string from

        :return: a string representation of the cookie and options.
        """
        cookie_string = f"{cookie['name']}={cookie['value']}"
        if self.sameSite:
            cookie_string += f"; SameSite={self.sameSite}"
        if 'expires' in cookie['options']:
            expires = cookie['options']['expires'].strftime('%a, %d %b %Y %H:%M:%S %Z')
            cookie_string += f"; expires={expires}"
        if self.domain:
            cookie_string += f"; domain={self.domain}"
        if self.path:
            cookie_string += f"; path={self.path}"
        if self.httpOnly:
            cookie_string += "; httpOnly"
        if self.secure:
            cookie_string += "; secure"
        return cookie_string

    async def update_session_key(self, session_key: PartialKey) -> None:
        """
        Updates a session record in storage
        :param crossauth_backend.PartialKey session_key: the fields to update.  `value` must be set, and
        will not be updated.  All other defined fields will be updated.

        :raises :class:`crossauth_backend.CrossauthError`: if the session does
        not exist. 
        """
        if 'value' not in session_key:
            raise CrossauthError(ErrorCode.InvalidKey, "No session when updating activity")
        session_key['value'] = self.hash_session_id(session_key['value'])
        await self.key_storage.update_key(session_key)

    def unsign_cookie(self, cookie_value: str) -> str:
        """
        Unsigns a cookie and returns the original value.
        :param str cookie_value: the signed cookie value

        :return: the unsigned value

        :raises :class:`crossauth_backend.CrossauthError`: if the signature
        is invalid. 
        """
        return Crypto.unsign_secure_token(cookie_value, self.__secret)

    async def get_user_for_session_id(self, session_id: str, options: UserStorageGetOptions = {}) -> UserAndKey:
        """
        Returns the user matching the given session key in session storage, or throws an exception.
        
        Looks the user up in the :class:`crossauth_backend.UserStorage` instance passed to the constructor.
        
        Undefined will also fail is CookieAuthOptions.filterFunction is defined and returns false,
        
        :param str session_id: the value in the session cookie
        :param crossauth_backend.UserStorageGetOptions options: See :class:`crossauth_backend.UserStorageGetOptions`

        :return: a :class:`crossauth_backend.User` object, with the password hash removed, and the:class:`crossauth_backend.Key` with the unhashed
         session_id

        :raises :class:`crossauth_backend.CrossauthError`: with :class:`ErrorCode` set to `InvalidSessionId` or `Expired`.
        """
        key = await self.get_session_key(session_id)
        if not self.__user_storage:
            return UserAndKey(None, key)
        if 'userid' in key and type(key['userid']) is not NullType:
            user = await self.__user_storage.get_user_by_id(key['userid'], options) # type: ignore
            return UserAndKey(user, key)
        else:
            return UserAndKey(None, key)

    async def get_session_key(self, session_id: str) -> Key:
        """
        Returns the user matching the given session key in session storage, or throws an exception.
        
        Looks the user up in the :class:`UserStorage` instance passed to the constructor.
        
        Undefined will also fail is CookieAuthOptions.filterFunction is defined and returns false,
        
        :param str session_id: the unsigned value of the session cookie

        :return: a :class:`crossauth_backend.User` object, with the password hash removed.

        :raises :class:`crossauth_backend.CrossauthError`: with 
        :class:`ErrorCode` set to `InvalidSessionId`,
        `Expired` or `UserNotExist`.
        """
        now = datetime.now()
        hashed_session_id = self.hash_session_id(session_id)
        key = await self.key_storage.get_key(hashed_session_id)
        key['value'] = session_id  # storage only has hashed version
        if 'expires' in key:
            expires = key['expires']
            if type(expires) is not NullType and now > expires: # type: ignore
                    CrossauthLogger.logger().warn(j({"msg": "Session id in cookie expired in key storage", "hashedSessionCookie": Crypto.hash(session_id)}))
                    raise CrossauthError(ErrorCode.Expired)
        if key.get('userid') and self.idle_timeout > 0 and 'lastactive' in key and now > key['lastactive'] + timedelta(0, self.idle_timeout):
            CrossauthLogger.logger().warn(j({"msg": "Session cookie with expired idle time received", "hashedSessionCookie": Crypto.hash(session_id)}))
            raise CrossauthError(ErrorCode.Expired)
        if self.filter_function and not self.filter_function(key):
            CrossauthLogger.logger().warn(j({"msg": "Filter function on session id in cookie failed", "hashedSessionCookie": Crypto.hash(session_id)}))
            raise CrossauthError(ErrorCode.InvalidKey)
        return key

    async def delete_all_for_user(self, userid: str | int, except_key: str|None = None) -> None:
        """
        Deletes all keys for the given user
        :param str|int userid: the user to delete keys for
        :param str|None except_key: if defined, don't delete this key

        """
        if except_key:
            except_key = self.hash_session_id(except_key)
        await self.key_storage.delete_all_for_user(userid, KeyPrefix.session, except_key)
