from crossauth_backend.crypto import Crypto
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.common.interfaces import Key, PartialKey, KeyPrefix
from crossauth_backend.storage import KeyStorage, UserStorage
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.storage import UserStorage, UserStorageGetOptions
from typing import Dict, Any, TypedDict, Literal, NotRequired, Optional, Callable, NamedTuple
from datetime import datetime, timedelta
from nulltype import NullType
CSRF_LENGTH = 16
SESSIONID_LENGTH = 16

class CookieOptions(TypedDict, total=False):
        domain : str
        expires : datetime
        maxAge : int
        httpOnly : bool
        path : str
        secure : bool
        sameSite : bool | Literal["lax", "strict", "none"]

def to_cookie_serialize_options(options: CookieOptions) -> Dict[str, Any]:
    return {
        **vars(options),
        'path': options["path"] if "path" in options else "/"
    }

class Cookie(TypedDict, total=True):
    name : str
    value : str
    options : CookieOptions

class DoubleSubmitCsrfTokenOptions(CookieOptions):
    cookie_name : NotRequired[str]
    header_value : NotRequired[str]
    secret: NotRequired[str]

class DoubleSubmitCsrfToken:
    def __init__(self, options: DoubleSubmitCsrfTokenOptions = DoubleSubmitCsrfTokenOptions()):
        self.header_value = "X-CROSSAUTH-CSRF"
        self.cookie_name = options["cookie_name"] if "cookie_name" in options else "CSRFTOKEN"
        self.domain = options["domain"] if "domain" in options else None
        self.httpOnly = options["httpOnly"] if "httpOnly" in options else False
        self.path = options["path"] if "path" in options else "/"
        self.secure = options["secure"] if "secure" in options else True
        self.sameSite = options["sameSite"] if "sameSite" in options else "lax"
        self.secret = options["secret"] if "secret" in options else ""

    def create_csrf_token(self) -> str:
        return Crypto.random_value(CSRF_LENGTH)

    def make_csrf_cookie(self, token: str) -> Cookie:
        cookie_value = Crypto.sign({'v': token}, self.secret, "")
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
        return Crypto.unsign(cookie_value, self.secret)['v']

    def make_csrf_cookie_string(self, cookie_value: str) -> str:
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

    def validate_double_submit_csrf_token(self, cookie_value: str, form_or_header_value: str) -> None:
        form_or_header_token = self.unmask_csrf_token(form_or_header_value)
        try:
            cookie_token = Crypto.unsign(cookie_value, self.secret)['v']
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            raise CrossauthError(ErrorCode.InvalidCsrf, "Invalid CSRF cookie")

        if cookie_token != form_or_header_token:
            CrossauthLogger.logger().warn(j({"msg": "Invalid CSRF token received - form/header value does not match", 
                                          "csrfCookieHash": Crypto.hash(cookie_value)}))
            raise CrossauthError(ErrorCode.InvalidCsrf)

    def validate_csrf_cookie(self, cookie_value: str) -> None:
        try:
            return Crypto.unsign(cookie_value, self.secret)['v']
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            raise CrossauthError(ErrorCode.InvalidCsrf, "Invalid CSRF cookie")

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

    def __init__(self, key_storage : KeyStorage, options: SessionCookieOptions = {}):
        self.persist : bool = True
        self.idle_timeout : int = 0
        _filterFunction : Callable[[Key], bool] | None = None

        ## cookie settings
        self.cookie_name : str = "SESSIONID"
        """ Name of the CSRF Cookie, set from input options """
        self.maxAge : int = 60*60*24*4; # 4 weeks
        self.domain : str | None = None
        self.httpOnly : bool = False
        self.path : str = "/"
        self.secure : bool = True
        self.sameSite : bool | Literal["lax", "strict", "none"] | None = "lax"

        ## hasher settings
        self._secret : str = ""

        self.user_storage = options["user_storage"] if "user_storage" in options else None
        self.key_storage = key_storage
        set_parameter("idle_timeout", ParamType.Number, self, options, "SESSION_IDLE_TIMEOUT")
        set_parameter("persist", ParamType.Number, self, options, "PERSIST_SESSION_ID")
        self.filter_function = options['filterFunction'] if 'filterFunction' in options else None

        # cookie settings
        set_parameter("cookie_name", ParamType.String, self, options, "SESSION_COOKIE_NAME");
        set_parameter("maxAge", ParamType.String, self, options, "SESSION_COOKIE_maxAge");
        set_parameter("domain", ParamType.String, self, options, "SESSION_COOKIE_DOMAIN");
        set_parameter("httpOnly", ParamType.Boolean, self, options, "SESSIONCOOKIE_HTTPONLY");
        set_parameter("path", ParamType.String, self, options, "SESSION_COOKIE_PATH");
        set_parameter("secure", ParamType.Boolean, self, options, "SESSION_COOKIE_SECURE");
        set_parameter("sameSite", ParamType.String, self, options, "SESSION_COOKIE_SAMESITE");

        # hasher settings
        self._secret = options["secret"] if "secret" in options else ""

    def expiry(self, date_created: datetime) -> datetime | None:
        expires = None
        if self.maxAge > 0:
            expires = date_created + timedelta(0, self.maxAge)
        return expires

    @staticmethod
    def hash_session_id(session_id: str) -> str:
        return KeyPrefix.session + Crypto.hash(session_id)

    async def create_session_key(self, userid: str | int | None, extra_fields: Optional[Dict[str, Any]] = None) -> CookieReturn:
        if extra_fields is None:
            extra_fields = {}
        max_tries = 10
        num_tries = 0
        session_id = Crypto.random_value(SESSIONID_LENGTH)
        date_created = datetime.now()
        expires = self.expiry(date_created)
        succeeded = False

        while num_tries < max_tries and not succeeded:
            hashed_session_id = self.hash_session_id(session_id)
            try:
                if self.idle_timeout > 0 and userid:
                    extra_fields['lastActivity'] = datetime.now()
                await self.key_storage.save_key(userid, hashed_session_id, date_created, expires, None, extra_fields)
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
                    CrossauthLogger.logger().debug({"err": e})
                    raise e

        return CookieReturn(userid, session_id, date_created, expires)

    def make_cookie(self, session_key: Dict[str, Any], persist: Optional[bool] = None) -> Dict[str, Any]:
        signed_value = Crypto.sign({'v': session_key['value']}, self._secret, "")
        options = {}
        if persist is None:
            persist = self.persist
        if self.domain:
            options['domain'] = self.domain
        if session_key.get('expires') and persist:
            options['expires'] = session_key['expires']
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
        if 'value' not in session_key:
            raise CrossauthError(ErrorCode.InvalidKey, "No session when updating activity")
        session_key['value'] = self.hash_session_id(session_key['value'])
        await self.key_storage.update_key(session_key)

    def unsign_cookie(self, cookie_value: str) -> str:
        return Crypto.unsign(cookie_value, self._secret)['v']

    async def get_user_for_session_id(self, session_id: str, options: UserStorageGetOptions = {}) -> Dict[str, Any]:
        key = await self.get_session_key(session_id)
        if not self.user_storage:
            return {'key': key, 'user': None}
        if 'userid' in key and type(key['userid']) is not NullType:
            user = await self.user_storage.get_user_by_id(key['userid'], options) # type: ignore
            return {'user': user, 'key': key}
        else:
            return {'user': None, 'key': key}

    async def get_session_key(self, session_id: str) -> Key:
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
        if except_key:
            except_key = self.hash_session_id(except_key)
        await self.key_storage.delete_all_for_user(userid, KeyPrefix.session, except_key)
