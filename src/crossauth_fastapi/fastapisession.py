# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import Callable, Mapping, Optional, Dict, Any, List, cast, TypedDict, Literal
from datetime import datetime
from typing import Mapping, Tuple, Set
import json
from fastapi import Request, FastAPI, Response
from fastapi.responses import JSONResponse
from starlette.datastructures import FormData
from starlette.types import Message
from crossauth_backend.session import SessionManagerOptions
from crossauth_backend.cookieauth import  CookieOptions
from crossauth_backend.common.interfaces import User, Key
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.storage import KeyStorage, KeyDataEntry
from crossauth_backend.auth import Authenticator
from crossauth_backend.session import SessionManager
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.crypto import Crypto
from crossauth_fastapi.fastapisessionadapter import FastApiSessionAdapter

class FastApiCookieOptions(TypedDict, total=True):
    max_age: int|None
    expires: datetime|str|int|None
    path: str|None
    domain: str|None
    secure: bool
    httponly: bool
    samesite: Literal['lax', 'strict', 'none'] | None

def toFastApiCookieOptions(options: CookieOptions):
    ret : FastApiCookieOptions = {
        "max_age": None,
        "expires": None,
        "path": "/",
        "domain": None,
        "secure": False,
        "httponly": False,
        "samesite": None
    }
    if "maxAge" in options: ret["max_age"] = options["maxAge"]
    if "expires" in options: ret["expires"] = options["expires"]
    if "path" in options: ret["path"] = options["path"]
    if "domain" in options: ret["domain"] = options["domain"]
    if "samesite" in options: ret["samesite"] = options["samesite"]
    return ret

class JsonOrFormData:
    def __init__(self):
        self.__form : FormData | None = None
        self.__json : Dict[str, Any] = {}


    async def load(self, request : Request):
        content_type = request.headers['content-type'] if 'content-type' in request.headers else "text/plain"
        body = await request.body()
        async def receive() -> Message:
            return {"type": "http.request", "body": body}
        request._receive = receive # type: ignore
        try:
            if (content_type == "application/x-www-form-urlencoded" or content_type == "multipart/form-data"):
                self.__form = await request.form()
            else:
                self.__json = await request.json()
        except: pass

    def get(self, name : str, default: Any|None = None):
        if (self.__form): 
            ret = default
            if (name not in self.__form): return default
            ret = self.__form[name]
            if (type(ret) == str): return ret
            raise CrossauthError(ErrorCode.DataFormat, "Field " + name + " is unsupported type")
        elif (self.__json): 
            return self.__json[name] if name in self.__json else default
        return None

    def getAsStr(self, name : str, default: str|None = None) -> str|None:
        if (self.__form): 
            ret = default
            if (name not in self.__form): return default
            ret = self.__form[name]
            if (type(ret) == str): return ret
            raise CrossauthError(ErrorCode.DataFormat, "Field " + name + " is unsupported type")
        elif (self.__json): 
            if (name not in self.__json): return default
            ret = self.__json[name] 
            if (type(ret) != str): return str(ret)
            return ret
        return None

    def getAsBool(self, name : str, default: bool|None = None) -> bool|None:
        if (self.__form): 
            ret = default
            if (name not in self.__form): return default
            ret = self.__form[name]
            if (type(ret) == str): 
                ret = ret.lower()
                return ret == "true" or ret == "t" or ret == "on" or ret == "1" or ret == "yes" or ret == "y"
            raise CrossauthError(ErrorCode.DataFormat, "Field " + name + " is unsupported type")
        elif (self.__json): 
            if (name not in self.__json): return default
            ret = self.__json[name] 
            if (type(ret) == bool): return ret
            elif (type(ret) == int or type(ret) == float): return int(ret) > 0
            elif (type(ret) == str):
                return ret == "true" or ret == "t" or ret == "on" or ret == "1" or ret == "yes" or ret == "y"
            raise CrossauthError(ErrorCode.DataFormat, "Field " + name + " is unexpected type")
        return None
    
    def getAsInt(self, name : str, default: int|None = None) -> int|None:
        if (self.__form): 
            ret = default
            if (name not in self.__form): return default
            ret = self.__form[name]
            if (type(ret) == str): 
                return int(ret)
            raise CrossauthError(ErrorCode.DataFormat, "Field " + name + " is unsupported type")
        elif (self.__json): 
            if (name not in self.__json): return default
            ret = self.__json[name] 
            if (type(ret) == bool): return 1 if ret else 0
            elif (type(ret) == int or type(ret) == float): return int(ret)
            elif (type(ret) == str):
                return int(ret)
            raise CrossauthError(ErrorCode.DataFormat, "Field " + name + " is unexpected type")
        return None

    def getAsFloat(self, name : str, default: float|None = None) -> float|None:
        if (self.__form): 
            ret = default
            if (name not in self.__form): return default
            ret = self.__form[name]
            if (type(ret) == str): 
                return float(ret)
            raise CrossauthError(ErrorCode.DataFormat, "Field " + name + " is unsupported type")
        elif (self.__json): 
            if (name not in self.__json): return default
            ret = self.__json[name] 
            if (type(ret) == bool): return 1 if ret else 0
            elif (type(ret) == int or type(ret) == float): return float(ret)
            elif (type(ret) == str):
                return float(ret)
            raise CrossauthError(ErrorCode.DataFormat, "Field " + name + " is unexpected type")
        return None

class FastApiSessionServerOptions(SessionManagerOptions, total=False):
    """ Options for :class:`FastApiSessionServer`. """

    add_to_session: Callable[[Request], Mapping[str, str|int|float|datetime|None]]
    """
    Called when a new session token is going to be saved 
    Add additional fields to your session storage here.  Return a map of 
    keys to values
    """

    validate_session: Callable[[Key, User|None, Request], None]
    """
    Called after the session ID is validated.
    Use this to add additional checks based on the request.  
    Throw an exception if cecks fail    
    """

    error_page : str
    """
    Page to render error messages, including failed login. 
    See the class documentation for :class:`FastApiServer` for more info.  
    Defaults to "error.jinja2".
    """

class FastApiSessionServer(FastApiSessionAdapter):
    """
    This class adds user endpoints to the FastAPI session server.

    **Important Note** This class is imcomplete.  It supports only enough
    functionality to provide CSRF cookies and anonymous sessions (where there
    is no user).  The rest of the functionality will come later.

    You shouldn't have create create this directly - it is created by
    :class:`FastApiServer`.

    **Using your own FastAPI app**

    If you are serving other endpoints, or you want to use something other than 
    Nunjucks, you can create
    and pass in your own FastAPI app.

    **Middleware**

    This class registers one middleware function to fill in the following
    fields in `Request.state`:

      - `user` a :class:`crossauch_backend.User` object which currently is always None
      - `auth_type`: set to `cookie` or None (currently always None)
      - `csrf_token`: a CSRF token that can be used in POST requests
      - `session_id` a session ID if one is created with :meth:`create_anonymous_session`
    """

    @property
    def app(self):
        return self._app
    
    @property
    def error_page(self):
        return self._error_page
    
    @property
    def session_manager(self):
        return self._session_manager
    
    @property
    def enable_csrf_protection(self):
        return self._enable_csrf_protection
    
    def __init__(self, app: FastAPI, 
                 key_storage: KeyStorage, 
                 authenticators: Mapping[str, Authenticator], 
                 options: FastApiSessionServerOptions = {}):
        """
        Constructor

        :param FastAPI app you can pass in your own FastAPI app instance or
               set this to None for one to be created
        :param :class:`crossauth_backend.KeyStorage` key_storage: where to
               put session IDs that are created
        :param Mapping[str, :class:`Authenticator`] authenticators, keyed
               on the name that appears in a :class:`crossauth_backend.User`'s `factor1` or
               `factor2`.  Currently user authentication is not implemented,
               so just pass an empty dict.
        :param FastApiSessionServerOptions options: see :class:`FastApiSessionServerOptions`

        """
        self._app = app
        self.__prefix : str = "/"
        self._error_page = "error.jinja2"
        self._session_manager = SessionManager(key_storage, authenticators, options)
        self.__add_to_session = options['add_to_session'] if "add_to_session" in options else None
        self.__validate_session = options['validate_session'] if "validate_session" in options else None
        self._enable_csrf_protection = True

        self._session_manager = SessionManager(key_storage, authenticators, options)

        set_parameter("error_page", ParamType.String, self, options, "ERROR_PAGE", protected=True)
        set_parameter("prefix", ParamType.String, self, options, "PREFIX")
        if not self.__prefix.endswith("/"): self.__prefix += "/"

        @app.middleware("http")
        async def pre_handler(request: Request, call_next): # type: ignore
            CrossauthLogger.logger().debug(j({"msg": "Getting session cookie"}))
            request.state.user= None
            request.state.csrf_token  = None
            request.state.session_id = None
            request.state.auth_type = None
            add_cookies : Dict[str, Tuple[str, CookieOptions]] = {}
            delete_cookies : Set[str] = set()
            headers : Dict[str, str] = {}

            session_cookie_value = self.get_session_cookie_value(request)
            report_session = {}
            if session_cookie_value:
                try:
                    report_session['hashedSessionId'] = Crypto.hash(self.session_manager.get_session_id(session_cookie_value))
                except:
                    report_session['hashedSessionCookie'] = Crypto.hash(session_cookie_value)

            CrossauthLogger.logger().debug(j({"msg": "Getting csrf cookie"}))
            cookie_value = None
            try:
                cookie_value = self.get_csrf_cookie_value(request)
                if cookie_value:
                    self.session_manager.validate_csrf_cookie(cookie_value)
            except Exception as e:
                CrossauthLogger.logger().warn(j({"msg": "Invalid csrf cookie received", "cerr": str(e), "hashedCsrfCookie": self.get_hash_of_csrf_cookie(request)}))
                #response.delete_cookie(self.session_manager.csrf_cookie_name)
                if (self.session_manager.csrf_cookie_name in add_cookies):
                    del add_cookies[self.session_manager.csrf_cookie_name]
                delete_cookies.add(self.session_manager.csrf_cookie_name)
                cookie_value = None

            #response : Response = cast(Response, await call_next(request))
            if request.method in ["GET", "OPTIONS", "HEAD"]:

                try:
                    if not cookie_value:
                        CrossauthLogger.logger().debug(j({"msg": "Invalid CSRF cookie - recreating"}))
                        csrf = await self.session_manager.create_csrf_token()
                        csrf_cookie = csrf.csrf_cookie
                        csrf_form_or_header_value = csrf.csrf_form_or_header_value
                        #options = toFastApiCookieOptions(csrf_cookie["options"])
                        #response.set_cookie(csrf_cookie["name"], csrf_cookie["value"], **options)
                        add_cookies[csrf_cookie["name"]] = (csrf_cookie["value"],csrf_cookie["options"])
                        if (csrf_cookie["name"] in delete_cookies):
                            delete_cookies.remove(csrf_cookie["name"])
                        request.state.csrf_token = csrf_form_or_header_value
                    else:
                        CrossauthLogger.logger().debug(j({"msg": "Valid CSRF cookie - creating token"}))
                        csrf_form_or_header_value = await self.session_manager.create_csrf_form_or_header_value(cookie_value)
                        request.state.csrf_token = csrf_form_or_header_value
                    #response.headers[self.session_manager.csrf_header_name] = request.state.csrf_token
                    headers[self.session_manager.csrf_header_name] = request.state.csrf_token
                except Exception as e:
                    CrossauthLogger.logger().error(j({
                        "msg": "Couldn't create CSRF token",
                        "cerr": str(e),
                        "user": FastApiSessionServer.username(request),
                        **report_session,
                    }))
                    CrossauthLogger.logger().debug(j({"err": str(e)}))
                    #response.delete_cookie(self.session_manager.csrf_cookie_name)
            else:
                if cookie_value:
                    try:
                        await self.csrf_token(request, add_cookies=add_cookies, delete_cookies=delete_cookies, headers=headers)
                    except Exception as e:
                        CrossauthLogger.logger().error(j({
                            "msg": "Couldn't create CSRF token",
                            "cerr": str(e),
                            "user": FastApiSessionServer.username(request),
                            **report_session,
                        }))
                        CrossauthLogger.logger().debug(j({"err": str(e)}))

            session_cookie_value = self.get_session_cookie_value(request)
            if session_cookie_value:
                try:
                    session_id = self.session_manager.get_session_id(session_cookie_value)
                    ret = await self.session_manager.user_for_session_id(session_id)
                    if self.__validate_session:
                        user : User|None = None
                        if (ret.user is not None): user = ret.user["user"]
                        self.__validate_session(ret.key, user, request)
                    request.state.session_id = session_id
                    CrossauthLogger.logger().debug(j({
                        "msg": "Valid session id",
                        "user": None
                    }))
                except Exception as e:
                    CrossauthLogger.logger().debug(j({"err": e}))
                    CrossauthLogger.logger().warn(j({
                        "msg": "Invalid session cookie received",
                        "hash_of_session_id": self.get_hash_of_session_id(request)
                    }))
                    #response.delete_cookie(self.session_manager.session_cookie_name)
                    if (self.session_manager.session_cookie_name in add_cookies):
                        del add_cookies[self.session_manager.session_cookie_name]
                    delete_cookies.add(self.session_manager.session_cookie_name)

            response : Response = cast(Response, await call_next(request))
            for cookie in delete_cookies:
                response.delete_cookie(cookie)
            for name in add_cookies:
                cookie = add_cookies[name]
                options = toFastApiCookieOptions(cookie[1])
                response.set_cookie(name, cookie[0], **options)
            for header_name in headers:
                response.headers[header_name] = headers[header_name]
            return response

        #####
        # Get CSRF Token
        async def api_getcsrftoken_endpoint(request: Request, response: Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method":request.method,
                "url": self.__prefix + 'api/getcsrftoken',
                "ip": request.client.host if request.client is not None else None,
                "user": FastApiSessionServer.username(request)
            }))
            try:
                return JSONResponse({
                    "ok": True,
                    "csrfToken": request.state.csrf_token
                })
            except:
                return JSONResponse({
                    "ok": False,
                })

        self.app.get(self.__prefix + 'api/getcsrftoken')(api_getcsrftoken_endpoint)
        self.app.post(self.__prefix + 'api/getcsrftoken')(api_getcsrftoken_endpoint)


    async def create_anonymous_session(self, request: Request, response: Response, data: Optional[Dict[str, Any]] = None) -> str:
        """
        Creates and persists an anonymous session.

        An anonymous session is one which is not associated with a user.  This
        is needed when you need to save session state, despite a user not being
        logged in.

        :param Request request the FastAPI Request object
        :param Response request the FastAPI Response object
        :param Dict[str, Any] data optionally, data to store in the session.
           The top level keys should not conflict with anything that FastAPI
           itself stores
        """
        CrossauthLogger.logger().debug(j({"msg": "Creating session ID"}))
        extra_fields : Mapping[str, str|int|float|datetime|None] = {}
        if self.__add_to_session: 
            extra_fields = self.__add_to_session(request) 
        if data:
            extra_fields = {"data": json.dumps(data)}

        ret = await self.session_manager.create_anonymous_session(extra_fields)
        session_cookie = ret.session_cookie
        csrf_cookie = ret.csrf_cookie
        csrf_form_or_header_value = ret.csrf_form_or_header_value
        options = toFastApiCookieOptions(session_cookie["options"])
        response.set_cookie(session_cookie["name"], session_cookie["value"], **options)
        request.state.csrf_token = csrf_form_or_header_value
        options = toFastApiCookieOptions(csrf_cookie["options"])
        response.set_cookie(csrf_cookie["name"], csrf_cookie["value"], **options)
        request.state.user = None
        session_id = self.session_manager.get_session_id(session_cookie["value"])
        request.state.session_id = session_id
        return session_cookie["value"]

    @staticmethod
    def username(request : Request) -> str|None:
        if (not hasattr(request.state, "user")): return None
        if (request.state.user is None): return None
        if (type(request.state.user) is not dict): return None
        user : User = request.state.user # type: ignore
        if (not "username" in user): return None # type: ignore
        return user["username"]

    @staticmethod
    def user(request : Request) -> User|None:
        if (not hasattr(request.state, "user")): return None
        if (request.state.user is None): return None
        if (type(request.state.user) is not dict): return None
        return request.state.user # type: ignore

    def handle_error(self, e: Exception, request: Request, response: Response, error_fn: Callable[[Response, CrossauthError], None], password_invalid_ok: bool = False):
        """
        Calls your defined `error_fn`, first sanitising by changing 
        `UserNotExist` and `UsernameOrPasswordInvalid` messages to `UsernameOrPasswordInvalid`.
        Also logs the error
        """
        try:
            ce = CrossauthError.as_crossauth_error(e)
            if not password_invalid_ok:
                if ce.code in [ErrorCode.UserNotExist, ErrorCode.PasswordInvalid]:
                    ce = CrossauthError(ErrorCode.UsernameOrPasswordInvalid, "Invalid username or password")
            CrossauthLogger.logger().debug(j({"err": ce}))
            CrossauthLogger.logger().error(j({
                "cerr": ce,
                "hash_of_session_id": self.get_hash_of_session_id(request),
                "user": FastApiSessionServer.username(request)
            }))
            return error_fn(response, ce)
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return error_fn(response, CrossauthError(ErrorCode.UnknownError))

    def get_session_cookie_value(self, request: Request) -> Optional[str]:
        """
        Returns the session cookie value or None if there isn't one

        :param Request request: the FastAPI Request

        """
        if request.cookies and self.session_manager.session_cookie_name in request.cookies:
            return request.cookies[self.session_manager.session_cookie_name]
        return None

    def get_csrf_cookie_value(self, request: Request) -> Optional[str]:
        """
        Returns the CSRF cookie value or None if there isn't one

        :param Request request: the FastAPI Request
        
        """
        if request.cookies and self.session_manager.csrf_cookie_name in request.cookies:
            return request.cookies[self.session_manager.csrf_cookie_name]
        return None

    def get_hash_of_session_id(self, request: Request) -> str:
        if not request.state.session_id:
            return ""
        try:
            return Crypto.hash(request.state.session_id)
        except:
            return ""

    def get_hash_of_csrf_cookie(self, request: Request) -> str:
        cookie_value = self.get_csrf_cookie_value(request)
        if not cookie_value:
            return ""
        try:
            return Crypto.hash(cookie_value.split(".")[0])
        except:
            return ""

    def validate_csrf_token(self, request: Request) -> Optional[str]:
        """
        Validates the CSRF token in the `Request.state` and cookie value.

        :param Request request: the FastAPI Request

        :return: the CSRF cookie value if there is one

        :raises: :class:`crossauth_backend.CrossauthError` with
           :class:`crossauth_backend.ErrorCode` of `InvalidCsrf
        """
        self.session_manager.validate_double_submit_csrf_token(self.get_csrf_cookie_value(request) or "", request.state.csrf_token)
        return self.get_csrf_cookie_value(request)

    async def csrf_token(self, request: Request, headers: Dict[str,str]|None=None, add_cookies : Dict[str, Tuple[str, CookieOptions]]|None=None, delete_cookies : Set[str]|None=None, response : Response|None = None) -> Optional[str]:
        """
        Validates the CSRF token in the header or `csrfToken` form or JSON field
        and cookie value.

        If it is then `request.state.csrf_token` is set.  If not it is cleared.

        Does not raise an exception
        """
        token : str|None = None
        header1 = self.session_manager.csrf_header_name
        if request.headers and header1.lower() in request.headers:
            header = request.headers[header1.lower()]
            if isinstance(header, list):
                token = header[0]
            else:
                token = header

        if token is None:
            data = JsonOrFormData()
            await data.load(request)
            token = data.getAsStr("csrfToken")

        if token:
            try:
                self.session_manager.validate_double_submit_csrf_token(self.get_csrf_cookie_value(request) or "", token)
                request.state.csrf_token = token
                if (headers is not None):
                    headers[self.session_manager.csrf_header_name] = token
                if (response is not None):
                    response.headers[self.session_manager.csrf_header_name] = token
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().debug(j({"msg": ce}))
                CrossauthLogger.logger().warn(j({
                    "msg": "Invalid CSRF token",
                    "hashedCsrfCookie": self.get_hash_of_csrf_cookie(request)
                }))
                if (delete_cookies is not None):
                 delete_cookies.add(self.session_manager.csrf_cookie_name)
                if add_cookies is not None and self.session_manager.csrf_cookie_name in add_cookies:
                    del add_cookies[self.session_manager.csrf_cookie_name]
                if (response is not None):
                    response.delete_cookie(self.session_manager.csrf_cookie_name)
                request.state.csrf_token = None
        else:
            request.state.csrf_token = None

        return token

    def send_json_error(self, response: Response, status: int, error: Optional[str] = None, e: Optional[Exception] = None) -> Response:
        """
        Returns an error as a FastAPI JSONResponse object, also logging it.
        """
        if not error or not e:
            error = "Unknown error"
        ce = CrossauthError.as_crossauth_error(e) if e else None

        CrossauthLogger.logger().warn(j({
            "msg": error,
            "error_code": ce.code if ce else None,
            "error_code_name": ce.code_name if ce else None,
            "http_status": status
        }))
        return JSONResponse(
            status_code=status,
            content={
                "ok": False,
                "status": status,
                "error_message": error,
                "error_code": ce.code if ce else None,
                "error_code_name": ce.code_name if ce else None
            },
            headers={"Content-Type": "application/json; charset=utf-8"}
        )

    def error_status(self, e: Exception) -> int:
        """
        Helper function that returns the `http_status` field of an Exception,
        first casting it to a :class:`crossauth_backend.CrossauthError` (if
        it wasn't already a CrossauthError, the status will be 500).
        """
        ce = CrossauthError.as_crossauth_error(e)
        return ce.http_status

    ############################################################
    # These methods come from FastApiSessionAdapter

    def csrf_protection_enabled(self) -> bool:
        """
        See :meth:`FastApiSessionAdapter.csrf_protection_enabled
        """
        return self.enable_csrf_protection

    def get_csrf_token(self, request: Request) -> Optional[str]:
        """
        See :meth:`FastApiSessionAdapter.get_csrf_token
        """
        return request.state.csrf_token

    def get_user(self, request: Request) -> Optional[User]:
        """
        See :meth:`FastApiSessionAdapter.get_user
        """
        return request.state.user

    async def update_session_data(self, request: Request, name: str, value: Any):
        """
        See :meth:`FastApiSessionAdapter.update_session_data
        """
        if not request.state.session_id:
            raise CrossauthError(ErrorCode.Unauthorized, "User is not logged in")
        await self.session_manager.update_session_data(request.state.session_id, name, value)

    async def update_many_session_data(self, request: Request, data_array: List[KeyDataEntry]):
        """
        See :meth:`FastApiSessionAdapter.update_many_session_data
        """
        if not request.state.session_id:
            raise CrossauthError(ErrorCode.Unauthorized, "No session present")
        await self.session_manager.update_many_session_data(request.state.session_id, data_array)

    async def delete_session_data(self, request: Request, name: str):
        """
        See :meth:`FastApiSessionAdapter.delete_session_data
        """
        if not request.state.session_id:
            CrossauthLogger.logger().warn(j({"msg": "Attempt to delete session data when there is no session"}))
        else:
            await self.session_manager.delete_session_data(request.state.session_id, name)

    async def get_session_data(self, request: Request, name: str) -> Optional[Dict[str, Any]]:
        """
        See :meth:`FastApiSessionAdapter.get_session_data
        """
        try:
            data = await self.session_manager.data_for_session_id(request.state.session_id) if request.state.session_id else None
            if data and name in data:
                return data[name]
        except Exception as e:
            CrossauthLogger.logger().error(j({
                "msg": f"Couldn't get {name} from session",
                "cerr": str(e)
            }))
            CrossauthLogger.logger().debug(j({"err": str(e)}))
        return None