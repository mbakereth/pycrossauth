# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import Callable, Mapping, Optional, Dict, Any, List, cast, TypedDict, Literal
from datetime import datetime
from typing import Mapping
import json
from fastapi import Request, FastAPI, Response
from fastapi.responses import JSONResponse
from starlette.datastructures import FormData
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
        content_type = request.headers['content-type']
        if (content_type == "application/x-www-form-urlencoded" or content_type == "multipart/form-data"):
            self.__form = await request.form()
        else:
            self.__json = await request.json()

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
    """ Options for :class:`FastifySessionServer`. """

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

class FastifySessionServer:

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
    
    def __init__(self, app: FastAPI, key_storage: KeyStorage, authenticators: Mapping[str, Authenticator], options: FastApiSessionServerOptions = {}):
        self._app = app
        self._error_page = "error.jinja2"
        self._session_manager = SessionManager(key_storage, authenticators, options)
        self.__add_to_session = options['add_to_session'] if "add_to_session" in options else None
        self.__validate_session = options['validate_session'] if "validate_session" in options else None
        self._enable_csrf_protection = True

        self._session_manager = SessionManager(key_storage, authenticators, options)

        set_parameter("error_page", ParamType.String, self, options, "ERROR_PAGE", protected=True)

        @app.middleware("http")
        async def pre_handler(request: Request, call_next): # type: ignore
            CrossauthLogger.logger().debug(j({"msg": "Getting session cookie"}))
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
                response = Response()
                response.delete_cookie(self.session_manager.csrf_cookie_name)
                cookie_value = None

            response : Response = cast(Response, await call_next(request))
            if request.method in ["GET", "OPTIONS", "HEAD"]:
                try:
                    if not cookie_value:
                        CrossauthLogger.logger().debug(j({"msg": "Invalid CSRF cookie - recreating"}))
                        csrf = await self.session_manager.create_csrf_token()
                        csrf_cookie = csrf.csrf_cookie
                        csrf_form_or_header_value = csrf.csrf_form_or_header_value
                        options = toFastApiCookieOptions(csrf_cookie["options"])
                        response.set_cookie(csrf_cookie["name"], csrf_cookie["value"], **options)
                        request.state.csrf_token = csrf_form_or_header_value
                    else:
                        CrossauthLogger.logger().debug(j({"msg": "Valid CSRF cookie - creating token"}))
                        csrf_form_or_header_value = await self.session_manager.create_csrf_form_or_header_value(cookie_value)
                        request.state.csrf_token = csrf_form_or_header_value
                    response.headers[self.session_manager.csrf_header_name] = request.state.csrf_token
                except Exception as e:
                    CrossauthLogger.logger().error(j({
                        "msg": "Couldn't create CSRF token",
                        "cerr": str(e),
                        "user": request.user.username if request.user else None,
                        **report_session,
                    }))
                    CrossauthLogger.logger().debug(j({"err": str(e)}))
                    response.delete_cookie(self.session_manager.csrf_cookie_name)
            else:
                if cookie_value:
                    try:
                        await self.csrf_token(request, response)
                    except Exception as e:
                        CrossauthLogger.logger().error(j({
                            "msg": "Couldn't create CSRF token",
                            "cerr": str(e),
                            "user": request.user.username if request.user else None,
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
                    CrossauthLogger.logger().warn(j({
                        "msg": "Invalid session cookie received",
                        "hashOfSessionId": self.get_hash_of_session_id(request)
                    }))
                    response.delete_cookie(self.session_manager.session_cookie_name)

            return response

    async def create_anonymous_session(self, request: Request, response: Response, data: Optional[Dict[str, Any]] = None) -> str:
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

    def handle_error(self, e: Exception, request: Request, response: Response, error_fn: Callable[[Response, CrossauthError], None], password_invalid_ok: bool = False):
        try:
            ce = CrossauthError.as_crossauth_error(e)
            if not password_invalid_ok:
                if ce.code in [ErrorCode.UserNotExist, ErrorCode.PasswordInvalid]:
                    ce = CrossauthError(ErrorCode.UsernameOrPasswordInvalid, "Invalid username or password")
            CrossauthLogger.logger().debug(j({"err": ce}))
            CrossauthLogger.logger().error(j({
                "cerr": ce,
                "hashOfSessionId": self.get_hash_of_session_id(request),
                "user": request.user.username if request.user else None
            }))
            return error_fn(response, ce)
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return error_fn(response, CrossauthError(ErrorCode.UnknownError))

    def get_session_cookie_value(self, request: Request) -> Optional[str]:
        if request.cookies and self.session_manager.session_cookie_name in request.cookies:
            return request.cookies[self.session_manager.session_cookie_name]
        return None

    def get_csrf_cookie_value(self, request: Request) -> Optional[str]:
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
        self.session_manager.validate_double_submit_csrf_token(self.get_csrf_cookie_value(request) or "", request.state.csrf_token)
        return self.get_csrf_cookie_value(request)

    async def csrf_token(self, request: Request, response: Response) -> Optional[str]:
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
            token = data.getAsStr("csrf_token")

        if token:
            try:
                self.session_manager.validate_double_submit_csrf_token(self.get_csrf_cookie_value(request) or "", token)
                request.state.csrf_token = token
                response.headers[self.session_manager.csrf_header_name] = token
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().debug(j({"msg": ce}))
                CrossauthLogger.logger().warn(j({
                    "msg": "Invalid CSRF token",
                    "hashedCsrfCookie": self.get_hash_of_csrf_cookie(request)
                }))
                response.delete_cookie(self.session_manager.csrf_cookie_name)
                request.state.csrf_token = None
        else:
            request.state.csrf_token = None

        return token

    def send_json_error(self, response: Response, status: int, error: Optional[str] = None, e: Optional[Exception] = None) -> Response:
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
        ce = CrossauthError.as_crossauth_error(e)
        return ce.http_status

    def csrf_protection_enabled(self) -> bool:
        return self.enable_csrf_protection

    def get_csrf_token(self, request: Request) -> Optional[str]:
        return request.state.csrf_token

    def get_user(self, request: Request) -> Optional[User]:
        return request.state.user

    async def update_session_data(self, request: Request, name: str, value: Any):
        if not request.state.session_id:
            raise CrossauthError(ErrorCode.Unauthorized, "User is not logged in")
        await self.session_manager.update_session_data(request.state.session_id, name, value)

    async def update_many_session_data(self, request: Request, data_array: List[KeyDataEntry]):
        if not request.state.session_id:
            raise CrossauthError(ErrorCode.Unauthorized, "No session present")
        await self.session_manager.update_many_session_data(request.state.session_id, data_array)

    async def delete_session_data(self, request: Request, name: str):
        if not request.state.session_id:
            CrossauthLogger.logger().warn(j({"msg": "Attempt to delete session data when there is no session"}))
        else:
            await self.session_manager.delete_session_data(request.state.session_id, name)

    async def get_session_data(self, request: Request, name: str) -> Optional[Dict[str, Any]]:
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