# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import Callable, Mapping, Optional, Dict, Any, List, cast, TypedDict, Literal
from datetime import datetime
from typing import Mapping, Tuple, Set
from urllib.parse import quote 
import json
from fastapi import FastAPI, Request, Response, Form, Query #, Depends, BaseModel
from fastapi.responses import JSONResponse, RedirectResponse, HTMLResponse
from starlette.datastructures import FormData
from starlette.types import Message
from crossauth_backend.session import SessionManagerOptions
from crossauth_backend.cookieauth import  CookieOptions
from crossauth_backend.common.interfaces import User, Key, UserInputFields, OAuthClient, UserState
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.storage import KeyStorage, KeyDataEntry, UserStorage, OAuthClientStorage
from crossauth_backend.auth import Authenticator
from crossauth_backend.session import SessionManager
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.crypto import Crypto
from crossauth_fastapi.fastapisessionadapter import FastApiSessionAdapter
from nulltype import NullType
from fastapi.templating import Jinja2Templates
from .sessionbodytypes import *
from .endpoints import *

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

    user_storage: UserStorage
    """ If enabling user login, must provide the user storage """

    authenticators : Dict[str, Authenticator]
    """
    Factor 1 and 2 authenticators.
    
    The key is what appears in the `factor1` and `factor2` filed in the
    Users table.
    """

    prefix : str
    """ All endpoint URLs will be prefixed with self.  Default `/` """

    admin_prefix : str
    """ Admin URLs will be prefixed with `this  Default `admin/` """

    endpoints : List[str]
    """ List of endpoints to add to the server ("login", "api/login", etc, 
       prefixed by the `prefix` parameter.  Empty for allMinusOAuth.  Default allMinusOAuth.
    """

    login_redirect : str
    """ Page to redirect to after successful login, default "/" """

    logout_redirect : str
    """ Page to redirect to after successful logout, default "/" """

    validate_user_fn: Callable[[UserInputFields], List[str]]
    """ Function that raises a :class: crossauth_backend.common.CrossauthError} 
    with :class: crossauth_backend.common.ErrorCode `FormEnty` if the user 
    doesn't confirm to local rules.  Doesn't validate passwords
    """

    create_user_fn: Callable[[Request, List[str], List[str]], UserInputFields]
    """
    Function that creates a user from form fields.
    Default one takes fields that begin with `user_`, removing the `user_` 
    prefix and filtering out anything not in the userEditableFields list in 
    the user storage.
    """

    update_user_fn: Callable[[User, Request, List[str]], User]
    """
    Function that updates a user from form fields.
    Default one takes fields that begin with `user_`, removing the `user_`
     prefix and filtering out anything not in the userEditableFields list in 
    the user storage.
    """

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

    login_page : str
    """
    Template file containing the login page (with without error messages).  
    See the class documentation for {@link FastifyServer} for more info.  
    Defaults to "login.njk".
    """

    factor2_page: str
    """
    Template file containing the page for getting the 2nd factor for 2FA 
    protected pages.  See the class documentation for {@link FastifyServer} 
    for more info.  Defaults to "factor2.njk".
    """

    signup_page : str
    """
    Template file containing the signup page (with without error messages).  
    See the class documentation for {@link FastifyServer} for more info. 
    Defaults to "signup.njk".
    Signup form should contain at least `username` and `password` and may
    also contain `repeatPassword`.  If you have additional
    fields in your user table you want to pass from your form, prefix 
    them with `user_`, eg `user_email`.
    If you want to enable email verification, set `enableEmailVerification` 
    and set `checkEmailVerified` on the user storage.
    """

    configure_factor2_page: str
    """ Page to set up 2FA after sign up """

    delete_user_page: str
    """ Confirm deleting a user """

    """ Confirm deleting an OAuth client """
    delete_client_page: str

    error_page : str
    """
    Page to render error messages, including failed login. 
    See the class documentation for :class:`FastApiServer` for more info.  
    Defaults to "error.jinja2".
    """

    change_password_page: str
    """ Page to render for password changing.  
    See the class documentation for {@link FastifyServer} for more info.  
    efaults to "changepassword.njk".
    """

    change_factor2_page: str
    """ Page to render for selecting a different 2FA.  
    See the class documentation for {@link FastifyServer} for more info.  
    efaults to "changepassword.njk".
    """

    update_user_page: str
    """ Page to render for updating user details.  
    See the class documentation for {@link FastifyServer} for more info.  
    efaults to "updateuser.njk".
    """

    request_reset_password_page: str
    """ Page to ask user for email and reset his/her password.  
    See the class documentation for {@link FastifyServer} for more info.  
    efaults to "requestpasswordreset.njk".
    """

    reset_password_page: str
    """ Page to render for password reset, after the emailed token has been 
    validated.  
    ee the class documentation for {@link FastifyServer} for more info.  
    efaults to "resetpassword.njk".
    """

    enable_email_verification: bool
    """
    Turns on email verification.  This will cause the verification tokens to 
    e sent when the account
    s activated and when email is changed.  Default false.
    """

    email_verified_page: str
    """ Page to render for to confirm email has been verified.  Only created 
    if `enableEmailVerification` is true.
    ee the class documentation for {@link FastifyServer} for more info.  
    efaults to "emailverified.njk"
    """

    factor2_protected_page_endpoints: List[str]
    """
    These page endpoints need the second factor to be entered.  Visiting
    the page redirects the user to the factor2 page.
        You probably want to do this for things like changing password.  The
    default is
     `/requestpasswordreset`,
     `/updateuser`,
     `/changepassword`,
     `/resetpassword`,
     `/changefactor2`,
    """

    factor2_protected_api_endpoints: List[str]
    """
    These page endpoints need the second factor to be entered.  Making
    a call to these endpoints results in a response of 
    {"ok": true, "factor2Required": true `}.  The user should then
    make a call to `/api/factor2`.   If the credetials are correct, the
    response will be that of the original request.
        You probably want to do this for things like changing password.  The
    default is
     `/api/requestpasswordreset`,
     `/api/updateuser`,
     `/api/changepassword`,
     `/api/resetpassword`,
     `/api/changefactor2`,
    """

    edit_user_scope: str
    """
    This parameter affects users who are not logged in with a session ID
    ut with an OAuth access token.  Such users can only update their user
    ecord if the scoped named in this variable has been authorized by
    hat user for the client.
        y default, no scopes are authorized to edit the user.
    """

    ###################################
    ## Admin pages

    """
    If true, all administrator endpoints will be enabled.
    If you explicitly name which endpoints to enable with the `endpoints`
    option, this is ignored.
    default false.
    """
    enable_admin_endpoints: bool

    enable_oauth_client_management: bool
    """
    If true, all endpoints for managing OAuth clients (including 
    he admin ones if `enableAdminEndpoints` is also true).
    If you explicitly name which endpoints to enable with the `endpoints`
    option, this is ignored.
    Default false
    """

    admin_create_user_page: str
    """
    The temaplte file for the admin create user page.
        Default `admin/createuser.njk`
    """

    admin_select_user_page: str
    """
    The temaplte file for the admin selecting a user.
    Default `admin/selectuser.njk`
    """

    admin_create_client_page: str
    """
    The temaplte file for the admin creating a user.
    Default `admin/createuser.njk`
    """

    user_search_fn : Callable[[str, UserStorage], List[User]]
    """
    Admin pages provide functionality for searching for users.  By
    default the search string must exactly match a username or
    email address (depending on the storage, after normalizing
    and lowercasing).  Override this behaviour with this function
    :param searchTerm the search term 
    :param userStorage the user storage to search
    :return array of matching users
    """

    client_serach_dn: Callable[[str, OAuthClientStorage, str|int|NullType], List[OAuthClient]]
    """
    Admin pages provide functionality for searching for OAuth clients.  By
    default the search string must exactly match the `client_name`.
    Override this behaviour with this function
    :param searchTerm the search term 
    :param clientStorage the client storage to search
    :param userid if defined and non null, only clients owned by that
           user ID will be returned.  If `null`, only clients not owned
           by a user will be returned.  If undefined, all matching clients
           will be returned
    :return array of matching clients
    """

    user_allowed_factor1: List[str]
    """
    When signing up themselves, users may choose any of these.
    Default: ["localpassword"]
    """

    admin_allowed_factor1: List[str]
    """
    When admins create a user, they may choose any of these.
    Default: ["localpassword"]
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

    @property
    def user_allowed_factor1(self):
        return self.__user_allowed_factor1
    
    @property
    def admin_allowed_factor1(self):
        return self.__admin_allowed_factor1

    @property
    def allowed_factor2(self):
        return self.__allowed_factor2

    @property
    def templates(self): return self._templates

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
        self.__user_allowed_factor1 = ["localpassword"]
        self.__admin_allowed_factor1 = ["localpassword"]
        self.__login_redirect = "/"
        self.__logout_redirect = "/"
        self.__allowed_factor2 : List[str] = []

        self._session_manager = SessionManager(key_storage, authenticators, options)

        self.__template_dir = "templates"

        set_parameter("error_page", ParamType.String, self, options, "ERROR_PAGE", protected=True)
        set_parameter("prefix", ParamType.String, self, options, "PREFIX")
        if not self.__prefix.endswith("/"): self.__prefix += "/"

        self.___endpoints : List[str] = []
        self.__signup_page: str = "signup.njk"
        self.__login_page: str = "login.njk"
        self.__factor2_page: str = "factor2.njk"
        self.__configure_factor2_page: str = "configurefactor2.njk"

        #self.__user_endpoints: FastifyUserEndpoints
        #self.__admin_endpoints: FastifyAdminEndpoints
        #self.__admin_client_endpoints: Optional[FastifyAdminClientEndpoints] = None
        #self.__user_client_endpoints: Optional[fastify_user_client_endpoints] = None

        self.__enable_email_verification: bool = True
        self.__enable_password_reset: bool = True
        self.__enable_admin_endpoints: Optional[bool] = False
        self.__enable_oauth_client_management: Optional[bool] = False
        self.__factor2_protected_page_endpoints: List[str] = [
            "/requestpasswordreset",
            "/updateuser",
            "/changepassword",
            "/resetpassword",
            "/changefactor2",
        ]
        self.__factor2_protected_api_endpoints: List[str] = [
            "/api/requestpasswordreset",
            "/api/updateuser",
            "/api/changepassword",
            "/api/resetpassword",
            "/api/changefactor2",
        ]
        self.__edit_user_scope: Optional[str] = None

        set_parameter("signup_page", ParamType.String, self, options, "SIGNUP_PAGE")
        set_parameter("login_page", ParamType.String, self, options, "LOGIN_PAGE")
        set_parameter("factor2_page", ParamType.String, self, options, "FACTOR2_PAGE")
        set_parameter("configure_factor2_page", ParamType.String, self, options, "SIGNUP_FACTOR2_PAGE")
        set_parameter("error_page", ParamType.String, self, options, "ERROR_PAGE", protected=True)
        set_parameter("allowed_factor2", ParamType.JsonArray, self, options, "ALLOWED_FACTOR2")
        set_parameter("enable_email_verification", ParamType.Boolean, self, options, "ENABLE_EMAIL_VERIFICATION")
        set_parameter("enable_password_reset", ParamType.Boolean, self, options, "ENABLE_PASSWORD_RESET")
        set_parameter("factor2_protected_page_endpoints", ParamType.JsonArray, self, options, "FACTOR2_PROTECTED_PAGE_ENDPOINTS")
        set_parameter("factor2_protected_api_endpoints", ParamType.JsonArray, self, options, "FACTOR2_PROTECTED_API_ENDPOINTS")
        set_parameter("enable_admin_endpoints", ParamType.Boolean, self, options, "ENABLE_ADMIN_ENDPOINTS")
        set_parameter("enable_oauth_client_management", ParamType.Boolean, self, options, "ENABLE_OAUTH_CLIENT_MANAGEMENT")
        set_parameter("edit_user_scope", ParamType.String, self, options, "EDIT_USER_SCOPE")
        set_parameter("user_allowed_factor1", ParamType.JsonArray, self, options, "USER_ALLOWED_FACTOR1")
        set_parameter("admin_allowed_factor1", ParamType.JsonArray, self, options, "ADMIN_ALLOWED_FACTOR1")
        set_parameter("login_redirect", ParamType.JsonArray, self, options, "LOGIN_REDIRECT")
        set_parameter("logout_redirect", ParamType.JsonArray, self, options, "LOGOUT_REDIRECT")
        set_parameter("template_dir", ParamType.String, self, options, "TEMPLATE_DIR")
        self._templates = Jinja2Templates(directory=self.__template_dir)

        if ("validate_user_fn" in options): self.__validate_user_fn = options["validate_user_fn"]
        if ("create_user_fn" in options): self.create_user_fn = options["create_user_fn"]
        if ("update_user_fn" in options): self.update_user_fn = options["update_user_fn"]
        if ("add_to_session" in options): self.add_to_session = options["add_to_session"]
        if ("validate_session" in options): self.validate_session = options["validate_session"]

        self.__endpoints : List[str] = [*SignupPageEndpoints, *SignupApiEndpoints]
        self.__endpoints = [*self.__endpoints, *SessionPageEndpoints, *SessionApiEndpoints]
        if (self.__enable_admin_endpoints): self.__endpoints = [*self.__endpoints, *SessionAdminPageEndpoints, *SessionAdminApiEndpoints]
        if (self.__enable_oauth_client_management): self.__endpoints = [*self.__endpoints, *SessionClientPageEndpoints, *SessionClientApiEndpoints, *SessionAdminClientPageEndpoints, *SessionAdminClientApiEndpoints]
        if (self.__enable_email_verification): self.__endpoints = [*self.__endpoints, *EmailVerificationPageEndpoints, *EmailVerificationApiEndpoints]
        if (self.__enable_password_reset): self.__endpoints = [*self.__endpoints, *PasswordResetPageEndpoints, *PasswordResetApiEndpoints]
        if ("endpoints" in options):
            set_parameter("endpoints", ParamType.JsonArray, self, options, "SESSION_ENDPOINTS");
            if (len(self.__endpoints) == 1 and self.__endpoints[0] == "all"): self.__endpoints = AllEndpoints
            if (len(self.__endpoints) == 1 and self.__endpoints[0] == "allMinusOAuth"): self.__endpoints = AllEndpointsMinusOAuth
        
        if (len(self.__allowed_factor2) > 0): self.__endpoints = [*self.__endpoints, *Factor2PageEndpoints, *Factor2ApiEndpoints]

        add_admin_client_endpoints = False
        for endpoint in self.__endpoints:
            if (endpoint in SessionAdminClientApiEndpoints or
                endpoint in SessionAdminClientPageEndpoints):
                    add_admin_client_endpoints = True
                    break
                
        
        if (add_admin_client_endpoints):
            #self.__admin_client_endpoints = new FastifyAdminClientEndpoints(this, options);
            pass
        

        add_user_client_endpoints = False
        for endpoint in self.__endpoints:
            if (endpoint in SessionClientApiEndpoints or
                endpoint in SessionClientPageEndpoints):
                    add_user_client_endpoints = True
                    break
                
        
        if (add_user_client_endpoints):
            #self.__user_client_endpoints = new fastify_user_client_endpoints(self, options);
            pass        

        self.add_endpoints()


        set_parameter("endpoints", ParamType.JsonArray, self, options, "ENDPOINTS")

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
                        if (ret.user is not None): user = ret.user
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
        if (session_cookie is None or csrf_cookie is None or csrf_form_or_header_value is None):
            raise CrossauthError(ErrorCode.InvalidSession, "Failed to get session and/CSRF cookie")
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

    def handle_error(self, e: Exception, request: Request, body: BaseModel, error_fn: Callable[[BaseModel, CrossauthError], HTMLResponse], password_invalid_ok: bool = False) -> Response:
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
            return error_fn(body, ce)
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return error_fn(body, CrossauthError(ErrorCode.UnknownError))

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
            if (token is None):
                token = data.getAsStr("csrf_token")


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
    
    def add_endpoints(self):
        pass

    ############################3
    ## page endpoints


    def add_login_endpoints(self):
        @self.app.get(self.__prefix + 'login')
        async def get_login( # type: ignore
            request: Request,
            next_param: Optional[str] = Query(None, alias="next")
        ):
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "GET",
                "url": self.__prefix + "login",
                "ip": request.client.host if request.client is not None else ""
            }))
            
            # Check if user is already logged in (assuming request.user is set via dependency or middleware)
            user = getattr(request.state, 'user', None)
            if user:
                redirect_url = next_param or self.__login_redirect
                return RedirectResponse(url=redirect_url, status_code=302)
            
            # Get CSRF token (assuming it's available via request state or dependency)
            csrf_token = getattr(request.state, 'csrf_token', None)
            
            data: Dict[str, Any] = {
                "urlPrefix": self.__prefix,
                "csrfToken": csrf_token
            }
            
            if next_param:
                data["next"] = next_param
            
            return self.templates.TemplateResponse(self.__login_page, {"request": request, **data})

        @self.app.post(self.__prefix + 'login')
        async def post_login( # type: ignore
            request: Request,
            next_param: Optional[str] = Form(None, alias="next"),
            persist: bool = Form(False),
            username: str = Form("")
        ):
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + "login",
                "ip": request.client.host if request.client else ""
            }))
            
            next_redirect = (next_param if next_param and len(next_param) > 0 
                           else self.__login_redirect)
            
            # Create request body equivalent
            body = LoginBodyType(next=next_param, persist=persist, username=username,)
            
            try:
                return await self.login(request, body, 
                    lambda body1, user: self._handle_login_response(request, body, user, next_redirect))
            except Exception as e:
                CrossauthLogger.logger().debug(j({"err": str(e)}))
                return self.handle_error(e, request, body, 
                    lambda error, ce: self._render_login_error_page(request, body, ce, next_redirect))

    def _handle_login_response(self, request: Request, body: LoginBodyType, user: User, next_redirect: str) -> Response|None:
        
        if user["state"] == UserState.password_change_needed:
            if "changepassword" in self.__endpoints:
                CrossauthLogger.logger().debug(j({"msg": "Password change needed - sending redirect"}))
                redirect_url = f"/changepassword?required=true&next={quote(f'login?next={next_redirect}')}"
                return RedirectResponse(url=redirect_url, status_code=302)
            else:
                ce = CrossauthError(ErrorCode.PasswordChangeNeeded)
                return self.handle_error(ce, request, body, 
                    lambda error, ce: self._render_login_error_page(request, body, ce, next_redirect))

        elif (user["state"] == UserState.password_reset_needed or 
              user["state"] == UserState.password_and_factor2_reset_needed):
            CrossauthLogger.logger().debug(j({"msg": "Password reset needed - sending error"}))
            ce = CrossauthError(ErrorCode.PasswordResetNeeded)
            return self.handle_error(ce, request, body, 
                lambda error, ce: self._render_login_error_page(request, body, ce, next_redirect))

        elif (len(self.allowed_factor2) > 0 and 
              (user["state"] == UserState.factor2_reset_needed or 
               not (user["factor2"] if "factor2" in user else "none") in self.allowed_factor2)):
            CrossauthLogger.logger().debug(j({
                "msg": f"Factor2 reset needed. Factor2 is {user["factor2"] if "factor2" in user else ""}, state is {user["state"]}, allowed factor2 is [{', '.join(self.allowed_factor2)}]",
                "username": user["username"]
            }))
            if "changefactor2" in self.__endpoints:
                CrossauthLogger.logger().debug(j({"msg": "Factor 2 reset needed - sending redirect"}))
                redirect_url = f"/changefactor2?required=true&next={quote(f'login?next={next_redirect}')}"
                return RedirectResponse(url=redirect_url, status_code=302)
            else:
                ce = CrossauthError(ErrorCode.Factor2ResetNeeded)
                return self.handle_error(ce, request, body, 
                    lambda error, ce: self._render_login_error_page(request, body, ce, next_redirect))

        elif not "factor2" not in user or ("factor2" in user and len(user["factor2"])) == 0:
            CrossauthLogger.logger().debug(j({"msg": "Successful login - sending redirect"}))
            return RedirectResponse(url=next_redirect, status_code=302)
        else:
            data : Dict[str,Any]= {
                "csrfToken": cast(str|None, getattr(request.state, 'csrf_token', None)),
                "next": body.next or self.__login_redirect,
                "persist": "on" if body.persist else "",
                "urlPrefix": self.__prefix,
                "factor2": user["factor2"] if "factor2" in user else "",
                "action": "loginfactor2"
            }
            return self.templates.TemplateResponse(self.__factor2_page, {"request": request, **data})

    def _render_login_error_page(self, request: Request, body: LoginBodyType, error: CrossauthError, next_redirect: str) -> HTMLResponse:
        csrf_token = getattr(request.state, 'csrf_token', None)
        return self.templates.TemplateResponse(self.__login_page, {
            "request": request,
            "errorMessage": error.message,
            "errorMessages": error.messages,
            "errorCode": error.code,
            "errorCodeName": error.code.value,
            "next": next_redirect,
            "persist": body.persist,
            "username": body.username,
            "csrfToken": csrf_token,
            "urlPrefix": self.__prefix
        })

    # These methods need to be implemented in your class:
    async def login(self, request: Request, body: LoginBodyType, success_callback: Callable[[BaseModel, User], Response|None]) -> Any:
        """
        This method needs to be implemented with your actual login logic.
        It should call success_callback(user) on successful authentication.
        """
        raise NotImplementedError("login method must be implemented")
