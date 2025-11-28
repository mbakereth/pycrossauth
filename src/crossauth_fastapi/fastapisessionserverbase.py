from abc import abstractmethod
from datetime import datetime
from fastapi import Request, FastAPI, Response
from fastapi.responses import JSONResponse
from typing import Optional, Any, Dict, Callable, List, Mapping, Tuple, Literal, Set
from fastapi.templating import Jinja2Templates
from nulltype import NullType
from starlette.datastructures import FormData
from crossauth_fastapi.fastapisessionadapter import FastApiSessionAdapter
from crossauth_backend.common.interfaces import User, UserInputFields, Key
from crossauth_backend.common.error import CrossauthError, ErrorCode
from .sessionendpoints import *
from .sessionbodytypes import *
from crossauth_backend.session import SessionManager
from crossauth_backend.auth import Authenticator
from crossauth_backend.storage import UserStorage, OAuthClientStorage, OAuthClient
from crossauth_backend.session import SessionManagerOptions

class FastApiSessionServerOptions(SessionManagerOptions, total=False):
    """ Options for :class:`FastApiSessionServer`. """

    """
    If enabling user login, must provide the user storage
    """
    user_storage : UserStorage

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

    create_user_fn: Callable[[Request, Dict[str, Any], List[str], List[str]], UserInputFields]
    """
    Function that creates a user from form fields.
    Default one takes fields that begin with `user_`, removing the `user_` 
    prefix and filtering out anything not in the userEditableFields list in 
    the user storage.
    """

    update_user_fn: Callable[[User, Request, Dict[str, Any], List[str]], User]
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
    If you want to enable email verification, set `enable_email_verification` 
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

JSONHDR : List[str] = ['Content-Type', 'application/json; charset=utf-8']
JSONHDRMAP = {'Content-Type': 'application/json; charset=utf-8'}

def cookies_from_response(response : Response) -> Dict[str, str]:
    headers = response.headers
    cookies : Dict[str,str] = {}
    if ('set-cookie' in headers):
        for pair in headers.getlist('set-cookie'):
            res = pair.split("=", 2)
            cookies[res[0]] = res[1]
    return cookies

def json_response(content: Dict[str, Any], resp: Response, status_code : int = 200, headers : Dict[str,str]|None=None) -> JSONResponse:
    r = JSONResponse(content, status_code=status_code)
    if (headers is not None):
        for h in headers:
            r.headers[h] = headers[h]
    else:
        for h in JSONHDRMAP:
            r.headers[h] = JSONHDRMAP[h]
    cookies = cookies_from_response(resp)
    for c in cookies:
        r.set_cookie(c, cookies[c])
    return r

def redirect(url: str, response: Response, request: Request, status_code: int=302) -> Response:
    #resp =  RedirectResponse(url=redirect_url, status_code=status_code)
    response.headers["Location"] = url
    response.status_code = status_code

    try:
        if (request.state.delete_cookies):
            dcookies: Set[str] = request.state.delete_cookies
            for name in dcookies:
                response.delete_cookie(name)
    except:
        pass

    try:
        if (request.state.set_cookies):
            cookies: Dict[str, Tuple[str, FastApiCookieOptions]] = request.state.set_cookies
            for name in cookies:
                response.set_cookie(name, cookies[name][0], **(cookies[name][1]))
    except:
        pass
    return response 

class FastApiCookieOptions(TypedDict, total=True):
    max_age: int|None
    expires: datetime|str|int|None
    path: str|None
    domain: str|None
    secure: bool
    httponly: bool
    samesite: Literal['lax', 'strict', 'none'] | None

def template_response(templates: Jinja2Templates, request: Request, response: Response, page: str, body: Dict[str,Any], status:int|None = None ) -> Response:
    if (status is None):
        r = templates.TemplateResponse(request, page, body)
    else:
        r = templates.TemplateResponse(request, page, body, status)
    cookies = cookies_from_response(response)
    for c in cookies:
        r.set_cookie(c, cookies[c])
    return r

def send_with_cookies(response : Response, request: Request) -> Response:
    try:
        if (request.state.delete_cookies):
            dcookies: Set[str] = request.state.delete_cookies
            for name in dcookies:
                response.delete_cookie(name)
    except:
        pass
    try:
        if (request.state.set_cookies):
            cookies: Dict[str, Tuple[str, FastApiCookieOptions]] = request.state.set_cookies
            for name in cookies:
                response.set_cookie(name, cookies[name][0], **(cookies[name][1]))
    except:
        pass
    return response

class JsonOrFormData:
    def __init__(self, request : Request, body: bytes|None = None):
        self.__request = request
        self.__form : FormData | None = None
        self.__json : Dict[str, Any] = {}

    def to_dict(self) -> Dict[str,Any]:
        if (self.__form):
            return self.__form.__dict__["_dict"]
        return self.__json
            
    # def __dict__(self) -> Dict[str,Any]:
    #     if (self.__form): 
    #         return self.__form.__dict__
    #     return self.__json
    
    async def load(self):
        content_type = self.__request.headers['content-type'] if 'content-type' in self.__request.headers else "text/plain"
        # body = await request.body()
        # async def receive() -> Message:
        #     return {"type": "http.request", "body": body}
        # request._receive = receive # type: ignore
        try:
            if (content_type == "application/x-www-form-urlencoded" or content_type == "multipart/form-data"):
                self.__form = await self.__request.form()
            else:
                self.__json = await self.__request.json()
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

    def has(self, name : str):
        if (self.__form): 
            if (name not in self.__form): return False
            return True
        elif (self.__json): 
            return name in self.__json
        return False

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
    
    def getAsStr1(self, name : str, default: str) -> str:
        val = self.getAsStr(name, default)
        return val if val is not None else ""

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
    
    def getAsBool1(self, name : str, default: bool) -> bool:
        val = self.getAsBool(name, default)
        return val if val is not None else False

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

    def getAsInt1(self, name : str, default: int) -> int:
        val = self.getAsInt(name, default)
        return val if val is not None else 0

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
    def getAsFloat1(self, name : str, default: float) -> float:
        val = self.getAsFloat(name, default)
        return val if val is not None else 0.0

class FastApiSessionServerBase(FastApiSessionAdapter):

    @property
    @abstractmethod
    def app(self) -> FastAPI:
        pass

    @property
    @abstractmethod
    def templates(self) -> Jinja2Templates: 
        pass

    @property
    @abstractmethod
    def session_manager(self) -> SessionManager:
        pass

    @property
    @abstractmethod
    def login_redirect(self) -> str:
        pass

    @property
    @abstractmethod
    def enable_email_verification(self) -> bool:
        pass

    @property
    @abstractmethod
    def authenticators(self) -> Mapping[str, Authenticator]:
        pass

    @property
    @abstractmethod
    def user_storage(self) -> UserStorage|None:
        pass

    @abstractmethod
    def allowed_factor2_details(self) -> List[AuthenticatorDetails]:
        pass

    @property
    @abstractmethod
    def allowed_factor2(self) -> List[str]:
        pass

    @property
    @abstractmethod
    def error_page(self) -> str:
        pass
    
    @abstractmethod
    def can_edit_user(self, request: Request) -> bool:
        pass

    @abstractmethod
    def send_json_error(self, request: Request, response: Response, status: int, error: Optional[str] = None, e: Optional[Exception] = None) -> Response:
        pass

    @abstractmethod
    def send_page_error(self, request: Request, response: Response, status: int, error: Optional[str] = None, e: Optional[Exception] = None) -> Response:
        pass

    @abstractmethod
    def handle_error(self, e: Exception, request: Request, form: JsonOrFormData|None, error_fn: Callable[[Dict[str,Any], CrossauthError], Response], password_invalid_ok: bool = False) -> Response:
        pass

    @abstractmethod
    def error_status(self, e: Exception) -> int:
        pass

    @abstractmethod
    def is_session_user(self, request: Request) -> bool:
        pass

    @abstractmethod
    async def get_session_data(self, request: Request, name: str) -> Optional[Dict[str, Any]]:
        pass


    @abstractmethod
    async def login_with_user(self, 
            user : User,
            bypass_2fa: bool,
            request: Request,
            resp: Response,
            success_fn: Callable[[Response, User], Response]) -> Response:
        pass

    create_user_fn : Callable[[Request, Dict[str, Any], List[str], List[str]], UserInputFields]
    update_user_fn : Callable[[User, Request, Dict[str, Any], List[str]], User]
    validate_user_fn : Callable[[UserInputFields], List[str]]
    