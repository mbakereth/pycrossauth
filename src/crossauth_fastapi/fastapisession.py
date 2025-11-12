# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import Callable, Mapping, Optional, Dict, Any, List, cast
from datetime import datetime
from typing import Mapping, Tuple, Set
from urllib.parse import quote 
import json
from fastapi import FastAPI, Request, Response, Query #, Depends, BaseModel
from fastapi.responses import JSONResponse, RedirectResponse
from crossauth_backend.cookieauth import  CookieOptions
from crossauth_backend.auth import AuthenticationParameters
from crossauth_backend.common.interfaces import User, UserInputFields, UserState, UserSecrets
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.storage import KeyStorage, KeyDataEntry
from crossauth_backend.auth import Authenticator
from crossauth_backend.session import SessionManager
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.crypto import Crypto
from crossauth_fastapi.fastapisessionserverbase import *
from .sessionbodytypes import *
from .sessionendpoints import *
import copy
from starlette.types import Message # , ASGIApp, Scope, Receive, Send
from .sessionendpoints import *
from .fastapiserverbase import FastApiServerBase
from .fastapiuserendpoints import FastApiUserEndpoints

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

async def set_body(request: Request, body: bytes):
    async def receive() -> Message:
        return {"type": "http.request", "body": body}
    request._receive = receive # type: ignore

async def get_body(request: Request) -> bytes:
    body = await request.body()
    await set_body(request, body)
    return body

async def create_body(request : Request) -> Message:
    return {
        'type': 'http.request',
        'body': await get_body(request),
        'more_body': False,
    }

def default_create_user(
    request: Request,
    body: Dict[str, Any],
    userEditableFields: List[str],
    allowableFactor1: List[str]
) -> UserInputFields:
    """
    Default function for creating users.  Can be overridden.
    
    Takes any field beginning with `user_` and that is also in
    `userEditableFields` (without the `user_` prefix).
    
    :param request: the fastify request
    :param userEditableFields: the fields a user may edit
    :param allowableFactor1: allowable factor1 values
    :returns: the new user
    """
    state = "active"
    user: UserInputFields = {
        "username": body["username"],
        "state": state,
        "factor1": "localpassword"
    }
    callerIsAdmin = request.state.user and FastApiServerBase.is_admin(request.state.user)
    for field in body:
        name = field.replace("user_", "", 1) if field.startswith("user_") else field
        if field.startswith("user_") and (callerIsAdmin or name in userEditableFields):
            user[name] = body[field]
    
    if "factor1" in body and body["factor1"] in allowableFactor1:
        user["factor1"] = body["factor1"]
    elif len(allowableFactor1) == 1:
        user["factor1"] = allowableFactor1[0]
    else:
        raise CrossauthError(ErrorCode.BadRequest, "factor1 not given in user")
    
    if "factor2" in body:
        user["factor2"] = "" if body["factor2"] is None else body["factor2"] 
    return user


def default_update_user(
    user: User,
    request: Request,
    body: Dict[str, Any],
    userEditableFields: List[str]
) -> UserInputFields:
    """
    Default function for creating users.  Can be overridden.
    
    Takes any field beginning with `user_` and that is also in
    `userEditableFields` (without the `user_` prefix).
    
    :param user: the user to update
    :param request: the fastify request
    :param userEditableFields: the fields a user may edit
    :returns: the new user
    """
    callerIsAdmin = request.state.user and FastApiServerBase.is_admin(request.state.user)
    for field in body:
        name = field.replace("user_", "", 1) if field.startswith("user_") else field
        if field.startswith("user_") and (callerIsAdmin or name in userEditableFields):
            user[name] = body[field]
    
    return user

def default_user_validator(user : UserInputFields) -> List[str]:
    """
    Default User validator.  Doesn't validate password

    Username must be at least two characters.
    :param password The password to validate
    :return an array of errors.  If there were no errors, returns an empty array
    """
    errors : List[str] = []
    if ("username" not in user):
        errors.append("Username must be given")
    elif (cast(Dict[str,Any], user)["username"] is None):
        errors.append("Username must be given")
    elif (len(user["username"]) < 2):
        errors.append("Username must be at least 2 characters");
    elif (len(user["username"]) > 254):
        errors.append("Username must be no longer than 254 characters");
    
    return errors


class FastApiSessionServer(FastApiSessionServerBase):
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
    def login_redirect(self):
        return self.__login_redirect
    
    @property
    def user_storage(self):
        return self.__user_storage

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
    def enable_email_verification(self) -> bool:
        return self.__enable_email_verification

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
    def authenticators(self):
        return self.__authenticators

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
        self.__user_endpoints = FastApiUserEndpoints(self, options)

        self._session_manager = SessionManager(key_storage, authenticators, options)
        self.__add_to_session = options['add_to_session'] if "add_to_session" in options else None
        self.__validate_session = options['validate_session'] if "validate_session" in options else None
        self._enable_csrf_protection = True
        self.__user_allowed_factor1 = ["localpassword"]
        self.__admin_allowed_factor1 = ["localpassword"]
        self.__login_redirect = "/"
        self.__logout_redirect = "/"
        self.__allowed_factor2 : List[str] = ["none"]
        self.__authenticators = authenticators

        self._session_manager = SessionManager(key_storage, authenticators, options)

        self.__template_dir = "templates"
        self.__user_storage = options["user_storage"] if "user_storage" in options else None
        

        set_parameter("error_page", ParamType.String, self, options, "ERROR_PAGE", protected=True)
        set_parameter("prefix", ParamType.String, self, options, "PREFIX")
        if not self.__prefix.endswith("/"): self.__prefix += "/"

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

        self.create_user_fn = default_create_user
        self.update_user_dn = default_update_user
        self.validate_user_fn = default_user_validator
        if ("validate_user_fn" in options): self.validate_user_fn = options["validate_user_fn"]
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
            set_parameter("endpoints", ParamType.JsonArray, self, options, "SESSION_ENDPOINTS")
            if (len(self.__endpoints) == 1 and self.__endpoints[0] == "all"): self.__endpoints = AllEndpoints
            if (len(self.__endpoints) == 1 and self.__endpoints[0] == "allMinusOAuth"): self.__endpoints = AllEndpointsMinusOAuth
        
        if (len(self.__allowed_factor2) > 0): 
            actual_factor2 = list(filter(lambda x: x != "" and x != "none", self.__allowed_factor2))
            if (len(actual_factor2) > 0):
                self.__endpoints = [*self.__endpoints, *Factor2PageEndpoints, *Factor2ApiEndpoints]

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

        # 2FA for endpoints that are protected by this (other than login)
        @app.middleware("http")
        async def pre_handler_2fa(request: Request, call_next): # type: ignore
            CrossauthLogger.logger().debug(j({"msg": "2FA middleware"}))

            session_cookie_value = self.get_session_cookie_value(request)
            
            if (session_cookie_value and 
                request.state.user and
                "factor2" in request.state.user and
                request.state.user["username"] != "" and
                (request.url.path in self.__factor2_protected_page_endpoints or 
                request.url.path in self.__factor2_protected_api_endpoints)):
                
                session_id = self.session_manager.get_session_id(session_cookie_value)
                
                if request.method not in ["GET", "OPTIONS", "HEAD"]:
                    session_data = await self.session_manager.data_for_session_id(session_id)
                    if (session_data is None): session_data = {}
                    
                    if "pre2fa" in session_data:
                        # 2FA has started - validate it
                        CrossauthLogger.logger().debug("Completing 2FA")

                        # get secrets from the request body 
                        authenticator = self.__authenticators[session_data["pre2fa"]["factor2"]]
                        # const secretNames = [...authenticator.secretNames(), 
                        #     ...authenticator.transientSecretNames()];
                        secret_names = [*authenticator.transient_secret_names()]
                        secrets: Dict[str, str] = {}
                        
                        # Extract request body data
                        await set_body(request, await request.body())
            
                        req = Request(
                            scope=request.scope,
                            receive=lambda : create_body(request),  # <-------- Pass it here
                        )
                        form = JsonOrFormData(req)
                        
                        for field in form.to_dict():
                            if field in secret_names:
                                secrets[field] = form.getAsStr1(field, "")

                        # const sessionCookieValue = this.getSessionCookieValue(request);
                        # if (!sessionCookieValue) throw new CrossauthError(ErrorCode.Unauthorized, "No session cookie found");
                        error: Optional[CrossauthError] = None
                        try:
                            # await this.sessionManager.completeTwoFactorPageVisit(request.body, sessionCookieValue);
                            await self.session_manager.complete_two_factor_page_visit(cast(AuthenticationParameters,secrets), session_id)
                        except Exception as e:
                            error = CrossauthError.as_crossauth_error(e)
                            CrossauthLogger.logger().debug(j({"err": str(e)}))
                            ce = CrossauthError.as_crossauth_error(e)
                            CrossauthLogger.logger().error(j({
                                "msg": error.message,
                                "cerr": str(e),
                                "user": form.getAsStr1("username", ""),
                                "errorCode": ce.code.value,
                                "errorCodeName": ce.code.name
                            }))
                        
                        # restore original request body
                        await set_body(request, json.dumps(session_data["pre2fa"]["body"]).encode())
                        
                        if error:
                            if error.code == ErrorCode.Expired:
                                # user will not be able to complete this process - delete 
                                CrossauthLogger.logger().debug("Error - cancelling 2FA")
                                # the 2FA data and start again
                                try:
                                    await self.session_manager.cancel_two_factor_page_visit(session_id)
                                except Exception as e:
                                    CrossauthLogger.logger().error(j({
                                        "msg": "Failed cancelling 2FA", 
                                        "cerr": str(e), 
                                        "user": form.getAsStr1("username", ""), 
                                        "hashOfSessionId": self.get_hash_of_session_id(request)
                                    }))
                                    CrossauthLogger.logger().debug(j({"err": str(e)}))
                                
                                self.handle_error(error, request, form,          
                                    lambda error, ce: self._render_login_error_page(request, response, form, ce, ""))

                                # await set_body(request, json.dumps({
                                #     **(session_data["pre2fa"]["body"]),
                                #     "errorMessage": error.message,
                                #     "errorMessages": error.message,
                                #     "errorCode": str(error.code.value),
                                #     "errorCodeName": error.code.name,
                                # }).encode())
                            else:
                                if request.url.path in self.__factor2_protected_page_endpoints:
                                    return send_with_cookies(RedirectResponse(
                                        url=f"{self.__prefix}factor2?error={error.code.name}",
                                        status_code=302
                                    ), request)
                                else:
                                    return send_with_cookies(JSONResponse(
                                        status_code=error.http_status,
                                        content={
                                            "ok": False,
                                            "errorMessage": error.message,
                                            "errorMessages": error.messages,
                                            "errorCode": error.code.value,
                                            "errorCodeName": error.code.name
                                        },
                                    ), request)
                    else:
                        # 2FA has not started - start it
                        self.validate_csrf_token(request)
                        CrossauthLogger.logger().debug("Starting 2FA")

                        # Extract request body data
                        await set_body(request, await request.body())
            
                        req = Request(
                            scope=request.scope,
                            receive=lambda : create_body(request),  # <-------- Pass it here
                        )
                        form = JsonOrFormData(req)
  
                        await self.session_manager.initiate_two_factor_page_visit(
                            request.state.user, 
                            session_id, 
                            form.to_dict(), 
                            #request.url.replace(/\?.*$/,"")
                            request.url.path
                        )
                        
                        if request.url.path in self.__factor2_protected_page_endpoints:
                            return send_with_cookies(RedirectResponse(
                                url=f"{self.__prefix}factor2",
                                status_code=302
                            ), request)
                        else:
                            return send_with_cookies(JSONResponse(
                                content={
                                    "ok": True,
                                    "factor2Required": True
                                }
                            ), request)
                else:
                    # if we have a get request to one of the protected urls, 
                    # cancel any pending 2FA
                    session_cookie_value = self.get_session_cookie_value(request)
                    if session_cookie_value:
                        session_id = self.session_manager.get_session_id(session_cookie_value)
                        session_data = await self.session_manager.data_for_session_id(session_id)
                        if session_data and "pre2fa" in session_data:
                            CrossauthLogger.logger().debug("Cancelling 2FA")
                            try:
                                await self.session_manager.cancel_two_factor_page_visit(session_id)
                            except Exception as e:
                                CrossauthLogger.logger().debug(j({"err": str(e)}))
                                CrossauthLogger.logger().error(j({
                                    "msg": "Failed cancelling 2FA", 
                                    "cerr": str(e), 
                                    "user": request.state.user.username if request.state.user else None, 
                                    "hashOfSessionId": self.get_hash_of_session_id(request)
                                }))
        
            response : Response = cast(Response, await call_next(request))
            return response
        
        @app.middleware("http")
        async def pre_handler_session(request: Request, call_next): # type: ignore
            CrossauthLogger.logger().debug(j({"msg": "Session middleware"}))
            request.state.user= None
            request.state.csrf_token  = None
            request.state.session_id = None
            request.state.auth_type = None
            request.state.set_cookies = {}
            add_cookies : Dict[str, Tuple[str, CookieOptions]] = {}
            delete_cookies : Set[str] = set()
            headers : Dict[str, str] = {}

            await set_body(request, await request.body())
 
            req = Request(
                scope=request.scope,
                receive=lambda : create_body(request),  # <-------- Pass it here
            )

            #form = JsonOrFormData(copy.deepcopy(request))
            form = JsonOrFormData(req)

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
                        await form.load()
                        await self.csrf_token(request, form, add_cookies=add_cookies, delete_cookies=delete_cookies, headers=headers)
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
                    user : User|None = None
                    if self.__validate_session:
                        self.__validate_session(ret.key, user, request)
                    if (ret.user is not None): user = ret.user
                    request.state.session_id = session_id
                    request.state.user = user
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
            set_cookies : Dict[str,Tuple[str, FastApiCookieOptions]]  = {}
            for name in add_cookies:
                cookie = add_cookies[name]
                options = toFastApiCookieOptions(cookie[1])
                response.set_cookie(name, cookie[0], **options)
                set_cookies[name] = (cookie[0], options)
            request.state.set_cookies = set_cookies
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
                return send_with_cookies(JSONResponse({
                    "ok": True,
                    "csrfToken": request.state.csrf_token
                }), request)
            except:
                return send_with_cookies(JSONResponse({
                    "ok": False,
                }), request)

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
        soptions = toFastApiCookieOptions(session_cookie["options"])
        response.set_cookie(session_cookie["name"], session_cookie["value"], **soptions)
        request.state.csrf_token = csrf_form_or_header_value
        coptions = toFastApiCookieOptions(csrf_cookie["options"])
        response.set_cookie(csrf_cookie["name"], csrf_cookie["value"], **coptions)
        set_cookies : Dict[str, Any] = {}
        try:
            set_cookies = request.state.set_cookies
        except:
            pass

        set_cookies[csrf_cookie["name"]] = (csrf_cookie["value"], coptions)
        set_cookies[session_cookie["name"]] = (session_cookie["value"], soptions)
        request.state.set_cookies = set_cookies
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

    def handle_error(self, e: Exception, request: Request, form: JsonOrFormData|None, error_fn: Callable[[Dict[str,Any], CrossauthError], Response], password_invalid_ok: bool = False) -> Response:
        """
        Calls your defined `error_fn`, first sanitising by changing 
        `UserNotExist` and `UsernameOrPasswordInvalid` messages to `UsernameOrPasswordInvalid`.
        Also logs the error
        """
        body = form.to_dict() if form else {}
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

    async def csrf_token(self, request: Request, form: JsonOrFormData, headers: Dict[str,str]|None=None, add_cookies : Dict[str, Tuple[str, CookieOptions]]|None=None, delete_cookies : Set[str]|None=None, response : Response|None = None) -> Optional[str]:
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
            #data = JsonOrFormData()
            #await form.load(request)
            token = form.getAsStr("csrfToken")
            if (token is None):
                token = form.getAsStr("csrf_token")


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

    def send_json_error(self, request: Request, response: Response, status: int, error: Optional[str] = None, e: Optional[Exception] = None) -> Response:
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
        return send_with_cookies(JSONResponse(
            status_code=status,
            content={
                "ok": False,
                "status": status,
                "error_message": error,
                "error_code": ce.code if ce else None,
                "error_code_name": ce.code_name if ce else None
            },
            headers={"Content-Type": "application/json; charset=utf-8"}
        ), request)

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

        if ("login" in self.__endpoints):
            self.add_login_endpoints()
        if ("logout" in self.__endpoints):
            self.add_logout_endpoints()
        if ("loginfactor2" in self.__endpoints):
            self.add_login_factor2_endpoints()
        if ("factor2" in self.__endpoints):
            self.add_factor2_endpoints()
        if ("signup" in self.__endpoints):
            self.add_signup_endpoints()
        if ("configurefactor2" in self.__endpoints):
            self.__user_endpoints.add_configure_factor2endpoints()
        if ("requestpasswordreset" in self.__endpoints):
            self.__user_endpoints.add_request_password_reset_endpoints()
        if ("resetpassword" in self.__endpoints):
            self.__user_endpoints.add_password_reset_endpoints()
        if ("verifyemail" in self.__endpoints):
            self.__user_endpoints.add_verify_email_endpoints()

        if ("api/userforsessionkey" in self.__endpoints):
            self.add_api_user_for_session_key_endpoints()
        if ("api/getcsrftoken" in self.__endpoints):
            self.add_api_getcsrftoken_endpoints()
        if ("api/login" in self.__endpoints):
            self.add_api_login_endpoints()
        if ("api/logout" in self.__endpoints):
            self.add_api_logout_endpoints()
        if ("api/loginfactor2" in self.__endpoints):
            self.add_api_login_factor2_endpoints()
        if ("api/cancelfactor2" in self.__endpoints):
            self.add_api_cancel_factor2_endpoints()
        if ("api/signup" in self.__endpoints):
            self.add_api_signup_endpoints()
        if ("api/configurefactor2" in self.__endpoints):
            self.__user_endpoints.add_api_configure_factor2endpoints()
        if ("api/requestpasswordreset" in self.__endpoints):
            self.__user_endpoints.add_api_request_password_reset_endpoints()
        if ("api/resetpassword" in self.__endpoints):
            self.__user_endpoints.add_api_password_reset_endpoints()
        if ("api/verifyemail" in self.__endpoints):
            self.__user_endpoints.add_api_verify_email_endpoints()

    ############################3
    ## page endpoints


    def add_login_endpoints(self):
        @self.app.get(self.__prefix + 'login')
        async def get_login( # type: ignore
            request: Request,
            response: Response,
            next_param: Optional[str] = Query(None, alias="next")
        ):
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "GET",
                "url": self.__prefix + "login",
                "ip": request.client.host if request.client is not None else ""
            }))
            
            # Check if user is already logged in (assuming request.state.user is set via dependency or middleware)
            user = getattr(request.state, 'user', None)
            if user:
                redirect_url = next_param or self.__login_redirect
                return redirect(url=redirect_url, response=response, status_code=302)
            
            # Get CSRF token (assuming it's available via request state or dependency)
            csrf_token = getattr(request.state, 'csrf_token', None)
            
            data: Dict[str, Any] = {
                "urlPrefix": self.__prefix,
                "csrfToken": csrf_token
            }
            
            if next_param:
                data["next"] = next_param
            
            return send_with_cookies(self.templates.TemplateResponse(
                request,
                self.__login_page, 
                {
                    **data
                }), request)

        @self.app.post(self.__prefix + 'login')
        async def post_login( # type: ignore
            request: Request,
            response: Response,
            #next_param: Optional[str] = Form(None, alias="next"),
            #persist: bool = Form(False),
            #username: str = Form("")
        ):
            form = JsonOrFormData(request)
            await form.load()
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + "login",
                "ip": request.client.host if request.client else ""
            }))
            
            next_redirect = form.getAsStr1("next", self.__login_redirect) 
            
            # Create request body equivalent
            #body = LoginBodyType(next=next_param, persist=persist, username=username,)
            
            try:
                return await self.__login(request, response, form,
                    lambda body1, resp1, user: self._handle_login_response(request, form, response, user, next_redirect))
            except Exception as e:
                CrossauthLogger.logger().debug(j({"err": str(e)}))
                return self.handle_error(e, request, form,
                    lambda error, ce: self._render_login_error_page(request, response, form, ce, next_redirect))

    def _handle_login_response(self, request: Request, form: JsonOrFormData, response: Response, user: User, next_redirect: str) -> Response:
        
        if user["state"] == UserState.password_change_needed:
            if "changepassword" in self.__endpoints:
                CrossauthLogger.logger().debug(j({"msg": "Password change needed - sending redirect"}))
                redirect_url = f"/changepassword?required=true&next={quote(f'login?next={next_redirect}')}"
                return redirect(url=redirect_url, response=response, status_code=302)
            else:
                ce = CrossauthError(ErrorCode.PasswordChangeNeeded)
                return self.handle_error(ce, request, form, 
                    lambda error, ce: self._render_login_error_page(request, response, form, ce, next_redirect))

        elif (user["state"] == UserState.password_reset_needed or 
              user["state"] == UserState.password_and_factor2_reset_needed):
            CrossauthLogger.logger().debug(j({"msg": "Password reset needed - sending error"}))
            ce = CrossauthError(ErrorCode.PasswordResetNeeded)
            return self.handle_error(ce, request, form,
                lambda error, ce: self._render_login_error_page(request, response, form, ce, next_redirect))

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
                return redirect(url=redirect_url, response=response, status_code=302)
            else:
                ce = CrossauthError(ErrorCode.Factor2ResetNeeded)
                return self.handle_error(ce, request, form,
                    lambda error, ce: self._render_login_error_page(request, response, form, ce, next_redirect))

        elif not "factor2" not in user or ("factor2" in user and len(user["factor2"])) == 0:
            CrossauthLogger.logger().debug(j({"msg": "Successful login - sending redirect"}))
            return redirect(url=next_redirect, response=response, status_code=302)
        else:
            data : Dict[str,Any]= {
                "csrfToken": cast(str|None, getattr(request.state, 'csrf_token', None)),
                "next": form.getAsStr1("next", self.__login_redirect),
                "persist": "on" if form.getAsBool1("persist", False) else "",
                "urlPrefix": self.__prefix,
                "factor2": user["factor2"] if "factor2" in user else "",
                "action": "loginfactor2"
            }
            return send_with_cookies(self.templates.TemplateResponse(
                request,
                self.__factor2_page, 
                {
                    **data
                }), request)

    def add_logout_endpoints(self):
        @self.app.post(self.__prefix + 'logout')
        async def logout_endpoint(request: Request, response: Response): # type: ignore
            # Extract request body (in real FastAPI this would be handled differently)
            form = JsonOrFormData(request)
            await form.load()
            next_redirect = form.getAsStr1("next", self.__login_redirect) 
            
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": 'POST',
                "url": self.__prefix + 'logout',
                "ip": request.client.host if request.client else None,
                "user": request.state.user["username"] if request.state.user else None
            }))
            
            try:
                return await self.__logout(request, form, response, 
                    lambda reply: redirect(form.getAsStr1("next", self.__logout_redirect), response))
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "msg": "Logout failure",
                    "user": request.state.user["username"] if request.state.user else None,
                    "errorCode": ce.code.value,
                    "errorCodeName": ce.code.name
                }))
                CrossauthLogger.logger().debug(j({"err": str(e)}))
                factor2 : str|None = None
                try:
                    if request.state.session_id:
                        session_data = await self.session_manager.data_for_session_id(request.state.session_id)
                        if (session_data):
                            factor2 = session_data["factor2"]
                except Exception as e2:
                    ce2 = CrossauthError.as_crossauth_error(e2)
                    CrossauthLogger.logger().error(j({
                        "msg": "Logout failure",
                        "user": request.state.user["username"] if request.state.user else None,
                        "errorCode": ce2.code.value,
                        "errorCodeName": ce2.code.name
                    }))
                    CrossauthLogger.logger().debug(j({"err": str(e2)}))
                if (factor2 and factor2 in self.authenticators):
                    return self.handle_error(e, request, form, 
                        lambda error, ce: self._render_login_factor2_error_page(request, response, form, ce, next_redirect, factor2))
                else:
                    return self.handle_error(e, request, form, 
                        lambda error, ce: self._render_login_error_page(request, response, form, ce, next_redirect))

    def _render_login_error_page(self, request: Request, response: Response, form: JsonOrFormData, error: CrossauthError, next_redirect: str) -> Response:
        csrf_token = getattr(request.state, 'csrf_token', None)
        return send_with_cookies(self.templates.TemplateResponse(
            request,
            self.__login_page, 
            {
                "errorMessage": error.message,
                "errorMessages": error.messages,
                "errorCode": error.code.value,
                "errorCodeName": error.code.value,
                "next": next_redirect,
                "persist": form.getAsBool1("persist", False),
                "username": form.getAsStr1("username", ""),
                "csrfToken": csrf_token,
                "urlPrefix": self.__prefix
            }, error.http_status), request)

    def _render_login_factor2_error_page(self, request: Request, response: Response, form: JsonOrFormData, error: CrossauthError, next_redirect: str, factor2: str) -> Response:
        csrf_token = getattr(request.state, 'csrf_token', None)
        return send_with_cookies(self.templates.TemplateResponse(
            request,
            self.__login_page, 
            {
                "errorMessage": error.message,
                "errorMessages": error.messages,
                "errorCode": error.code.value,
                "errorCodeName": error.code.name,
                "next": next_redirect,
                "persist": form.getAsBool1("persist", False),
                "username": form.getAsStr1("username", ""),
                "csrfToken": csrf_token,
                "urlPrefix": self.__prefix,
                "action": "loginfactor2",
                "factor2": factor2,
            }, error.http_status), request)

    def add_login_factor2_endpoints(self):

        @self.app.post(self.__prefix + 'loginfactor2')
        async def post_loginfactor2( # type: ignore
            request: Request,
            response: Response,
            #next_param: Optional[str] = Form(None, alias="next"),
            #persist: bool = Form(False),
            #username: str = Form("")
        ):
            form = JsonOrFormData(request)
            await form.load()
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + "loginfactor2",
                "ip": request.client.host if request.client else ""
            }))
            
            next_redirect = form.getAsStr1("next", self.__login_redirect) 
            
            # Create request body equivalent
            #body = LoginBodyType(next=next_param, persist=persist, username=username,)
            
            def handle_login_factor2_response(request: Request, form: JsonOrFormData, response: Response, user: User, next_redirect: str) -> Response:
                
                return redirect(url=next_redirect, response=response, status_code=302)
            try:
                return await self.__login_factor2(request, response, form,
                    lambda body1, resp1, user: handle_login_factor2_response(request, form, response, user, next_redirect))
            except Exception as e:
                CrossauthLogger.logger().debug(j({"err": str(e)}))
                return self.handle_error(e, request, form,
                    lambda error, ce: self._render_login_error_page(request, response, form, ce, next_redirect))

    def add_factor2_endpoints(self):

        @self.app.get(self.__prefix + 'factor2')
        async def get_factor2( # type: ignore
            request: Request,
            response: Response,
            error_param: Optional[str] = Query(None, alias="error")
        ):
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "GET",
                "url": self.__prefix + "factor2",
                "ip": request.client.host if request.client is not None else ""
            }))

            if (not request.state.session_id):
                raise CrossauthError(ErrorCode.Unauthorized, "No session cookie present")
            
            session_cookie_value = self.get_session_cookie_value(request)
            if (not session_cookie_value):
                raise CrossauthError(ErrorCode.Unauthorized, "No session cookie present")
            session_id = self.session_manager.get_session_id(session_cookie_value)
            session_data = await self.session_manager.data_for_session_id(session_id)
            if (session_data is None or "pre2fa" not in session_data):
                raise CrossauthError(ErrorCode.Unauthorized, "2FA not initiated")
            data: Dict[str, Any] = {
                "urlPrefix": self.__prefix,
                "csrfToken": request.state.csrf_token,
                "action": session_data["pre2fa"]["url"],
                "factor2": session_data["pre2fa"]["factor2"],
                "errorCodeName": error_param
            }
            
            # Check if user is already logged in (assuming request.state.user is set via dependency or middleware)
            
            return send_with_cookies(self.templates.TemplateResponse(
                request,
                self.__factor2_page, 
                    {
                        **data
                }), request)

    def add_signup_endpoints(self):

        @self.app.get(self.__prefix + 'signup')
        async def get_signup( # type: ignore
            request: Request,
            response: Response,
            next_param: Optional[str] = Query(None, alias="next")
        ):
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "GET",
                "url": self.__prefix + "signup",
                "ip": request.client.host if request.client is not None else ""
            }))

            data: Dict[str, Any] = {
                "urlPrefix": self.__prefix,
                "csrfToken": request.state.csrf_token,
                "next": next_param
            }
            
            return send_with_cookies(self.templates.TemplateResponse(
                request,
                self.__signup_page, 
                {
                    **data
            }), request)

        @self.app.post(self.__prefix + 'signup')
        async def post_signup( # type: ignore
            request: Request,
            resp: Response,
            #next_param: Optional[str] = Form(None, alias="next"),
            #persist: bool = Form(False),
            #username: str = Form("")
        ):
            form = JsonOrFormData(request)
            await form.load()
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + "signup",
                "ip": request.client.host if request.client else ""
            }))
            
            next_redirect = form.getAsStr1("next", self.__login_redirect) 
            
            # Create request body equivalent
            #body = LoginBodyType(next=next_param, persist=persist, username=username,)
            
            body = form.to_dict()
            try:

                def signup_lambda(data: Dict[str,Any], resp : Response, user: User|None) -> Response:
                    if "userData" in data and "factor2" in data["userData"] and data["userData"]["factor2"]:
                        return send_with_cookies(self.templates.TemplateResponse(
                            request,
                            self.__configure_factor2_page, 
                            {
                                "csrfToken": data["csrfToken"],
                                **data["userData"]
                            }), request)
                    elif (self.__enable_email_verification):
                        return send_with_cookies(self.templates.TemplateResponse(
                            request,
                            self.__signup_page, 
                            {
                                "next": next_redirect,
                                "csrfToken": data["csrfToken"],
                                "message": "Please check your email to finish signing up.",
                                "allowedFactor2": self.allowed_factor2_details(),
                                "urlPrefix": self.__prefix, 
                                "factor2": body["factor2"] if "factor2" in body else None,
                                **(data["userData"] if "userData" in data else {})
                            }), request)
                    else:
                        #return RedirectResponse(url=self.__login_redirect, status_code=302)
                        return redirect(url=self.__login_redirect, response=resp, status_code=302)

                CrossauthLogger.logger().debug(j({"msg": "Next page " + next_redirect}))
                return await self.__signup(request, resp, form, signup_lambda)
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "msg": "Signup failure",
                    "user": body["username"],
                    "errorCodeName": ce.code_name,
                    "errorCode": ce.code.value
                }))
                CrossauthLogger.logger().debug(j({"err": e}))

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                def handle_error_fn(data: Dict[str,Any], error: CrossauthError):
                    extra_fields : Dict[str,Any] = {}
                    for field in body:
                        if (field.startswith("user_")):
                            extra_fields[field] = body[field]
                    return send_with_cookies(self.templates.TemplateResponse(
                        request,
                        self.__signup_page, 
                        {
                            "errorMessage": error.message,
                            "errorMessages": error.messages, 
                            "errorCode": error.code.value,
                            "errorCodeName": error.code.name,
                            "next": next_redirect, 
                            "persist": body["persist"] if body and "persist" in body else None,
                            "username": body["username"] if body and "username" in body else None,
                            "csrfToken": request.state.csrf_token,
                            "factor2": body["factor2"] if body and "factor2" in body else None,
                            "allowedFactor2": self.allowed_factor2_details(),
                            "urlPrefix": self.__prefix, 
                            **extra_fields,
                        }, error.http_status), request)
                    
                return self.handle_error(e, request, form,
                    lambda error, ce: handle_error_fn({}, ce))

    #################################
    ## API endpoints

    def _render_api_login_error_page(self, request: Request, response: Response, form: JsonOrFormData, error: CrossauthError) -> Response:
        return send_with_cookies(JSONResponse({
                "ok": False, 
                "errorMessage": error.message,
                "errorMessages": error.messages,
                "errorCode": error.code.value,
                "errorCodeName": error.code.name,
            },  headers=JSONHDRMAP), request)

    def add_api_getcsrftoken_endpoints(self):
        @self.app.get(self.__prefix + 'api/getcsrftoken')
        async def get_login( # type: ignore
            request: Request,
            response: Response,
        ):
            CrossauthLogger.logger().info(j({
                "msg": "API visit",
                "method": "GET",
                "url": self.__prefix + "api/getcsrftoken",
                "ip": request.client.host if request.client is not None else ""
            }))
            
            return send_with_cookies(JSONResponse({"ok": True, "csrfToken": request.state.csrf_token}, headers=JSONHDRMAP), request)

    def add_api_user_for_session_key_endpoints(self):
        @self.app.get(self.__prefix + 'api/userforsessionkey')
        async def get_api_user_for_session( # type: ignore
            request: Request,
            response: Response,
        ):
        
            CrossauthLogger.logger().info(j({
                "msg": "API visit",
                "method": "GET",
                "url": self.__prefix + "api/userforsessionkey",
                "ip": request.client.host if request.client is not None else ""
            }))
            
            user : User|None = None
            if (request.state.session_id):
                resp = await self.session_manager.user_for_session_id(request.state.session_id)
                user = resp.user
    
            return send_with_cookies(JSONResponse({"ok": True, "user": user}, headers=JSONHDRMAP), request)

    def add_api_login_endpoints(self):

        @self.app.post(self.__prefix + 'api/login')
        async def post_api_login( # type: ignore
            request: Request,
            response: Response,
            #next_param: Optional[str] = Form(None, alias="next"),
            #persist: bool = Form(False),
            #username: str = Form("")
        ):

            # Check if user is already logged in (assuming request.state.user is set via dependency or middleware)
            user = getattr(request.state, 'user', None)
            if user:
                return send_with_cookies(JSONResponse({"ok": False, "user": request.state.user}, headers=JSONHDRMAP), request)

            form = JsonOrFormData(request)
            await form.load()
            CrossauthLogger.logger().info(j({
                "msg": "API visit",
                "method": "POST",
                "url": self.__prefix + "api/login",
                "ip": request.client.host if request.client else ""
            }))
                                    
            try:
                return await self.__login(request, response, form,
                    lambda body1, resp1, user: self._handle_api_login_response(request, form, response, user))
            except Exception as e:
                CrossauthLogger.logger().debug(j({"err": str(e)}))
                return self.handle_error(e, request, form,
                    lambda error, ce: self._render_api_login_error_page(request, response, form, ce))

    def _handle_api_login_response(self, request: Request, form: JsonOrFormData, response: Response, user: User) -> Response:
        
        if user["state"] == UserState.password_change_needed:
            ce = CrossauthError(ErrorCode.PasswordChangeNeeded)
            return self.handle_error(ce, request, form, 
                lambda error, ce: self._render_api_login_error_page(request, response, form, ce))

        elif (user["state"] == UserState.password_reset_needed or 
              user["state"] == UserState.password_and_factor2_reset_needed):
            CrossauthLogger.logger().debug(j({"msg": "Password reset needed - sending error"}))
            ce = CrossauthError(ErrorCode.PasswordResetNeeded)
            return self.handle_error(ce, request, form,
                lambda error, ce: self._render_api_login_error_page(request, response, form, ce))

        elif (len(self.allowed_factor2) > 0 and 
              (user["state"] == UserState.factor2_reset_needed or 
               not (user["factor2"] if "factor2" in user else "none") in self.allowed_factor2)):
            CrossauthLogger.logger().debug(j({
                "msg": f"Factor2 reset needed. Factor2 is {user["factor2"] if "factor2" in user else ""}, state is {user["state"]}, allowed factor2 is [{', '.join(self.allowed_factor2)}]",
                "username": user["username"]
            }))
            ce = CrossauthError(ErrorCode.Factor2ResetNeeded)
            return self.handle_error(ce, request, form,
                lambda error, ce: self._render_api_login_error_page(request, response, form, ce))

        elif "factor2" in user and user["factor2"] != "" and user["factor2"] in self.authenticators:
            CrossauthLogger.logger().debug(j({"msg": "Login - factor2 required"}))
            return send_with_cookies(JSONResponse({"ok": True, "twoFactorRequired": True}, headers=JSONHDRMAP), request)
        else:
            CrossauthLogger.logger().debug(j({"msg": "Successful login - sending ok"}))
            return send_with_cookies(JSONResponse({"ok": True, "user": user}, headers=JSONHDRMAP), request)

    def allowed_factor2_details(self) -> List[AuthenticatorDetails]:
        """
        For each of the authenticators passed to the constructor, returns
        some details about it
        @returns a list of AuthenticatorDetails objects.
        """
        ret: List[AuthenticatorDetails] = []
        for authenticatorName in self.allowed_factor2:
            if authenticatorName in self.authenticators:
                secrets = self.authenticators[authenticatorName].secret_names()
                ret.append({
                    "name": authenticatorName,
                    "friendlyName": self.authenticators[authenticatorName].friendly_name,
                    "hasSecrets": len(secrets) > 0,
                })
            elif authenticatorName == "none":
                ret.append({"name": "none", "friendlyName": "None", "hasSecrets": False})
        

        return ret
    
    def add_api_login_factor2_endpoints(self):

        @self.app.post(self.__prefix + 'api/loginfactor2')
        async def post_api_loginfactor2( # type: ignore
            request: Request,
            response: Response,
        ):
            form = JsonOrFormData(request)
            await form.load()
            CrossauthLogger.logger().info(j({
                "msg": "API visit",
                "method": "POST",
                "url": self.__prefix + "loginfactor2",
                "ip": request.client.host if request.client else ""
            }))
                        
            # Create request body equivalent
            #body = LoginBodyType(next=next_param, persist=persist, username=username,)
            
            def handle_login_factor2_response(request: Request, form: JsonOrFormData, response: Response, user: User) -> Response:
                return send_with_cookies(JSONResponse({"ok": True, "user": user}, headers=JSONHDRMAP), request)
            
            try:
                return await self.__login_factor2(request, response, form,
                    lambda body1, resp1, user: handle_login_factor2_response(request, form, response, user))
            except Exception as e:
                CrossauthLogger.logger().debug(j({"err": str(e)}))
                ce = CrossauthError.as_crossauth_error(e)
                return self.handle_error(ce, request, form,
                    lambda error, ce: self._render_api_login_error_page(request, response, form, ce))

    def add_api_signup_endpoints(self):

        @self.app.post(self.__prefix + 'api/signup')
        async def post_api_signup( # type: ignore
            request: Request,
            resp: Response,
        ):
            form = JsonOrFormData(request)
            await form.load()
            CrossauthLogger.logger().info(j({
                "msg": "API visit",
                "method": "POST",
                "url": self.__prefix + "api/signup",
                "ip": request.client.host if request.client else ""
            }))
                        
            # Create request body equivalent
            #body = LoginBodyType(next=next_param, persist=persist, username=username,)
            
            body = form.to_dict()
            try:

                def signup_lambda(data: Dict[str,Any], resp : Response, user: User|None) -> Response:
                    if ("userData" in data):
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": True,
                                "user": user,
                                "emailVerificationNeeded": self.enable_email_verification if self.enable_email_verification else False,
                                **data["userData"]
                            }), request)
                    else:
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": True,
                                "user": user,
                                "emailVerificationNeeded": self.enable_email_verification if self.enable_email_verification else False,
                            }), request)


                return await self.__signup(request, resp, form, signup_lambda)
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "msg": "Signup failure",
                    "user": body["username"],
                    "errorCodeName": ce.code_name,
                    "errorCode": ce.code.value
                }))
                CrossauthLogger.logger().debug(j({"err": e}))

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                def handle_error_fn(data: Dict[str,Any], error: CrossauthError):
                    extra_fields : Dict[str,Any] = {}
                    for field in body:
                        if (field.startswith("user_")):
                            extra_fields[field] = body[field]
                    return send_with_cookies(JSONResponse(
                        {
                            "errorMessage": error.message,
                            "errorMessages": error.messages, 
                            "errorCode": error.code.value,
                            "errorCodeName": error.code.name,
                            "persist": body["persist"] if "persist" in body else None,
                            "username": body["username"] if "username" in body else None,
                            "csrfToken": request.state.csrf_token,
                            "factor2": body["factor2"] if "factor2" in body else None,
                            "allowedFactor2": self.allowed_factor2_details(),
                            "urlPrefix": self.__prefix, 
                            **extra_fields,
                        }, error.http_status), request)
                    
                return self.handle_error(e, request, form,
                    lambda error, ce: handle_error_fn({}, ce))

    def add_api_logout_endpoints(self):
        @self.app.post(self.__prefix + 'api/logout')
        async def api_logout_endpoint(request: Request, response: Response): # type: ignore
            # Extract request body (in real FastAPI this would be handled differently)
            form = JsonOrFormData(request)
            await form.load()
            
            CrossauthLogger.logger().info(j({
                "msg": "API visit",
                "method": 'POST',
                "url": self.__prefix + 'api/logout',
                "ip": request.client.host if request.client else None,
                "user": request.state.user["username"] if request.state.user else None
            }))
            
            try:
                return await self.__logout(request, form, response, 
                    lambda reply: send_with_cookies(JSONResponse({"ok": True}, headers=JSONHDRMAP), request))
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "msg": "Logout failure",
                    "user": request.state.user["username"] if request.state.user else None,
                    "errorCode": ce.code.value,
                    "errorCodeName": ce.code.name
                }))
                return send_with_cookies(JSONResponse({
                    "ok": False,
                    "message": ce.message,
                    "messages": ce.messages,
                    "errorCode": ce.code.value,
                    "errorCodeName": ce.code.name
                    }, headers=JSONHDRMAP), request)

    def add_api_cancel_factor2_endpoints(self):
        @self.app.get(self.__prefix + 'api/cancelfactor2')

        async def post_api_cancel_factor2( # type: ignore
            request: Request,
            response: Response,
        ):
            CrossauthLogger.logger().info(j({
                "msg": "API visit",
                "method": "GET",
                "url": self.__prefix + "api/cancelfactor2",
                "ip": request.client.host if request.client is not None else ""
            }))
            
            if (request.state.user):
                return send_with_cookies(JSONResponse({"ok": True, "csrfToken": request.state.csrf_token}, headers=JSONHDRMAP), request)
            
            form = JsonOrFormData(request)
            try:
                return await self.__cancel_factor2(request, response, form, 
                        lambda reply: send_with_cookies(JSONResponse({"ok": True}, headers=JSONHDRMAP), request))
            except Exception as e:
                user : User|None = request.state.user
                username = user["username"] if user else None
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "msg": "Cancel 2FA failure",
                    "user": username,
                    "errorCodeName": ce.code.name,
                    "errorCode": ce.code.value
                }))
                CrossauthLogger.logger().debug(j({"err": e}))
                return self.handle_error(e, request, form, lambda data, e: send_with_cookies(JSONResponse({
                    "ok": False,
                    "errorMessage": e.message,
                    "errorMessages": e.messages,
                    "errorCode": e.code.value,
                    "errorCodeName": e.code.name,

                }), request))

    ##########################################
    ## Shared between page and API endpoints

    async def __login(self, 
                   request: Request, 
                   resp: Response, 
                   form : JsonOrFormData,
                   success_fn: Callable[[Dict[str,Any], Response, User], Response]) -> Response:
        """
        Private async method to handle user login
        
        :param request: The request object containing body with LoginBodyType
        :param resp : The response object for setting cookies
        :param success_fn: Callback function to handle successful login
        
        Returns:
            Result of success_fn callback
        """
        
        if request.state.user:
            # already logged in - nothing to do
            return success_fn(form.to_dict(), resp, request.state.user)

        # get data from request body
        username = form.getAsStr1("username", "")
        persist = form.getAsBool1("persist", False)
        persist = False

        # throw an exception if the CSRF token isn't valid
        # await self.validate_csrf_token(request)
        if not request.state.csrf_token:
            raise CrossauthError(ErrorCode.InvalidCsrf)

        # keep the old session ID. If there was one, we will delete it after
        old_session_id = self.get_session_cookie_value(request)

        # call implementor-provided hook to add additional fields to session key
        extra_fields : Mapping[str, str|int|float|datetime|None] = {}
        if (self.__add_to_session):
            extra_fields = self.__add_to_session(request)

        # log user in and get new session cookie, CSRF cookie and user
        # if 2FA is enabled, it will be an anonymous session
        body = form.to_dict()
        login_result = await self.session_manager.login(
            username,cast(AuthenticationParameters, body), extra_fields, persist
        )
        session_cookie = login_result.session_cookie
        csrf_cookie = login_result.csrf_cookie
        user = login_result.user

        if (user is None):
            raise CrossauthError(ErrorCode.Unauthorized, "Login failed")


        # Set the new cookies in the reply
        CrossauthLogger.logger().debug(j({
            "msg": f"Login: set session cookie {session_cookie["name"] if session_cookie else ""} opts {json.dumps(session_cookie["options"] if session_cookie else {})}",
            "user": form.getAsStr1("username", "")
        }))
        if (session_cookie):
            resp.set_cookie(session_cookie["name"],
                        session_cookie["value"],
                        **toFastApiCookieOptions(session_cookie["options"]))
            set_cookies : Dict[str,Any] = {}
            try:
                set_cookies = request.state.set_cookies
            except:
                pass
            set_cookies[session_cookie["name"]] = (session_cookie["value"],
                        toFastApiCookieOptions(session_cookie["options"]))
            request.state.set_cookies = set_cookies
            
        CrossauthLogger.logger().debug(j({
            "msg": f"Login: set csrf cookie {csrf_cookie["name"] if csrf_cookie else ""} opts {json.dumps(session_cookie["options"] if session_cookie else {})}",
            "user": form.getAsStr1("username", "")
        }))
        if (csrf_cookie):
            resp.set_cookie(csrf_cookie["name"], csrf_cookie["value"], **toFastApiCookieOptions(csrf_cookie["options"]))
        
            request.state.csrf_token = await self.session_manager.create_csrf_form_or_header_value(
                csrf_cookie["value"]
            )

        request.state.user = user

        # delete the old session key if there was one
        if old_session_id:
            try:
                await self.session_manager.delete_session(old_session_id)
            except Exception as e:
                CrossauthLogger.logger().warn(j({
                    "msg": "Couldn't delete session ID from database",
                    "hashOfSessionId": self.get_hash_of_session_id(request)
                }))
                CrossauthLogger.logger().debug(j({"err": str(e)}))
            form = JsonOrFormData(copy.deepcopy(request))

        return success_fn(body, resp, user)
    
    async def __logout(self, request: Request, form: JsonOrFormData, response: Response, 
                    success_fn: Callable[[Response], Any]) -> Response:
        """
        Handle user logout process
        
        :param request: FastAPI request object
        :param response: FastAPI response object  
        :param success_fn: Function to call on successful logout
        """
        
        # logout
        if (request.state.session_id):
            await self._session_manager.logout(request.state.session_id)
        
        # clear cookies
        CrossauthLogger.logger().debug(j({
            "msg": f"Logout: clear cookie {self._session_manager.session_cookie_name}"
        }))
        
        response.delete_cookie(self._session_manager.session_cookie_name)
        response.delete_cookie(self._session_manager.csrf_cookie_name)
        
        if (request.state.session_id):
            try:
                await self._session_manager.delete_session(request.state.session_id)
            except Exception as e:
                CrossauthLogger.logger().warn(j({
                    "msg": "Couldn't delete session ID from database",
                    "hashOfSessionId": self.get_hash_of_session_id(request)
                }))
                CrossauthLogger.logger().debug(j({"err": str(e)}))
        
        return success_fn(response)

    async def __login_factor2(self, 
                   request: Request, 
                   resp: Response, 
                   form : JsonOrFormData,
                   success_fn: Callable[[Dict[str,Any], Response, User], Response]) -> Response:
        """
        Private async method to handle user login
        
        :param request: The request object containing body with LoginBodyType
        :param resp : The response object for setting cookies
        :param success_fn: Callback function to handle successful login
        
        Returns:
            Result of success_fn callback
        """
        
        if request.state.user:
            # already logged in - nothing to do
            return success_fn(form.to_dict(), resp, request.state.user)

        body = form.to_dict()
        auth_params : AuthenticationParameters = cast(AuthenticationParameters, body)

        # get data from request body
        persist = form.getAsBool1("persist", False)
        persist = False

        # throw an exception if the CSRF token isn't valid
        if (self.is_session_user(request) and not request.state.csrf_token):
            raise CrossauthError(ErrorCode.InvalidCsrf)


        session_id = request.state.session_id
        if (session_id is None):
            raise CrossauthError(ErrorCode.InvalidSession)
        
        # call implementor-provided hook to add additional fields to session key
        extra_fields : Mapping[str, str|int|float|datetime|None] = {}
        if (self.__add_to_session):
            extra_fields = self.__add_to_session(request)
        tokens = await self.session_manager.complete_two_factor_login(auth_params, session_id, extra_fields, persist)
        session_cookie = tokens.session_cookie
        csrf_cookie = tokens.csrf_cookie
        user = tokens.user
        CrossauthLogger.logger().debug(j({
            "msg": "Login: set session cookie " + session_cookie["name"] if session_cookie else "" + " opts " + json.dumps(session_cookie["options"] if session_cookie else {}),
            "user": user["username"] if user else ""
        }))

        if (user is None):
            raise CrossauthError(ErrorCode.Unauthorized, "Login failed")


        # Set the new cookies in the reply
        if (session_cookie):
            resp.set_cookie(session_cookie["name"],
                        session_cookie["value"],
                        **toFastApiCookieOptions(session_cookie["options"]))
            set_cookies : Dict[str,Any] = {}
            try:
                set_cookies = request.state.set_cookies
            except:
                pass
            set_cookies[session_cookie["name"]] = (session_cookie["value"],
                        toFastApiCookieOptions(session_cookie["options"]))
            request.state.set_cookies = set_cookies
            
        CrossauthLogger.logger().debug(j({
            "msg": f"Login: set csrf cookie {csrf_cookie["name"] if csrf_cookie else ""} opts {json.dumps(session_cookie["options"] if session_cookie else {})}",
            "user": form.getAsStr1("username", "")
        }))
        if (csrf_cookie):
            resp.set_cookie(csrf_cookie["name"], csrf_cookie["value"], **toFastApiCookieOptions(csrf_cookie["options"]))
        
            request.state.csrf_token = await self.session_manager.create_csrf_form_or_header_value(
                csrf_cookie["value"]
            )


        return success_fn(body, resp, user)
    
    async def cancel_factor2(self, 
                   request: Request, 
                   resp: Response, 
                   success_fn: Callable[[Response], Response]) -> Response:
        if (self.is_session_user(request) and not request.state.csrf_token):
            raise CrossauthError(ErrorCode.InvalidCsrf)
        session_cookie_value = self.get_csrf_cookie_value(request)
        if (session_cookie_value):
            await self.session_manager.cancel_two_factor_page_visit(session_cookie_value)
        return success_fn(resp)

    async def __signup(self,
            request : Request,
            resp : Response, 
            form : JsonOrFormData,
            success_fn: Callable[[Dict[str,Any], Response, User|None], Response]) -> Response:
        if (not self.user_storage):
            raise CrossauthError(ErrorCode.Configuration, "Cannot call signup unless you provide a user stotage")
        if (self.is_session_user(request) and not request.state.csrf_token):
            raise CrossauthError(ErrorCode.InvalidCsrf)
        
        # get data from the request body
        # make sure the requested second factor is valid
        body = form.to_dict()
        username = body["username"]
        if ("factor2" not in body or body["factor2"] is None):
            body["factor2"] = self.allowed_factor2[0]
        factor2 = body["factor2"] if body["factor2"] else "none"
        if (factor2 not in self.allowed_factor2):
            raise CrossauthError(ErrorCode.Forbidden, 
                "Illegal second factor " + factor2 + " requested")
        if (body["factor2"] == "none" or body["factor2"] == ""):
            body["factor2"] = None
        
        # call implementor-provided function to create the user object (or our default)
        user = self.create_user_fn(request, body, self.__user_storage.user_editable_fields if self.__user_storage else [], self.user_allowed_factor1)

        # ask the authenticator to validate the user-provided secret
        auth_params = cast(AuthenticationParameters, body)
        password_errors = self.authenticators[user["factor1"]].validate_secrets(auth_params)

        # get the repeat secrets (secret names prefixed with repeat_)
        secret_names = self.authenticators[user["factor1"]].secret_names()
        repeat_secrets : AuthenticationParameters|None = {}
        found = False
        for field in body:
            if field.startswith("repeat_"):
                name = field[7:]
                if name in secret_names:
                    repeat_secrets[name] = body[field]
                    found = True
        if (not found):
            repeat_secrets = None

        #  set the user's state to active, awaitingtwofactor or 
        # awaitingemailverification
        # depending on settings for next step
        user["state"] = "active"
        if ("factor2" in body and body["factor2"] != "none" and body["factor2"] != "" and body["factor2"] is not None):
            user["state"] = "awaitingtwofactor"
        elif (self.__enable_email_verification):
            user["state"] = "awaitingemailverification"

        # call the implementor-provided hook to validate the user fields
        user_errors = self.validate_user_fn(user)

        # report any errors
        errors = [*user_errors, *password_errors]
        if (len(errors) > 0):
            raise CrossauthError(ErrorCode.FormEntry, errors)

        # See if the user was already created, with the correct password, and 
        # is awaiting 2FA
        # completion.  Send the same response as before, in case the user 
        # closed the browser
        two_factor_initiated = False
        try:
            us = await self.user_storage.get_user_by_username(username)
            await self._session_manager.authenticators[user["factor1"]].authenticate_user(us["user"], us["secrets"], auth_params)
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            if (ce.code == ErrorCode.TwoFactorIncomplete):
                two_factor_initiated = True
            
        if (not body["factor2"] and not two_factor_initiated):
            # not enabling 2FA
            await self.session_manager.create_user(user, cast(UserSecrets, body),cast(UserSecrets|None, repeat_secrets))
            if not self.__enable_email_verification:
                return await self.__login(request, resp, form, lambda req, resp, user: success_fn({"csrfToken": request.state.csrf_token}, resp, user))
            return success_fn({"csrfToken": request.state.csrf_token}, resp, None)
        else:
            # also enabling 2FA
            user_data : Dict[str, Any] = {}
            if (two_factor_initiated):
                # account already created but 2FA setup not complete
                if (not request.state.session_id):
                    raise CrossauthError(ErrorCode.Unauthorized)
                uds = await self.session_manager.repeat_two_factor_signup(request.state.session_id)
                user_data = uds.user_data
            else:
                # account not created - create one with state awaiting 2FA setup
                session_value = await self.create_anonymous_session(request, resp, body)
                session_id = self._session_manager.get_session_id(session_value)
                uds = await self.session_manager.initiate_two_factor_signup(user, cast(UserSecrets, body), session_id, cast(UserSecrets|None, repeat_secrets))
                user_data = uds.user_data

            # pass caller back 2FA parameters
            try:
                data: Dict[str, Any] = {
                    "userData": user_data,
                    "username": username,
                    "csrfToken": request.state.csrf_token,
                    "next": body["next"] if "next" in body and body["next"] is not None else self.__login_redirect,
                }
                return success_fn(data, resp, None)
            except Exception as e:
                # if there is an error, make sure we delete the user before returning
                try:
                    await self.session_manager.delete_user_by_username(username)
                except Exception as e1:
                    CrossauthLogger.logger().error(j({"err": e1}))
                return success_fn({}, resp, None)


    def is_session_user(self, request: Request) -> bool:
        """ 
        Returns whether there is a user logged in with a cookie-based session
        """
        return request.state.user and request.state.auth_type == "cookie"
    
    """
    Calls the `isAdminFn` passed during construction.
    :param user the user to check
    :return true if the passed user is an admin, false otherwise.
    """
    @staticmethod
    def is_admin(user : User):
        return FastApiServerBase.is_admin(user); 


    async def __cancel_factor2(self, request: Request, response: Response, form: JsonOrFormData, success_fn: Callable[[Response], Response]) -> Response:
        if (self.is_session_user(request) and not request.state.csrf_token):
            raise CrossauthError(ErrorCode.InvalidCsrf)
        
        session_cookie_value = self.get_session_cookie_value(request)
        if (session_cookie_value):
            await self.session_manager.cancel_two_factor_page_visit(session_cookie_value)

        return success_fn(response)

    async def login_with_user(self, 
            user : User,
            bypass_2fa: bool,
            request: Request,
            resp: Response,
            success_fn: Callable[[Response, User], Response]) -> Response:
        """
        This is called after the user has been validated to log the user in
        """

        # get old session ID so we can delete it after
        old_session_id = self.get_session_cookie_value(request)

        # call implementor-provided hook to add custom fields to session key
        extra_fields : Mapping[str,Any] = {}
        if (self.__add_to_session):
            extra_fields = self.__add_to_session(request)

        # log user in - this doesn't do any authentication
        tokens = await self.session_manager.login("", {}, extra_fields, False, user, bypass_2fa)

        session_cookie = tokens.session_cookie
        csrf_cookie = tokens.csrf_cookie

        CrossauthLogger.logger().debug(j({
            "msg": f"Login: set csrf cookie {csrf_cookie["name"] if csrf_cookie else ""} opts {json.dumps(session_cookie["options"] if session_cookie else {})}",
        }))

        # Set the new cookies in the reply
        if (session_cookie):
            resp.set_cookie(session_cookie["name"],
                        session_cookie["value"],
                        **toFastApiCookieOptions(session_cookie["options"]))
        if (csrf_cookie):
            resp.set_cookie(csrf_cookie["name"], csrf_cookie["value"], **toFastApiCookieOptions(csrf_cookie["options"]))
        
            request.state.csrf_token = await self.session_manager.create_csrf_form_or_header_value(
                csrf_cookie["value"]
            )

        # delete the old session key if there was one
        if old_session_id:
            try:
                await self.session_manager.delete_session(old_session_id)
            except Exception as e:
                CrossauthLogger.logger().warn(j({
                    "msg": "Couldn't delete session ID from database",
                    "hashOfSessionId": self.get_hash_of_session_id(request)
                }))
                CrossauthLogger.logger().debug(j({"err": str(e)}))

        return success_fn(resp, user)
    
    def can_edit_user(self, request : Request) -> bool:
        """
        A user can edit his or her account if they are logged in with
        session management, or are logged in with some other means and
        e`ditUserScope` has been set and is included in the user's scopes.
        @param request the Fastify request
        @returns true or false
        """
        scope = cast(None|List[str], request.state.scope)

        return self.is_session_user(request) or \
            (self.__edit_user_scope is not None and scope is not None and \
                self.__edit_user_scope in scope)
    
    def send_page_error(self, request: Request, response: Response, status: int, error: Optional[str] = None, e: Optional[Exception] = None) -> Response:
        return FastApiServerBase.send_page_error(self.templates, request, response, status, error)
