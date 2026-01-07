# Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file

from typing import Optional, Any, Dict, Callable, cast, Awaitable
from fastapi import Request, Response, Query
from fastapi.responses import JSONResponse, RedirectResponse
import re

from crossauth_fastapi.fastapisessionserverbase import *
from crossauth_fastapi.fastapiserverbase import FastApiServerBase
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.crypto import Crypto
from crossauth_backend.common.interfaces import User, UserState
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.auth import AuthenticationParameters
from crossauth_backend.common.interfaces import User, UserInputFields, UserState, UserSecrets
from crossauth_backend.storage import UserStorage
from crossauth_backend.emailtoken import TokenEmailer

async def default_user_search_fn(search_term: str, user_storage: UserStorage) -> List[User]:

    users : List[User] = []
    try:
        user_ret = await user_storage.get_user_by_username(search_term)
        users.append(user_ret["user"])
    except Exception as e1:
        ce1 = CrossauthError.as_crossauth_error(e1)
        if (ce1.code != ErrorCode.UserNotExist):
            CrossauthLogger.logger().debug(j({"err": ce1}));
            raise ce1
        
        try:
            user_ret =  await user_storage.get_user_by_email(search_term)
            users.push(user_ret["user"])
        except Exception as e2:
            ce2 = CrossauthError.as_crossauth_error(e2)
            if (ce2.code != ErrorCode.UserNotExist):
                CrossauthLogger.logger().debug(j({"err": ce2}))
                raise ce2
    return users

class FastApiAdminEndpoints():
    """
    self class provides user endpoints for the Fastify server.

    Endpoints include changeing password, editing the User record, etc.

    self class is not intended to be created directly.  It is created
    by {@link FastifySessionServer}.  For a description of the endpoints,
    and how to create templates for them, see that class.
    """

    def __init__(self, sesion_server: FastApiSessionServerBase, 
                 options: FastApiSessionServerOptions ):

        """
        Constructor.
        
        :param sessionServer the instance of the Fastify session server self
            object belongs to
        :param options See {@link FastifySessionServerOptions}
        """

        self.__session_server = sesion_server
        self.app = self.__session_server.app
        self.__user_search_fn: Callable[[str, UserStorage], Awaitable[List[User]]]
        self.__enable_oauth_client_management = False

        self.__admin_prefix : str = "/admin/"
        self.__admin_create_user_page: str = "admin/createuser.njk"
        self.__admin_select_user_page: str = "admin/selectuser.njk"
        self.__admin_update_user_page: str = "admin/updateuser.njk"
        self.__admin_change_password_page: str = "admin/changepassword.njk"
        self.__delete_user_page: str = "deleteuser.njk"

        set_parameter("admin_prefix", ParamType.String, self, options, "ADMIN_PREFIX")
        set_parameter("admin_create_user_page", ParamType.String, self, options, "ADMIN_CREATE_USER_PAGE")
        set_parameter("admin_select_user_page", ParamType.String, self, options, "ADMIN_SELECT_USER_PAGE")
        set_parameter("admin_update_user_page", ParamType.String, self, options, "ADMIN_UPDATE_USER_PAGE")
        set_parameter("admin_change_password_page", ParamType.String, self, options, "ADMIN_CHANGE_PASSWORD_PAGE")
        set_parameter("delete_user_page", ParamType.String, self, options, "DELETE_USER_PAGE")
        set_parameter("enable_oauth_client_management", ParamType.Boolean, self, options, "ENABLE_OAUTH_CLIENT_MANAGEMENT")

        if (not self.__admin_prefix.endswith("/")): 
            self.__admin_prefix += "/"
        if (not self.__admin_prefix.startsWith("/")):
            self.__admin_prefix = "/" + self.__admin_prefix
        if (options.user_search_fn):
            self.__user_search_fn = options.user_search_fn

    ############################
    ## page endpoints

    def add_create_user_endpoints(self):

        @self.app.get(self.__admin_prefix + 'createuser')
        async def get_create_user( # type: ignore
            request: Request,
            response: Response,
            next_param: Optional[str] = Query(None, alias="next")
        ):
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": "GET",
                "url": self.__admin_prefix + "createuser",
                "ip": request.client.host if request.client is not None else ""
            }))

            if (self.is_session_user(request) and not request.state.csrf_token):
                raise CrossauthError(ErrorCode.InvalidCsrf)

            form = JsonOrFormData(request)
            if (not request.state.user or not FastApiServerBase.is_admin(request.user)):
                return await self._access_denied_page(request, form);                    
            

            data: Dict[str, Any] = {
                "urlPrefix": self.__prefix,
                "csrfToken": request.state.csrf_token,
                "next": next_param,
                "allowedFactor2": self.__session_server.allowed_factor2details(),
            }
            
            return send_with_cookies(self.templates.TemplateResponse(
                request,
                self.__admin_create_user_page, 
                {
                    **data
            }), request)

        @self.app.post(self.__prefix + 'signup')
        async def post_create_user( # type: ignore
            request: Request,
            resp: Response,
            #next_param: Optional[str] = Form(None, alias="next"),
            #persist: bool = Form(False),
            #username: str = Form("")
        ):
            form = JsonOrFormData(request)
            await form.load()
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": "POST",
                "url": self.__admin_prefix + "createuser",
                "ip": request.client.host if request.client else ""
            }))
            
            next_redirect = form.getAsStr1("next", self.__login_redirect) 
            
            # Create request body equivalent
            #body = LoginBodyType(next=next_param, persist=persist, username=username,)
            
            body = form.to_dict()
            try:

                def createuser_lambda(data: Dict[str,Any], resp : Response, user: User|None) -> Response:
                    if (data and "userData" in data):
                        return send_with_cookies(RedirectResponse(
                            url=next_redirect,
                            status_code=302,
                            **data["userData"],
                        ), request)
                    else:
                        return send_with_cookies(RedirectResponse(
                            url=next_redirect,
                            status_code=302
                        ), request)

                CrossauthLogger.logger().debug(j({"message": "Next page " + next_redirect}))
                return await self.__create_user(request, resp, form, createuser_lambda)
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "message": "Signup failure",
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


    ##########################
    # API endpoints

    def add_api_create_endpoints(self):

        @self.app.post(self.__prefix + 'api/createuser')
        async def post_api_createuser( # type: ignore
            request: Request,
            resp: Response,
        ):
            form = JsonOrFormData(request)
            await form.load()
            CrossauthLogger.logger().info(j({
                "message": "API visit",
                "method": "POST",
                "url": self.__prefix + "api/createuser",
                "ip": request.client.host if request.client else ""
            }))
                        
            # Create request body equivalent
            #body = LoginBodyType(next=next_param, persist=persist, username=username,)
            
            body = form.to_dict()
            try:

                def createuser_lambda(data: Dict[str,Any], resp : Response, user: User|None) -> Response:
                    if ("userData" in data):
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": True,
                                "user": user,
                                **data["userData"]
                            }), request)
                    else:
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": True,
                                "user": user,
                            }), request)


                return await self.__create_user(request, resp, form, createuser_lambda)
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "message": "Signup failure",
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
                            "ok": False,
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

    ##########################
    # Shared functions

    def is_session_user(self, request: Request) -> bool:
        """ 
        Returns whether there is a user logged in with a cookie-based session
        """
        return request.state.user and request.state.auth_type == "cookie"

    async def _access_denied_page(self, request : Request, form: JsonOrFormData|None):
        ce = CrossauthError(ErrorCode.InsufficientPriviledges)

        def error_fn(body: Dict[str,Any], error: CrossauthError):
            return send_with_cookies(self.templates.TemplateResponse(
                request,
                self.__session_server.error_page,  {
                    "errorMessage": error.message,
                    "errorMessages": error.messages, 
                    "errorCode": error.code.value,
                    "errorCodeName": error.code.name,
                }, error.http_status), request)

        return self.__session_server.handle_error(ce, request, form, error_fn)
    
    async def __create_user(self,
            request : Request,
            resp : Response, 
            form : JsonOrFormData,
            success_fn: Callable[[Dict[str,Any], Response, User|None], Response]) -> Response:
        if (not self.user_storage):
            raise CrossauthError(ErrorCode.Configuration, "Cannot call signup unless you provide a user stotage")
        
        if not request.state.user or not FastApiServerBase.is_admin(request.state.user):
            return await self._access_denied_page(request, form)
        
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
        user = self.__session_server.create_user_fn(request, body, {
            **self.__session_server.user_storage.admin_editable_fields, 
            **self.__session_server.user_storage.user_editable_fields} if self.__session_server.user_storage else [], 
            self.__session_server.admin_allowed_factor1, self.__session_server.allowed_factor2)

        # ask the authenticator to validate the user-provided secret
        auth_params = cast(AuthenticationParameters, body)
        secret_names = self.__session_server.authenticators[user["factor1"]].secret_names()
        has_secrets = True
        for secret in secret_names:
            if ((secret not in body or not body[secret]) and ("repeat_" + secret not in body or not request.body["repeat_"+secret])):
                has_secrets = False
        
        if (has_secrets):
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
        if (not has_secrets):
            if ("factor2" in body and body["factor2"] != "none" and body["factor2"] != "" and body["factor2"] is not None):
                user["state"] = UserState.passwordAndFactor2ResetNeeded
                CrossauthLogger.logger().warn(j({"msg": "Setting state for user to " + UserState.passwordAndFactor2ResetNeeded, 
                    username: user["username"]}))
            else:
                user["state"] = UserState.factor2ResetNeeded
                CrossauthLogger.logger().warn(j({"msg": "Setting state for user to " + UserState.factor2ResetNeeded, 
                    username: user["username"]}))
        elif ("factor2" in body and body["factor2"] != "none" and body["factor2"] != "" and body["factor2"] is not None):
            user["state"] = UserState.factor2ResetNeeded
            CrossauthLogger.logger().warn(j({"msg": "Setting state for user to " + UserState.factor2ResetNeeded, 
                username: user["username"]}))

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
            
        await self.session_manager.create_user(user, cast(UserSecrets, body),cast(UserSecrets|None, repeat_secrets))

        if not has_secrets:
            email : str|int|None = body["username"] if "username" in body else None
            if ("user_email" in request.body):
                email1 = body["user_email"]
                if (type(email1) == str):
                    email = email1
            
            TokenEmailer.validate_email(email)
            if (not email):
                raise CrossauthError(ErrorCode.FormEntry, "No password given but no email address found either")
            await self.__session_server.session_manager.request_password_reset(email)

        return success_fn({}, resp, None)
