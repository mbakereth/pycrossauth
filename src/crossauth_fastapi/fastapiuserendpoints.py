from typing import Optional, Any, Dict, Callable, cast
from fastapi import Request, Response, Query
import re

from crossauth_fastapi.fastapisessionserverbase import *
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.crypto import Crypto
from crossauth_backend.common.interfaces import User, UserState
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.auth import AuthenticationParameters

class FastApiUserEndpoints():
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

        self.__prefix : str = "/"
        self.__update_user_page: str = "updateuser.njk"
        self.__change_factor2_page: str = "changefactor2.njk"
        self.__configure_factor2_page: str = "configurefactor2.njk"
        self.__change_password_page: str = "changepassword.njk"
        self.__reset_password_page: str = "resetpassword.njk"
        self.__request_password_reset_page: str = "requestpasswordreset.njk"
        self.__email_verified_page: str = "emailverified.njk"
        self.__signup_page: str = "signup.njk"
        self.__delete_user_page: str = "deleteuser.njk"
        self.__enable_email_verification : bool = True
        self.__enable_password_reset : bool = False

        set_parameter("prefix", ParamType.String, self, options, "PREFIX")
        set_parameter("enable_email_verification", ParamType.Boolean, self, options, "ENABLE_EMAIL_VERIFICATION")
        set_parameter("enable_password_reset", ParamType.Boolean, self, options, "ENABLE_PASSWORD_RESET")
        set_parameter("update_user_page", ParamType.String, self, options, "UPDATE_USER_PAGE")
        set_parameter("change_factor2_page", ParamType.String, self, options, "CHANGE_FACTOR2_PAGE")
        set_parameter("configure_factor2_page", ParamType.String, self, options, "SIGNUP_FACTOR2_PAGE")
        set_parameter("change_password_page", ParamType.String, self, options, "CHANGE_PASSWORD_PAGE")
        set_parameter("reset_password_page", ParamType.String, self, options, "RESET_PASSWORD_PAGE")
        set_parameter("request_password_reset_page", ParamType.String, self, options, "REQUEST_PASSWORD_RESET_PAGE")
        set_parameter("email_verified_page", ParamType.String, self, options, "EMAIL_VERIFIED_PAGE")
        set_parameter("signup_page", ParamType.String, self, options, "SIGNUP_PAGE")
        set_parameter("delete_user_page", ParamType.String, self, options, "DELETE_USER_PAGE")

    ############################
    ## page endpoints

    def add_update_user_endpoints(self) -> None:

        @self.app.get(self.__prefix + 'updateuser')
        async def get_update_user( # type: ignore
            request: Request,
            response: Response,
        ) -> Response:
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'updateuser',
                "ip": request.client.host if request.client else None
            }))
            return send_with_cookies(self.__session_server.templates.TemplateResponse(
                request,
                self.__update_user_page, 
                {
                    "csrfToken": request.state.csrf_token,
                }), request)
                
        @self.app.post(self.__prefix + 'updateuser')
        async def post_update_user(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'POST',
                "url": self.__prefix + 'updateuser',
                "ip": request.client.host if request.client else None
            }))
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()
            body = form.to_dict()

            if (not self.__session_server.can_edit_user(request)):
                return self.__session_server.send_page_error(request, response, 401, "User edit is not supported")
            
            extra_fields : Dict[str,Any] = {}
            for field in body:
                if (field.startswith("user_")):
                    extra_fields[field] = body[field]
            
            try:
                def handle_success(reply: Response, user: User|None, email_verification_required: bool) -> Response:
                    # success
                    message = \
                        "Please click on the link in your email to verify your email address." \
                        if email_verification_required else \
                        "Your details have been updated"

                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                        request,
                        self.__update_user_page, 
                        {
                            "csrfToken": request.state.csrf_token,
                            "urlPrefix": self.__prefix,
                            "isAdmin": False,
                            "message": message,
                            "allowedFactor2": self.__session_server.allowed_factor2_details(),
                        }), request)
                
                return await self.__update_user(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Update user failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__update_user_page, 
                            {
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                                "urlPrefix": self.__prefix, 
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__session_server.error_page, {
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_delete_user_endpoints(self) -> None:

        @self.app.get(self.__prefix + 'deleteuser')
        async def get_delete_user( # type: ignore
            request: Request,
            response: Response,
        ) -> Response:
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'deleteuser',
                "ip": request.client.host if request.client else None
            }))
            return send_with_cookies(self.__session_server.templates.TemplateResponse(
                request,
                self.__delete_user_page, 
                {
                    "csrfToken": request.state.csrf_token,
                }), request)
                
        @self.app.post(self.__prefix + 'deleteuser')
        async def post_delete_user(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'POST',
                "url": self.__prefix + 'deleteuser',
                "ip": request.client.host if request.client else None
            }))
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()
            body = form.to_dict()

            if (not self.__session_server.can_edit_user(request)):
                return self.__session_server.send_page_error(request, response, 401, "User edit is not supported")
            
            extra_fields : Dict[str,Any] = {}
            for field in body:
                if (field.startswith("user_")):
                    extra_fields[field] = body[field]
            
            try:
                next_page = form.getAsStr1('next', self.__session_server.login_redirect) 
                userid = request.state.user["id"] if "id" in request.state.user else None
                def handle_success(reply: Response) -> Response:
                    # success

                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                        request,
                        self.__delete_user_page, 
                        {
                            "csrfToken": request.state.csrf_token,
                            "urlPrefix": self.__prefix,
                            "next": next_page,
                            "userid": userid,
                            "isAdmin": False,
                            "allowedFactor2": self.__session_server.allowed_factor2_details(),
                        }), request)
                
                return await self.__delete_user(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Update user failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__delete_user_page, 
                            {
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                                "urlPrefix": self.__prefix, 
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__session_server.error_page, {
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_configure_factor2endpoints(self) -> None:
        """
        Adds the `configurefactor2` GET and POST endpoints.
        """

        @self.app.get(self.__prefix + 'configurefactor2')
        async def get_configure_factor2( # type: ignore
            request: Request,
            response: Response,
            next_param: Optional[str] = Query(None, alias="next")
        ) -> Response:
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'configurefactor2',
                "ip": request.client.host if request.client else None
            }))
            try:
                def handle_success(data: Dict[str, Any], response: Response, _user: User|None) -> Response:
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                        request,
                        self.__signup_page, 
                        {
                            **data,
                            "next": next_param,
                        }), request)
                
                return await self.__reconfigure_factor2(request, response, handle_success)
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "message": "Configure factor2 failure",
                    "user": request.state.user["username"] if "username" in request.state.user else None,
                    "errorCode": ce.code.value,
                    "errorCodeName": ce.code.name
                }))
                CrossauthLogger.logger().debug(j({"err": str(e)}))
                
                def handle_error_fn(data: Dict[str,Any], error: CrossauthError):
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                        request,
                        self.__signup_page, 
                        {
                            "ok": False,
                            "errorMessage": error.message,
                            "errorMessages": error.messages, 
                            "errorCode": error.code.value, 
                            "errorCodeName": error.code.name, 
                            "next": next_param, 
                            "csrfToken": request.state.csrf_token,
                            "allowedFactor2": self.__session_server.allowed_factor2_details(),
                            "urlPrefix": self.__prefix, 
                        }, error.http_status), request)
                
                return self.__session_server.handle_error(e, request, None,
                    lambda error, ce: handle_error_fn({}, ce))

        @self.app.post(self.__prefix + 'configurefactor2')
        async def post_configure_factor2(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'POST',
                "url": self.__prefix + 'configurefactor2',
                "ip": request.client.host if request.client else None
            }))
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()
            
            next_page = form.getAsStr1('next', self.__session_server.login_redirect) 
            
            
            try:
                CrossauthLogger.logger().debug(j({"message": "Next page " + next_page}))

                def handle_success(reply: Response, user: User) -> Response:
                    # success
                    
                    if (user["state"] == UserState.awaiting_email_verification):
                        # email verification has been sent - tell user
                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__signup_page, 
                            {
                                "next": next_page,
                                "csrfToken": request.state.csrf_token,
                                "urlPrefix": self.__prefix,
                                "message": "Please check your email to finish signing up."
                            }), request)
                    else:
                        if not self.__session_server.is_session_user(request):
                            # we came here as part of login in - take user to orignally requested page
                            return redirect(next_page, response, request, 302)
                        else:
                            # we came here because the user asked to change 2FA - tell them it was successful
                            return send_with_cookies(self.__session_server.templates.TemplateResponse(
                                request,
                                self.__configure_factor2_page, 
                                {
                                "message": "Two-factor authentication updated",
                                "urlPrefix": self.__prefix,
                                "isAdmin": False,
                                "next": next_page,
                                "required": form.getAsBool1('required', False),
                                "csrfToken": request.state.csrf_token,
                                }), request)

                return await self.__configure_factor2(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:
                    session_id = request.state.session_id
                    if not session_id:
                        # self shouldn't happen - user's cannot call self URL without having a session,
                        # user or anonymous.  However, just in case...
                        ce = CrossauthError.as_crossauth_error(e)
                        CrossauthLogger.logger().error(j({
                            "message": "Signup second factor failure",
                            "errorCodeName": ce.code.name,
                            "errorCode": ce.code.value
                        }))
                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__session_server.error_page, 
                            {
                                "status": 500,
                                "errorMessage": "An unknown error occurred",
                                "errorCode": ErrorCode.UnknownError.value,
                                "errorCodeName": ErrorCode.UnknownError.name,
                            }, ce.http_status), request)

                    # normal error - wrong code, etc.  show the page again
                    data = await self.__session_server.session_manager.data_for_session_id(session_id)
                    data2fa = data["2fa"] if data and "2fa" in data else None
                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Signup two factor failure",
                        "user": data2fa.get('username') if data2fa and "username" in data2fa else None,
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__configure_factor2_page, 
                            {
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "next": next_page, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                                "urlPrefix": self.__prefix, 
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__session_server.error_page, {
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_request_password_reset_endpoints(self) -> None:

        @self.app.get(self.__prefix + 'requestpasswordreset')
        async def get_request_password_reset( # type: ignore
            request: Request,
            response: Response,
            next_param: Optional[str] = Query(None, alias="next"),
            required_param: Optional[str] = Query(None, alias="required")
        ) -> Response:
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'requestpasswordreset',
                "ip": request.client.host if request.client else None
            }))
            return send_with_cookies(self.__session_server.templates.TemplateResponse(
                request,
                self.__request_password_reset_page, 
                {
                    "csrfToken": request.state.csrf_token,
                    "next": next_param,
                    "required": required_param is not None and len(required_param) > 0 and required_param[:1].lower() in ("t", "y", "1"),
                }), request)
                
        @self.app.post(self.__prefix + 'requestpasswordreset')
        async def post_request_password_reset(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'POST',
                "url": self.__prefix + 'requestpasswordreset',
                "ip": request.client.host if request.client else None
            }))
            message = "If a user with exists with the email you entered, a message with " \
                + " a link to reset your password has been sent."; 
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()
            email = form.getAsStr("email")

            next_page = form.getAsStr1('next', self.__session_server.login_redirect) 
            
            try:
                CrossauthLogger.logger().debug(j({"message": "Next page " + next_page}))

                def handle_success(reply: Response) -> Response:
                    # success

                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__request_password_reset_page, 
                            {
                                "next": next_page,
                                "csrfToken": request.state.csrf_token,
                                "message": message,
                                "isAdmin": False,
                                "urlPrefix": self.__prefix,
                                "email": email,
                            }), request)
                
                return await self.__request_password_reset(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Request password reset failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__request_password_reset_page, 
                            {
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "next": next_page, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                                "urlPrefix": self.__prefix, 
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__session_server.error_page, {
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_password_reset_endpoints(self) -> None:

        @self.app.get(self.__prefix + 'resetpassword')
        async def get_password_reset( # type: ignore
            request: Request,
            response: Response,
            token: str,
        ) -> Response:
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'resetpassword',
                "ip": request.client.host if request.client else None
            }))
            return send_with_cookies(self.__session_server.templates.TemplateResponse(
                request,
                self.__reset_password_page, 
                {
                    "csrfToken": request.state.csrf_token,
                    "token": token,
                }), request)
                
        @self.app.post(self.__prefix + 'resetpassword')
        async def post_password_reset(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'POST',
                "url": self.__prefix + 'resetpassword',
                "ip": request.client.host if request.client else None
            }))
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()            
            
            try:
                def handle_success(reply: Response, user: User|None) -> Response:
                    # success

                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__reset_password_page, 
                            {
                                "csrfToken": request.state.csrf_token,
                                "message": "Your password has been changed.",
                                "isAdmin": False,
                                "urlPrefix": self.__prefix,
                                "user": user,
                            }), request)
                
                return await self.__reset_password(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Password reset failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__reset_password_page, 
                            {
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "token": form.getAsStr("token"), 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                                "urlPrefix": self.__prefix, 
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__session_server.error_page, {
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_verify_email_endpoints(self) -> None:

        @self.app.get(self.__prefix + 'verifyemail/{token}')
        async def get_verify_email( # type: ignore
            request: Request,
            response: Response,
            token: str,
        ) -> Response:
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'verifyemail',
                "ip": request.client.host if request.client else None
            }))

            try:

                def success_fn(response: Response, user: User) -> Response:
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                                            request,
                                            self.__email_verified_page, 
                                            {
                                                "urlPrefix": self.__prefix,
                                                "isAdmin": False,
                                                "user": user,
                                            }), request)                    
                return await self.__verify_email(token, request, response, success_fn)
                
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Verify email failed",
                        "hashedToken": Crypto.hash(token),
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__email_verified_page, 
                            {
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                                "urlPrefix": self.__prefix, 
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, None,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__session_server.error_page, {
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_change_password_endpoints(self) -> None:

        @self.app.get(self.__prefix + 'changepassword')
        async def get_change_password( # type: ignore
            request: Request,
            response: Response,
            next_param: Optional[str] = Query(None, alias="next"),
            required_param: Optional[str] = Query(None, alias="required")
        ) -> Response:
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'changepassword',
                "ip": request.client.host if request.client else None
            }))

            if (not self.__session_server.is_session_user(request) or not request.state.user):
                # user is not logged on - check if there is an anonymous 
                # session with passwordchange set (meaning the user state
                # was set to UserState.passwordChangeNeeded when logging on)
                data = \
                    await self.__session_server.get_session_data(request, "passwordchange")
                if (data is None or "username" not in data or data["username"] is None):
                    if (not self.__session_server.is_session_user(request)):
                        return self.__session_server.send_page_error(
                            request,
                            response,
                            401,
                            self.__session_server.error_page)

            return send_with_cookies(self.__session_server.templates.TemplateResponse(
                request,
                self.__change_password_page, 
                {
                    "csrfToken": request.state.csrf_token,
                    "isAdmin": False,
                    "next": next_param,
                    "required": required_param is not None and len(required_param) > 0 and required_param[:1].lower() in ("t", "y", "1"),
                }), request)
                
        @self.app.post(self.__prefix + 'changepassword')
        async def post_change_password(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'POST',
                "url": self.__prefix + 'changepassword',
                "ip": request.client.host if request.client else None
            }))
            message = "Your password has been changed."; 
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()

            next_page = form.getAsStr1('next', self.__session_server.login_redirect) 
            required = form.getAsBool1('required', False) 
            
            try:
                CrossauthLogger.logger().debug(j({"message": "Next page " + next_page}))

                def handle_success(reply: Response, user: User|None) -> Response:
                    # success

                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__change_password_page, 
                            {
                                "next": next_page,
                                "csrfToken": request.state.csrf_token,
                                "message": message,
                                "isAdmin": False,
                                "urlPrefix": self.__prefix,
                                "required": required,
                            }), request)
                
                return await self.__change_password(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Request password reset failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__change_password_page, 
                            {
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "next": next_page, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                                "urlPrefix": self.__prefix, 
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__session_server.error_page, {
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_change_factor2_endpoints(self) -> None:

        @self.app.get(self.__prefix + 'changefactor2')
        async def get_change_factor2( # type: ignore
            request: Request,
            response: Response,
            next_param: Optional[str] = Query(None, alias="next"),
        ) -> Response:
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'changefactor2',
                "ip": request.client.host if request.client else None
            }))
            if (not self.__session_server.is_session_user(request) or not request.state.user):
                # user is not logged on - check if there is an anonymous 
                # session with passwordchange set (meaning the user state
                # was set to UserState.passwordChangeNeeded when logging on)
                data = \
                    await self.__session_server.get_session_data(request, "factor2change")
                if (data is None or "username" not in data or data["username"] is None):
                    if (not self.__session_server.is_session_user(request)):
                        return self.__session_server.send_page_error(
                            request,
                            response,
                            401,
                            self.__session_server.error_page)
                    
                
            
            return send_with_cookies(self.__session_server.templates.TemplateResponse(
                request,
                self.__change_factor2_page, 
                {
                    "csrfToken": request.state.csrf_token,
                    "next": next_param,
                }), request)
                
        @self.app.post(self.__prefix + 'changefactor2')
        async def post_change_factor2(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "Page visit",
                "method": 'POST',
                "url": self.__prefix + 'changefactor2',
                "ip": request.client.host if request.client else None
            }))
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()

            next_page = form.getAsStr1('next', self.__session_server.login_redirect) 
            
            try:
                CrossauthLogger.logger().debug(j({"message": "Next page " + next_page}))

                def handle_success(reply: Response, data: Dict[str,Any], user: User|None) -> Response:
                    # success

                        if ("factor2" in data and data["factor2"] is not None):
                            return send_with_cookies(self.__session_server.templates.TemplateResponse(
                                request,
                                self.__configure_factor2_page, 
                                {
                                    "next": next_page,
                                    "csrfToken": request.state.csrf_token,
                                    **data["userData"],
                                    "urlPrefix": self.__prefix,
                                }), request)
                        else:
                            return send_with_cookies(self.__session_server.templates.TemplateResponse(
                                request,
                                self.__configure_factor2_page, 
                                {
                                    "next": next_page,
                                    "csrfToken": request.state.csrf_token,
                                    "isAdmin": False,
                                    "message": "Two factor authentication has been updated",
                                    "urlPrefix": self.__prefix,
                                }), request)
                
                return await self.__change_factor2(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Request password reset failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__change_factor2_page, 
                            {
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "next": next_page, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                                "urlPrefix": self.__prefix, 
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(self.__session_server.templates.TemplateResponse(
                            request,
                            self.__session_server.error_page, {
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    ############################
    ## API endpoints

    def add_api_update_user_endpoints(self) -> None:
                
        @self.app.post(self.__prefix + 'api/updateuser')
        async def post_update_user(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "API visit",
                "method": 'POST',
                "url": self.__prefix + 'api/updateuser',
                "ip": request.client.host if request.client else None
            }))
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()            
            
            try:

                def handle_success(reply: Response, user: User|None, email_verification_required: bool) -> Response:
                    # success

                    return send_with_cookies(JSONResponse(
                        {
                            "ok": True,
                            "emailVerificationRequired": email_verification_required,
                        }), request)
                
                return await self.__update_user(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Update user failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": False,
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(JSONResponse({
                            "ok": False,
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_api_delete_user_endpoints(self) -> None:
                
        @self.app.post(self.__prefix + 'api/deleteuser')
        async def post_delete_user(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "API visit",
                "method": 'POST',
                "url": self.__prefix + 'api/deleteuser',
                "ip": request.client.host if request.client else None
            }))
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()            
            
            try:

                def handle_success(reply: Response) -> Response:
                    # success

                    return send_with_cookies(JSONResponse(
                        {
                            "ok": True,
                        }), request)
                
                return await self.__delete_user(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Delete user failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": False,
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(JSONResponse({
                            "ok": False,
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_api_configure_factor2endpoints(self) -> None:
        """
        Adds the `configurefactor2` GET and POST endpoints.
        """

        @self.app.get(self.__prefix + 'api/configurefactor2')
        async def get_api_configure_factor2( # type: ignore
            request: Request,
            response: Response,
        ) -> Response:
            CrossauthLogger.logger().info(j({
                "message": "API visit",
                "method": 'GET',
                "url": self.__prefix + 'api/onfigurefactor2',
                "ip": request.client.host if request.client else None
            }))
            try:
                def handle_success(data: Dict[str, Any], response: Response, _user: User|None) -> Response:
                    return send_with_cookies(JSONResponse(
                        {
                            "ok": True,
                            **data,
                        }, headers=JSONHDRMAP), request)
                
                return await self.__reconfigure_factor2(request, response, handle_success)
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "message": "Configure factor2 failure",
                    "user": request.state.user["username"] if "username" in request.state.user else None,
                    "errorCode": ce.code.value,
                    "errorCodeName": ce.code.name
                }))
                CrossauthLogger.logger().debug(j({"err": str(e)}))
                
                def handle_error_fn(data: Dict[str,Any], error: CrossauthError):
                    return send_with_cookies(JSONResponse(
                        {
                            "ok": False,
                            "errorMessage": error.message,
                            "errorMessages": error.messages, 
                            "errorCode": error.code.value, 
                            "errorCodeName": error.code.name, 
                            "csrfToken": request.state.csrf_token,
                            "allowedFactor2": self.__session_server.allowed_factor2_details(),
                        }, status_code=error.http_status, headers=JSONHDRMAP), request)
                
                return self.__session_server.handle_error(e, request, None,
                    lambda error, ce: handle_error_fn({}, ce))

        @self.app.post(self.__prefix + 'api/configurefactor2')
        async def post_api_configure_factor2(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "API visit",
                "method": 'POST',
                "url": self.__prefix + 'api/configurefactor2',
                "ip": request.client.host if request.client else None
            }))
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()            
            
            try:
                def handle_success(reply: Response, user: User) -> Response:
                    # success
                    
                    resp : Dict[str, Any] = {
                        "csrfToken": request.state.csrf_token,
                        "urlPrefix": self.__prefix,
                        "message": "Please check your email to finish signing up."

                    }
                    
                    if (user["state"] == UserState.awaiting_email_verification):
                        # email verification has been sent - tell user
                        resp["emailVerificationNeeded"] = self.__session_server.enable_email_verification
                    return send_with_cookies(JSONResponse(
                        {
                            "ok": True,
                            "user" : user,    
                        }, headers=JSONHDRMAP), request)

                return await self.__configure_factor2(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:
                    session_id = request.state.session_id
                    if not session_id:
                        # self shouldn't happen - user's cannot call self URL without having a session,
                        # user or anonymous.  However, just in case...
                        ce = CrossauthError.as_crossauth_error(e)
                        CrossauthLogger.logger().error(j({
                            "message": "Signup second factor failure",
                            "errorCodeName": ce.code.name,
                            "errorCode": ce.code.value
                        }))
                        CrossauthLogger.logger().error(j({
                            "message": "Session not defined during two factor process"
                        }))
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": False,
                                "status": 500,
                                "errorMessage": "An unknown error occurred",
                                "errorCode": ErrorCode.UnknownError.value,
                                "errorCodeName": ErrorCode.UnknownError.name,
                            }, headers=JSONHDRMAP, status_code=ce.http_status), request)

                    # normal error - wrong code, etc.  show the page again
                    data = await self.__session_server.session_manager.data_for_session_id(session_id)
                    data2fa = data["2fa"] if data and "2fa" in data else None
                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Signup two factor failure",
                        "user": data2fa.get('username') if data2fa and "username" in data2fa else None,
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": False,
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                            }, headers=JSONHDRMAP, status_code=error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(JSONResponse({
                            "ok": False,
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, headers=JSONHDRMAP, status_code=500), request)

    def add_api_request_password_reset_endpoints(self) -> None:
                
        @self.app.post(self.__prefix + 'api/requestpasswordreset')
        async def post_request_password_reset(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "API visit",
                "method": 'POST',
                "url": self.__prefix + 'api/requestpasswordreset',
                "ip": request.client.host if request.client else None
            }))
            message = "If a user with exists with the email you entered, a message with " \
                + " a link to reset your password has been sent."; 
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()            
            email = form.getAsStr("email")
            
            try:

                def handle_success(reply: Response) -> Response:
                    # success

                        return send_with_cookies(JSONResponse(
                            {
                                "ok": True,
                                "email": email,
                                "message": message,
                            }), request)
                
                return await self.__request_password_reset(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Request password reset failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": False,
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(JSONResponse({
                            "ok": False,
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_api_password_reset_endpoints(self) -> None:
                
        @self.app.post(self.__prefix + 'api/resetpassword')
        async def post_request_password_reset(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "API visit",
                "method": 'POST',
                "url": self.__prefix + 'api/resetpassword',
                "ip": request.client.host if request.client else None
            }))

            # Get body data
            form = JsonOrFormData(request)
            await form.load()            
            
            try:

                def handle_success(reply: Response, user: User|None) -> Response:
                    # success

                        return send_with_cookies(JSONResponse(
                            {
                                "ok": True,
                                "user": user,
                            }), request)
                
                return await self.__reset_password(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Request password reset failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": False,
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(JSONResponse({
                            "ok": False,
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_api_change_password_endpoints(self) -> None:
                
        @self.app.post(self.__prefix + 'api/changepassword')
        async def post_change_password(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "API visit",
                "method": 'POST',
                "url": self.__prefix + 'api/changepassword',
                "ip": request.client.host if request.client else None
            }))
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()            
            
            message = "Your password has been changed."

            try:

                def handle_success(reply: Response, user: User|None) -> Response:
                    # success

                        return send_with_cookies(JSONResponse(
                            {
                                "ok": True,
                                "message": message,
                                "urlPrefix": self.__prefix,
                            }), request)
                
                return await self.__change_password(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Change password failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": False,
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(JSONResponse({
                            "status": 500,
                            "ok": False,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_api_change_factor2_endpoints(self) -> None:
                
        @self.app.post(self.__prefix + 'api/changefactor2')
        async def post_change_password(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "message": "API visit",
                "method": 'POST',
                "url": self.__prefix + 'api/changefactor2',
                "ip": request.client.host if request.client else None
            }))
            # Get body data
            form = JsonOrFormData(request)
            await form.load()            

            if (not self.__session_server.is_session_user(request)):
                return self.__session_server.send_json_error(request, response, 401)

            try:

                def handle_success(reply: Response, data: Dict[str, Any], user: User|None) -> Response:
                    # success

                        return send_with_cookies(JSONResponse(
                            {
                                "ok": True,
                                "urlPrefix": self.__prefix,
                                **data["userData"]
                            }), request)
                
                return await self.__change_factor2(request, response, form, handle_success)
            except Exception as e:
                # error

                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Change factor2 failure",
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(JSONResponse(
                            {
                                "ok": False,
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                                "allowedFactor2": self.__session_server.allowed_factor2_details(),
                            }, error.http_status), request)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(JSONResponse({
                            "status": 500,
                            "ok": False,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500), request)

    def add_api_verify_email_endpoints(self) -> None:

        @self.app.get(self.__prefix + 'api/verifyemail/{token}')
        async def get_verify_email( # type: ignore
            request: Request,
            response: Response,
            token: str,
        ) -> Response:
            CrossauthLogger.logger().info(j({
                "message": "API visit",
                "method": 'GET',
                "url": self.__prefix + 'verifyemail',
                "ip": request.client.host if request.client else None
            }))

            try:

                return await self.__verify_email(token, request, response, lambda response, user: send_with_cookies(JSONResponse(
                        {
                            "urlPrefix": self.__prefix,
                            "user": user,
                        }, headers=JSONHDRMAP), request))
                
            except Exception as e:
                # error
                CrossauthLogger.logger().debug(j({"err": str(e)}))
                try:

                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "message": "Verify email failed",
                        "hashedToken": Crypto.hash(token),
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return send_with_cookies(JSONResponse({
                                "ok": False,
                                "errorMessage": error.message,
                                "errorMessages": error.messages, 
                                "errorCode": error.code.value, 
                                "errorCodeName": error.code.name, 
                                "csrfToken": request.state.csrf_token,
                            }, error.http_status, headers=JSONHDRMAP), request)
                    
                    return self.__session_server.handle_error(e, request, None,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return send_with_cookies(JSONResponse({
                            "ok": False,
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            }, status_code=500, headers=JSONHDRMAP), request)

    ##########################################
    ## Shared between page and API endpoints

    async def __configure_factor2(
        self,
        request: Request,  # FastifyRequest equivalent with Body type
        response: Response,  # FastifyReply equivalent
        form: JsonOrFormData,
        success_fn: Callable[[Response, User], Response]
    ) -> Response:
        """
        Configure Factor 2 authentication.
        
        :param request: The request object containing the body with ConfigureFactor2BodyType
        :param reply: The reply/response object
        :param  success_fn: Success callback function that takes response and optional user
        """
        
        body = form.to_dict()

        # validate the CSRF token
        # await self.validate_csrf_token(request)
        if self.__session_server.is_session_user(request) and not request.state.csrf_token:
            raise CrossauthError(ErrorCode.InvalidCsrf)
        
        # get the session - it may be a real user or anonymous
        if not request.state.session_id:
            raise CrossauthError(
                ErrorCode.Unauthorized,
                "No session active while enabling 2FA.  Please enable cookies"
            )
        
        # finish 2FA setup - validate secrets and update user
        user = await self.__session_server.session_manager.complete_two_factor_setup(
            cast(AuthenticationParameters, body),
            request.state.session_id
        )
        
        if not self.__session_server.is_session_user(request) and not self.__session_server.enable_email_verification:
            # we skip the login if the user is already logged in and we are not doing email verification
            return await self.__session_server.login_with_user(
                user,
                True,
                request,
                response,
                lambda req, usr: success_fn(req, usr)
            )
        
        return success_fn(response, user)

    async def __reconfigure_factor2(
        self,
        request: Request,  
        response: Response,    
        success_fn: Callable[[Dict[str,Any], Response, User|None], Response]
    ) -> Response:
        """
        Reconfigure the second factor authentication for a user.
        
        Can only call this if logged in and CSRF token is valid.
        """
        
        # can only call this if logged in and CSRF token is valid
        if (not request.state.user or 
            not request.state.session_id or 
            not self.__session_server.is_session_user(request)):
            raise CrossauthError(ErrorCode.Unauthorized)

        # get second factor authenticator
        factor2: str = request.state.user["factor2"] if "factor2" in request.state.user else ""
        authenticator = self.__session_server.authenticators.get(factor2)
        if not authenticator or len(authenticator.secret_names()) == 0:
            raise CrossauthError(
                ErrorCode.BadRequest,
                "Selected second factor does not have configuration"
            )

        # step one in 2FA setup - create secrets and get data to display to user
        user_data = await self.__session_server.session_manager.initiate_two_factor_setup(
            request.user,
            factor2,
            request.state.session_id
        )

        # show user result
        data: Dict[str, Any] = {
            **user_data,
            "csrf_token": request.state.csrf_token,
        }
        return success_fn(data, response, None)

    async def __request_password_reset(
        self,
        request: Request,  
        response: Response,    
        form: JsonOrFormData,
        success_fn: Callable[[Response], Response]
    ) -> Response:
        
        # this has to be enabled in configuration
        if (not self.__enable_password_reset):
            raise CrossauthError(ErrorCode.Configuration,
                 "password reset not enabled")

        # validate CSRF token
        if (not request.state.csrf_token ):
            raise CrossauthError(ErrorCode.InvalidCsrf)

        # send password reset mail
        email = form.getAsStr("email")
        if (email is None or email == ""):
            raise CrossauthError(ErrorCode.BadRequest, "Must provide email address")
        try:
            await self.__session_server.session_manager.request_password_reset(email)
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            if (ce.code == ErrorCode.UserNotExist):
                # fail silently - don't let user know email doesn't exist
                CrossauthLogger.logger().warn(j({"message": "Password reset requested for invalid email", "email": email}))
            else:
                CrossauthLogger.logger().error(j({"message": "Couldn't send password reset email", "email": email}))
                raise ce

        return success_fn(response)

    async def __reset_password(
        self,
        request: Request,  
        response: Response,    
        form: JsonOrFormData,
        success_fn: Callable[[Response, User|None], Response]
    ) -> Response:
        
        # this has to be enabled in configuration
        if (not self.__enable_password_reset):
            raise CrossauthError(ErrorCode.Configuration,
                 "password reset not enabled")

        # validate CSRF token
        if (not request.state.csrf_token ):
            raise CrossauthError(ErrorCode.InvalidCsrf)

        # get token and associated user
        token = form.getAsStr("token")
        if (not token):
            raise CrossauthError(ErrorCode.BadRequest, "Must provide token")
        user = await self.__session_server.session_manager.user_for_password_reset_token(token)
        body = form.to_dict()

        # get secrets from the request body
        # there should be new_{secret} and repeat_{secret}
        if (user["factor1"] not in self.__session_server.authenticators):
            raise CrossauthError(ErrorCode.Unauthorized, "Unrecognised factor1")
        authenticator = self.__session_server.authenticators[user["factor1"]]
        secret_names = authenticator.secret_names()
        new_secrets : AuthenticationParameters|None = {}
        repeat_secrets : AuthenticationParameters|None = {}
        found = False
        for field in body:
            if field.startswith("repeat_"):
                name = field[7:]
                if name in secret_names:
                    repeat_secrets[name] = body[field]
                    found = True
            elif field.startswith("new_"):
                name = field[4:]
                if name in secret_names:
                    new_secrets[name] = body[field]
        if (not found):
            repeat_secrets = None

        # validate the new secrets (with the implementor-provided function)
        errors = authenticator.validate_secrets(new_secrets)
        if len(errors) > 0:
            raise CrossauthError(ErrorCode.PasswordFormat, errors)
        
        # check new and repeat secrets are valid and update the user
        user1 = await self.__session_server.session_manager.reset_secret(token, 1, new_secrets, repeat_secrets)
        if (user1["state"] != UserState.factor2_reset_needed):
            # log the user in
            return await self.__session_server.login_with_user(user1, True, request, response, success_fn)

        return success_fn(response, None)

    async def __change_password(
        self,
        request: Request,  
        response: Response,    
        form: JsonOrFormData,
        success_fn: Callable[[Response, User|None], Response]
    ) -> Response:
        
        # this has to be enabled in configuration
        if (not self.__enable_password_reset):
            raise CrossauthError(ErrorCode.Configuration,
                 "password reset not enabled")

        # validate CSRF token
        if (not request.state.csrf_token ):
            raise CrossauthError(ErrorCode.InvalidCsrf)

        body = form.to_dict()

        user : User|None = None
        required = False

        if (self.__session_server.user_storage is None):
            raise CrossauthError(ErrorCode.Configuration, "Cannot change password if user storage not defined")

        if (not self.__session_server.is_session_user(request) or not request.state.user):
            # user is not logged on - check if there is an anonymous 
            # session with passwordchange set (meaning the user state
            # was set to changepasswordneeded when logging on)
            data = await self.__session_server.get_session_data(request, "passwordchange")
            if (data is not None and "username" in data and data["username"] is not None):
                resp = await self.__session_server.user_storage.get_user_by_username(
                    data["username"], {
                        "skip_active_check": True,
                        "skip_email_verified_check": True,
                    })
                user = resp["user"]
                required = True
                if (not request.state.csrf_token):
                    raise CrossauthError(ErrorCode.InvalidCsrf)
            else:
                raise CrossauthError(ErrorCode.Unauthorized)
            
        elif (not self.__session_server.can_edit_user(request)):
            raise CrossauthError(ErrorCode.InsufficientPriviledges)
        else:
            if (self.__session_server.is_session_user(request) and not request.state.csrf_token):
                raise CrossauthError(ErrorCode.InvalidCsrf)
            
            user = request.state.user
        
        if (user is None):
            raise CrossauthError(ErrorCode.Unauthorized)

        # get the authenticator for factor1 (passwords on factor2 are not supported)
        authenticator = self.__session_server.authenticators[user["factor1"]]

        # the form should contain old_{secret}, new_{secret} and repeat_{secret}
        # extract them, making sure the secret is a valid one
        secret_names = authenticator.secret_names()
        old_secrets : AuthenticationParameters = {}
        new_secrets : AuthenticationParameters = {}
        repeat_secrets : AuthenticationParameters|None = {}
        for field in body:
            if (field.startswith("new_")):
                name = re.sub(r'^new_', "", field) 
                if (name in secret_names):
                    new_secrets[name] = body[field]
            elif (field.startswith("old_")):
                name = re.sub(r'^old_', "", field) 
                if (name in secret_names):
                    old_secrets[name] = body[field]
            elif (field.startswith("repeat_")):
                name = re.sub(r'^repeat_', "", field) 
                if (name in secret_names):
                    repeat_secrets[name] = body[field]
            
        if (len(repeat_secrets.keys()) == 0):
            repeat_secrets = None

        # validate the new secret - this is through an implementor-supplied function
        errors = authenticator.validate_secrets(new_secrets)
        if (len(errors) > 0):
            raise CrossauthError(ErrorCode.PasswordFormat, errors)
        
        # validate the old secrets, check the new and repeat ones match and 
        # update if valid
        old_state = user["state"]
        try:
            if (required):
                user["state"] = "active"
                await self.__session_server.user_storage.update_user({"id": user["id"], "state":user["state"]})
            
            await self.__session_server.session_manager.change_secrets(user["username"],
                1,
                new_secrets,
                repeat_secrets,
                old_secrets
            )
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": e}))
            if (required):
                try:
                    await self.__session_server.user_storage.update_user({"id": user["id"], "state": old_state})
                except Exception as e2:
                    CrossauthLogger.logger().debug(j({"err": e2}))
                
            raise ce

        if (required):
            # this was a forced change - user is not actually logged on
            return await self.__session_server.login_with_user(user, False, request, response, success_fn)
                
        return success_fn(response, None)

    async def __change_factor2(
        self,
        request: Request,  
        response: Response,    
        form: JsonOrFormData,
        success_fn: Callable[[Response, Dict[str,Any], User|None], Response]
    ) -> Response:
        
        # validate CSRF token
        if (not request.state.csrf_token ):
            raise CrossauthError(ErrorCode.InvalidCsrf)

        body = form.to_dict()

        user : User|None = None

        if (self.__session_server.user_storage is None):
            raise CrossauthError(ErrorCode.Configuration, "Cannot change factor2 if user storage not defined")

        if (not self.__session_server.is_session_user(request) or not request.state.user):
            # user is not logged on - check if there is an anonymous 
            # session with passwordchange set (meaning the user state
            # was set to changepasswordneeded when logging on)
            data = await self.__session_server.get_session_data(request, "factor2change")
            if (data is not None and "username" in data and data["username"] is not None):
                resp = await self.__session_server.user_storage.get_user_by_username(
                    data["username"], {
                        "skip_active_check": True,
                        "skip_email_verified_check": True,
                    })
                user = resp["user"]
                if (not request.state.csrf_token):
                    raise CrossauthError(ErrorCode.InvalidCsrf)
            else:
                raise CrossauthError(ErrorCode.Unauthorized)
            
        elif (not self.__session_server.can_edit_user(request)):
            raise CrossauthError(ErrorCode.InsufficientPriviledges)
        else:
            if (self.__session_server.is_session_user(request) and not request.state.csrf_token):
                raise CrossauthError(ErrorCode.InvalidCsrf)
            
            user = request.state.user
        
        if (user is None):
            raise CrossauthError(ErrorCode.Unauthorized)
        
        # make sure user is logged in
        if (not request.state.session_id):
            raise CrossauthError(ErrorCode.Unauthorized)

        # validate the requested factor2
        new_factor2 : str|None = body["factor2"] if "factor2" in body else None
        if (new_factor2 is not None and new_factor2 not in self.__session_server.allowed_factor2):
            raise CrossauthError(ErrorCode.Forbidden,
                 "Illegal second factor " + new_factor2 + " requested")
        if (new_factor2 == "none" or new_factor2 == ""):
            new_factor2 = None
        
        # get data to show user to finish 2FA setup
        userData = await self.__session_server.session_manager.initiate_two_factor_setup(user, new_factor2, request.state.session_id)

        ret_data : Dict[str,Any] = {
            "factor2": new_factor2,
            "userData": userData,
            "username": userData["username"] if "username" in userData else None,
            "next": body["next"] if next in body else self.__session_server.login_redirect,
            "csrfToken": request.state.csrf_token,
        }
        return success_fn(response, ret_data, None)

    async def __verify_email(self, token: str, request: Request, 
        response: Response, 
        success_fn : Callable[[Response, User], Response]) -> Response:

        # this has to be enabled in configuration
        if not self.__session_server.enable_email_verification:
            raise CrossauthError(ErrorCode.Configuration, 
                "Email verification reset not enabled")

        # get the email verification token

        # validate the token and log the user in
        user = \
            await self.__session_server.session_manager.apply_email_verification_token(token)
        return await self.__session_server.login_with_user(user, True, request, response, success_fn)
    
    async def __update_user(self, request: Request, 
        response: Response, 
        form: JsonOrFormData,
        success_fn : Callable[[Response, User, bool], Response]) -> Response:


        body = form.to_dict()

        if (not self.__session_server.can_edit_user(request) or not request.state.user):
            raise CrossauthError(ErrorCode.Unauthorized)
        
        # get new user fields from form, including from the 
        # implementor-provided hook
        user : User = {
            "id": request.state.user["id"],
            "username": request.state.user["username"],
            "state": UserState.active,
            "factor1": request.state.user["factor1"],
        }
        if (not self.__session_server.user_storage):
            raise CrossauthError(ErrorCode.Configuration, "Cannot update user as user storage not defined")
        user = self.__session_server.update_user_fn(user, request, body, self.__session_server.user_storage.user_editable_fields)

        # validate the new user using the implementor-provided function
        errors = self.__session_server.validate_user_fn(user)
        if (len(errors) > 0):
            raise CrossauthError(ErrorCode.FormEntry, errors)

        # update the user
        resp = await self.__session_server.session_manager.update_user(request.state.user, user)

        return success_fn(response, request.state.user, resp.email_verification_token_sent)
        
    async def __delete_user(self, request: Request, 
        response: Response, 
        form: JsonOrFormData,
        success_fn : Callable[[Response], Response]) -> Response:

        if (not self.__session_server.can_edit_user(request) or not request.state.user):
            raise CrossauthError(ErrorCode.Unauthorized)
        
        if (not self.__session_server.user_storage):
            raise CrossauthError(ErrorCode.Configuration, "Cannot update user as user storage not defined")

        # delete the user
        resp = await self.__session_server.session_manager.delete_user_by_username(request.state.user["username"])

        return success_fn(response)
        