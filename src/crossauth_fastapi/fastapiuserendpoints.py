from typing import Optional, Any, Dict, Callable, cast
from fastapi import Request, Response, Query

from crossauth_fastapi.fastapisessionserverbase import FastApiSessionServerOptions, FastApiSessionServerBase, JsonOrFormData, redirect
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.interfaces import User
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

    ############################3
    ## page endpoints


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
                "msg": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'configurefactor2',
                "ip": request.client.host if request.client else None
            }))
            try:
                def handle_success(data: Dict[str, Any], response: Response, _user: User|None) -> Response:
                    return self.__session_server.templates.TemplateResponse(
                        request, 
                        self.__signup_page, 
                        {
                            **data,
                            "next": next_param,
                        })
                
                return await self.__reconfigure_factor2(request, response, handle_success)
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "msg": "Configure factor2 failure",
                    "user": request.state.user["username"] if hasattr(request.state.user, 'username') else None,
                    "errorCode": ce.code.value,
                    "errorCodeName": ce.code.name
                }))
                CrossauthLogger.logger().debug(j({"err": str(e)}))
                
                def handle_error_fn(data: Dict[str,Any], error: CrossauthError):
                    return self.__session_server.templates.TemplateResponse(
                        request, 
                        self.__signup_page, 
                        {
                            "errorMessage": error.message,
                            "errorMessages": error.messages, 
                            "errorCode": error.code.value, 
                            "errorCodeName": error.code.name, 
                            "next": next_param, 
                            "csrfToken": request.state.csrf_token,
                            "allowedFactor2": self.__session_server.allowed_factor2_details(),
                            "urlPrefix": self.__prefix, 
                        }, error.http_status)
                
                return self.__session_server.handle_error(e, request, None,
                    lambda error, ce: handle_error_fn({}, ce))

        @self.app.post(self.__prefix + 'configurefactor2')
        async def post_configure_factor2(request: Request, response: Response) -> Response: # type: ignore
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": 'POST',
                "url": self.__prefix + 'configurefactor2',
                "ip": request.client.host if request.client else None
            }))
            
            # Get body data
            form = JsonOrFormData(request)
            await form.load()
            
            next_page = form.getAsStr1('next', self.__session_server.login_redirect) 
            
            
            try:
                CrossauthLogger.logger().debug(j({"msg": "Next page " + next_page}))

                def handle_success(reply: Response, user: User) -> Response:
                    # success

                    authenticator = self.__session_server.authenticators[user["factor2"]] if user and "factor2" in user and cast(Dict[str,Any],user)["factor2"] is not None and user["factor2"] != "" else None
                    
                    if (not self.__session_server.is_session_user(request) and
                        self.__session_server.enable_email_verification and
                        (authenticator is None or
                        authenticator.skip_email_verification_on_signup() != True)):
                        # email verification has been sent - tell user
                        return self.__session_server.templates.TemplateResponse(
                            request, 
                            self.__signup_page, 
                            {
                                "next": next_page,
                                "csrfToken": request.state.csrf_token,
                                "urlPrefix": self.__prefix,
                                "message": "Please check your email to finish signing up."
                            })
                    else:
                        if not self.__session_server.is_session_user(request):
                            # we came here as part of login in - take user to orignally requested page
                            return redirect(next_page, response, 302)
                        else:
                            # we came here because the user asked to change 2FA - tell them it was successful
                            return self.__session_server.templates.TemplateResponse(
                                request, 
                                self.__configure_factor2_page, 
                                {
                                "message": "Two-factor authentication updated",
                                "urlPrefix": self.__prefix,
                                "next": next_page,
                                "required": form.getAsBool1('required', False),
                                "csrfToken": request.state.csrf_token,
                                })

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
                            "msg": "Signup second factor failure",
                            "errorCodeName": ce.code.name,
                            "errorCode": ce.code.value
                        }))
                        CrossauthLogger.logger().error(j({
                            "msg": "Session not defined during two factor process"
                        }))
                        return self.__session_server.templates.TemplateResponse(
                            request, 
                            self.__session_server.error_page, 
                            {
                                "status": 500,
                                "errorMessage": "An unknown error occurred",
                                "errorCode": ErrorCode.UnknownError.value,
                                "errorCodeName": ErrorCode.UnknownError.name,
                            }, ce.http_status)

                    # normal error - wrong code, etc.  show the page again
                    data = await self.__session_server.session_manager.data_for_session_id(session_id)
                    data2fa = data["2fa"] if data and "2fa" in data else None
                    ce = CrossauthError.as_crossauth_error(e)
                    CrossauthLogger.logger().error(j({
                        "msg": "Signup two factor failure",
                        "user": data2fa.get('username') if data2fa and "username" in data2fa else None,
                        "errorCodeName": ce.code.name,
                        "errorCode": ce.code.value
                    }))
                    
                    def handle_error_fn(resp: Response, error: CrossauthError) -> Response:
                        return self.__session_server.templates.TemplateResponse(
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
                            }, error.http_status)
                    
                    return self.__session_server.handle_error(e, request, form,
                        lambda error, ce: handle_error_fn(response, ce))
                except Exception as e2:
                    # self is reached if there is an error processing the error
                    CrossauthLogger.logger().error(j({"err": str(e2)}))
                    response = Response(status_code=500)
                    return self.__session_server.templates.TemplateResponse(
                        request, 
                        self.__session_server.error_page, {
                            "status": 500,
                            "errorMessage": "An unknown error occurred",
                            "errorCode": ErrorCode.UnknownError.value,
                            "errorCodeName": ErrorCode.UnknownError.name,
                            })

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
