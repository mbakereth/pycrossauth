# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import Callable, Self, Literal, List, NamedTuple, Dict, Any, Optional
from fastapi import Request, Response
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.oauth.client import OAuthTokenResponse
from crossauth_backend.oauth.client import OAuthClientOptions
from crossauth_backend.crypto import Crypto
from crossauth_fastapi.fastapiserver import FastApiErrorFn, FastApiServer
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, JSONResponse
import json
from datetime import datetime
from jwt import JWT

###################################################################
## OPTIONS

class BffEndpoint(NamedTuple):
    url: str
    methods: List[Literal["GET", "POST", "PUT", "DELETE", "PATCH"]]
    matchSubUrls: bool

class FastApiOAuthClientOptions(OAuthClientOptions, total=False):
    """
    Options for {@link FastApiOAuthClient}.
    """

    siteUrl: str
    """ 
    The base URL for endpoints served by this class.
    THe only endpoint that is created is the redirect Uri, which is
    `siteUrl` + `prefix` + `authzcode`,
    """

    prefix : str
    """
    The prefix between the `siteUrl` and endpoints created by this
    class.  See :class:`FastApiOAuthClientOptions.siteUrl`.
    """

    session_data_name : str
    """
    When using the BFF (backend-for-frontend) pattern, tokens are saved
    in the `data` field of the session ID.  They are saved in the JSON
    object with this field name.  Default `oauth`.
    """

    errorPage : str
    """
    The template file for rendering error messages
    when `FastApiOAuthClientOptions.errorResponseType`
    is `errorPage`.
    """

    passwordFlowPage : str
    """
    The template file for asking the user for username and password
    in the password flow,
    
    Default `passwordflow.junja2`
    """

    deviceCodeFlowPage : str
    """
    The template file to tell users the url to go to to complete the 
    device code flow.
    
    Default `devicecodeflow.njk`
    """

    deleteTokensPage : str
    """
    The template file to show the result in the `deletetokens` endpoint.
    
    Default `deletetokens.jinja2`
    """

    deleteTokensGetUrl : str
    """
    Tthe `deletetokens` GET endpoint.
    
    Default undefined - don't create the endpoint
    """

    deleteTokensPostUrl : str
    """
    Whether to add the `deletetokens` POST endpoint.
    
    Default undefined - don't create the endpoint
    """

    apiDeleteTokensPostUrl : str
    """
    Whether to add the `api/deletetokens` POST endpoint.
    
    Default undefined - don't create the endpoint
    """

    mfaOtpPage : str
    """
    The template file for asking the user for an OTP in the password MFA
    flow.
    """

    mfaOobPage : str
    """
    The template file for asking the user for an OOB in the password MFA
    flow.
    """

    authorizedPage : str
    """
    The template file for telling the user that authorization was successful.
    """

    authorizedUrl : str
    """
    If the {@link FastApiOAuthClientOptions.tokenResponseType} is
    `saveInSessionAndRedirect`, this is the relative URL that the usder
    will be redirected to after authorization is complete.
    """

    passwordFlowUrl : str
    """
    The URL to create the password flow under.  Default `passwordflow`.
    """

    deviceCodeFlowUrl : str
    """
    The URL to to create the device code flow under.  Default `devicecodeflow`.
    """

    deviceCodePollUrl : str
    """
    The URL to to for polling until the device code flow completes.  
    Default `devicecodepoll`.
    """

    passwordOtpUrl : str
    """
    The URL to create the otp endpoint for the password mfa flow under.  
    This endpoint asks the user for his or her OTP.
    Default `passwordflowotp`.
    """

    passwordOobUrl : str
    """
    The URL to create the otp endpoint for the password mfa flow under.  
    This endpoint asks the user for his or her OOB.
    Default `passwordflowoob`.
    """

    receiveTokenFn: Callable[[OAuthTokenResponse,
        Self,
        Request,
        Response], Response|None] 
    """
    This function is called after successful authorization to pass the
    new tokens to.
    - oauthResponse the response from the OAuth `token` endpoint.
    - client the fastify OAuth client
    - request the FastApi request
    - reply the FastApi reply
    - returns the FastApi reply
    """

    errorFn : FastApiErrorFn
    """
    The function to call when there is an OAuth error and
    {@link FastApiOAuthClientOptions.errorResponseType}
    is `custom`.
    See {@link FastApiErrorFn}.
    """

    tokenResponseType : Literal[
        "sendJson",
        "saveInSessionAndLoad",
        "saveInSessionAndRedirect",
        "sendInPage",
        "custom"]
    """
    What to do when receiving tokens.
    See :class:`FastApiOAuthClient` class documentation for full description.
    """

    errorResponseType : Literal[
        "sendJson", 
        "errorPage", 
        "custom"]
    """
    What do do on receiving an OAuth error.
    See lass documentation for full description.
    """

    bffEndpoints: List[BffEndpoint]
    """ 
    Array of resource server endppints to serve through the
    BFF (backend-for-frontend) mechanism.
    See :class:`FastApiOAuthClient` class documentation for full description.
    """

    bffEndpointName : str
    """
    Prefix for BFF endpoints.  Default "bff".
    See:class:`FastApiOAuthClient` class documentation for full description.
    """

    bffBaseUrl : str
    """
    Base URL for resource server endpoints called through the BFF
    mechanism.
    See {@link FastApiOAuthClient} class documentation for full description.
    """

    tokenEndpoints : List[Literal["access_token", "refresh_token", "id_token",
        "have_access_token", "have_refresh_token", "have_id_token"]]
    """
    Endpoints to provide to acces tokens through the BFF mechanism,
    See {@link FastApiOAuthClient} class documentation for full description.
    """

    """
    Set of flows to enable (see {@link @crossauth/common!OAuthFlows}).
    
    Defaults to empty.
    """
    validFlows : List[str]

##############################################################
## Class

class FastApiOAuthClient:
    @property
    def templates(self): return self._templates

    @property
    def error_page(self): return self._error_page

    @property
    def authorized_page(self): return self._authorized_page

    @property
    def authorized_url(self): return self._authorized_url

    @property
    def server(self): return self._server

    @property
    def session_data_name(self):
        return self._session_data_name

    def __init__(self, server: FastApiServer):
        self._templates = Jinja2Templates(directory="templates")
        self._error_page = "error.jinja2"
        self._authorized_page = "authorized.jinja2"
        self._authorized_url : str|None = "http://authorized"
        self._server = server
        self._session_data_name = "oauth"



##############################################################
## Default functions

async def json_error(client: FastApiOAuthClient, 
                     request : Request, 
                     response : Response,
                     ce : CrossauthError) -> Response:
    response.status_code = ce.http_status
    return JSONResponse({
        "ok": False,
        "status": ce.http_status,
        "error_message": ce.messages,
        "error_messages": ce.message,
        "error_code": ce.code.value,
        "error_code_name": ce.code_name
    }, ce.http_status, headers=response.headers)

async def page_error(client: FastApiOAuthClient,
    request: Request,
    response: Response,
    ce: CrossauthError) -> Response : 
    CrossauthLogger.logger().debug(j({"err": ce}))
    templates = client.templates

    return templates.TemplateResponse(
        request=request,
        name=client.error_page,
        context = {
            "status": ce.http_status,
            "error_message": ce.message,
            "error_messages": ce.messages,
            "error_code": ce.code.value,
            "error_code_name": ce.code_name
        },
    headers=response.headers,
    status_code=ce.http_status)

def decode_payload(token: str|None) -> Optional[Dict[str, Any]]:
    payload = None
    if token:
        try:
            payload = json.loads(Crypto.base64_decode(token.split(".")[1]))
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": ce}))
            CrossauthLogger.logger().error(j({"msg": "Couldn't decode id token"}))
    return payload

async def send_json(oauth_response: OAuthTokenResponse,
                    client: FastApiOAuthClient,
                    request: Request,
                    response: Response|None = None) -> Response|None:
    if response is not None:
        resp : Dict[str,Any] = {
            "ok": True,
            **oauth_response,
        }
        if "id_token" in  oauth_response:
            resp["id_payload"] = decode_payload(oauth_response["id_token"])
        return JSONResponse(resp, 200, headers=response.headers)

def log_tokens(oauth_response: OAuthTokenResponse):
    instance = JWT()
    if "access_token" in oauth_response:
        try:
            jwt = instance.decode(oauth_response["access_token"], None, do_verify=False, do_time_check=False)
            jti : str|None = jwt.get("jti")
            hash_value = Crypto.hash(jti) if jti else None
            CrossauthLogger.logger().debug(j({"msg": "Got access token", "accessTokenHash": hash_value}))
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": e}))

    if "id_token" in oauth_response:
        try:
            jwt = instance.decode(oauth_response["id_token"], None, do_verify=False, do_time_check=False)
            jti : str|None = jwt.get("jti")
            hash_value = Crypto.hash(jti) if jti else None
            CrossauthLogger.logger().debug(j({"msg": "Got id token", "idTokenHash": hash_value}))
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": e}))

    if "refresh_token" in oauth_response:
        try:
            jwt = instance.decode(oauth_response["refresh_token"], None, do_verify=False, do_time_check=False)
            jti : str|None = jwt.get("jti")
            hash_value = Crypto.hash(jti) if jti else None
            CrossauthLogger.logger().debug(j({"msg": "Got refresh token", "refreshTokenHash": hash_value}))
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": e}))

async def send_in_page(oauth_response: OAuthTokenResponse,
                       client: FastApiOAuthClient,
                       request: Request,
                       response: Response|None = None) -> Response|None:
    if "error" in oauth_response:
        ce = CrossauthError.from_oauth_error(oauth_response["error"], 
                                             oauth_response["error_description"] if "error_description" in oauth_response else oauth_response["error"])
        if response:
            templates = client.templates

            return templates.TemplateResponse(
                request=request,
                name=client.error_page,
                context = {
                    "status": ce.http_status,
                    "error_message": ce.message,
                    "error_messages": ce.messages,
                    "error_code_name": ce.code_name
                } , status_code=ce.http_status,
            headers=response.headers)

    log_tokens(oauth_response)

    if response:
        templates = client.templates
        try:
            context : Dict[str,Any] = {**oauth_response}
            if ("id_token" in oauth_response):
                context["id_payload"] = oauth_response["id_token"]
            return templates.TemplateResponse(
                request=request,
                name=client.authorized_page,
                context = context,
                status_code=200, headers=response.headers)

        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            return templates.TemplateResponse(
                request=request,
                name=client.error_page,
                context = {
                    "status": ce.http_status,
                    "error_message": ce.message,
                    "error_messages": ce.messages,
                    "error_code_name": ce.code_name
                }, status_code=ce.http_status, headers=response.headers)

async def update_session_data(oauth_response: OAuthTokenResponse,
                               client: FastApiOAuthClient,
                               request: Request,
                               response: Response|None = None):
    if not client.server.session_adapter:
        raise CrossauthError(ErrorCode.Configuration, "Cannot update session data if sessions not enabled")
    
    expires_in : int|None = oauth_response["expires_in"] if "expires_in" in oauth_response else None
    if expires_in is None and "access_token" in oauth_response:
        instance = JWT()
        payload = instance.decode(oauth_response["access_token"], None, do_verify=False, do_time_check=False)
        if 'exp' in payload:
            expires_in = payload['exp']
    
    if not expires_in:
        raise CrossauthError(ErrorCode.BadRequest, "OAuth server did not return an expiry for the access token")
    
    expires_at = int(datetime.now().timestamp()*1000) + (expires_in * 1000)
    
    if client.server.session_server:
        session_cookie_value = client.server.session_server.get_session_cookie_value(request)
        if not session_cookie_value and response is not None:
            session_cookie_value = await client.server.session_server.create_anonymous_session(request, response, {
                client.session_data_name: {**oauth_response, "expires_at": expires_at}
            })
        else:
            await client.server.session_adapter.update_session_data(request, client.session_data_name, {**oauth_response, "expires_at": expires_at})
    else:
        if not client.server.session_adapter:
            raise CrossauthError(ErrorCode.Configuration, "Cannot get session data if sessions not enabled")
        await client.server.session_adapter.update_session_data(request, client.session_data_name, {**oauth_response, "expires_at": expires_at})

async def save_in_session_and_load(oauth_response: OAuthTokenResponse,
                       client: FastApiOAuthClient,
                       request: Request,
                       response: Response|None = None) -> Response|None:
    if "error" in oauth_response:
        ce = CrossauthError.from_oauth_error(oauth_response["error"], 
                                             oauth_response["error_description"] if "error_description" in oauth_response else oauth_response["error"])
        if response:
            templates = client.templates

            return templates.TemplateResponse(
                request=request,
                name=client.error_page,
                context = {
                    "status": ce.http_status,
                    "error_message": ce.message,
                    "error_messages": ce.messages,
                    "error_code_name": ce.code_name
                }, status_code=ce.http_status, headers=response.headers)

    log_tokens(oauth_response)
    templates = client.templates
    try:
        if "access_token" in oauth_response or "id_token" in oauth_response or "refresh_token" in oauth_response:
            await update_session_data(oauth_response, client, request, response)

        if response:

            context : Dict[str,Any] = {**oauth_response}
            if ("id_token" in oauth_response):
                context["id_payload"] = oauth_response["id_token"]

            return templates.TemplateResponse(
                    request=request,
                    name=client.authorized_page,
                    context = context,
                    status_code=200, headers=response.headers)
    except Exception as e:
        ce = CrossauthError.as_crossauth_error(e)
        CrossauthLogger.logger().debug(j({"err": ce}))
        CrossauthLogger.logger().debug(j({"cerr": ce, "msg": "Error receiving tokens"}))
        if response:
            return templates.TemplateResponse(
                request=request,
                name=client.error_page,
                context = {
                    "status": ce.http_status,
                    "error_message": ce.message,
                    "error_messages": ce.messages,
                    "error_code_name": ce.code_name
                }, status_code=ce.http_status, headers=response.headers)

async def save_in_session_and_redirect(oauth_response: OAuthTokenResponse,
                                       client: FastApiOAuthClient,
                                       request: Request,
                                       response: Response|None = None) -> Response|None:
    if "error" in oauth_response:
        ce = CrossauthError.from_oauth_error(oauth_response["error"], 
                                             oauth_response["error_description"] if "error_description" in oauth_response else oauth_response["error"])
        if response is not None:
            templates = client.templates

            return templates.TemplateResponse(
                    request=request,
                    name=client.error_page,
                    context = {
                        "status": ce.http_status,
                        "error_message": ce.message,
                        "error_messages": ce.messages,
                        "error_code_name": ce.code_name
                    }, status_code=ce.http_status, headers=response.headers)

    log_tokens(oauth_response)

    templates = client.templates
    try:
        if "access_token" in oauth_response or "id_token" in oauth_response or "refresh_token" in oauth_response:
            await update_session_data(oauth_response, client, request, response)

        if response:
            if client.authorized_url is None:

                ce = CrossauthError(ErrorCode.Configuration, "Authorized url not configured")
                return templates.TemplateResponse(
                        request=request,
                        name=client.error_page,
                        context = {
                            "status": ce.http_status,
                            "error_message": ce.message,
                            "error_messages": ce.messages,
                            "error_code_name": ce.code_name
                        }, status_code=ce.http_status, headers=response.headers)

            context : Dict[str,Any] = {**oauth_response}
            if ("id_token" in oauth_response):
                context["id_payload"] = oauth_response["id_token"]

            return RedirectResponse(client.authorized_url)
    except Exception as e:
        ce = CrossauthError.as_crossauth_error(e)
        CrossauthLogger.logger().debug(j({"err": ce}))
        CrossauthLogger.logger().debug(j({"cerr": ce, "msg": "Error receiving tokens"}))
        if response:
            return templates.TemplateResponse(
                    request=request,
                    name=client.error_page,
                    context = {
                        "status": ce.http_status,
                        "error_message": ce.message,
                        "error_messages": ce.messages,
                        "error_code_name": ce.code_name
                    }, status_code=ce.http_status, headers=response.headers)
