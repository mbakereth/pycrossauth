# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import Callable, Self, Literal, List, NamedTuple, Dict, Any, Optional, Awaitable, cast
from fastapi import Request, Response
from crossauth_backend.common.interfaces import User
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.oauth.client import OAuthTokenResponse, OAuthDeviceResponse, OAuthClientOptions, OAuthClient, OAuthFlows, OAuthMfaAuthenticatorsOrTokenResponse
from crossauth_backend.crypto import Crypto
from crossauth_backend.storage import UserStorage
from crossauth_fastapi.fastapiserverbase import FastApiServerBase, FastApiErrorFn
from crossauth_fastapi.fastapisession import FastApiSessionServer
from crossauth_fastapi.fastapisession import JsonOrFormData
from fastapi.templating import Jinja2Templates
from fastapi.responses import RedirectResponse, JSONResponse
import json
import qrcode
from datetime import datetime, timedelta
from jwt import JWT
import aiohttp
import io
import base64

class OAuthTokenResponseWithExpiry(OAuthTokenResponse, total=False):
    expires_at: int

###################################################################
# Helpers

def string_is_true(val : str) -> bool:
    val = val.lower() 
    if (val == "1" or val == "yes" or \
        val == "true" or val == "t" or \
        val == "y" or val == "on"):
        return True
    return False

###################################################################
## OPTIONS

class BffEndpoint(NamedTuple):
    url: str
    methods: List[Literal["GET", "POST", "PUT", "DELETE", "PATCH"]]
    match_sub_urls: bool

class FastApiOAuthClientOptions(OAuthClientOptions, total=False):
    """
    Options for :class:`FastApiOAuthClient`.
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

    error_page : str
    """
    The template file for rendering error messages
    when `FastApiOAuthClientOptions.error_response_type`
    is `error_page`.
    """

    password_flow_page : str
    """
    The template file for asking the user for username and password
    in the password flow,
    
    Default `passwordflow.junja2`
    """

    device_code_flow_page : str
    """
    The template file to tell users the url to go to to complete the 
    device code flow.
    
    Default `devicecodeflow.jinja2`
    """

    delete_tokens_page : str
    """
    The template file to show the result in the `deletetokens` endpoint.
    
    Default `deletetokens.jinja2`
    """

    delete_tokens_get_url : str
    """
    Tthe `deletetokens` GET endpoint.
    
    Default undefined - don't create the endpoint
    """

    delete_tokens_post_url : str
    """
    Whether to add the `deletetokens` POST endpoint.
    
    Default undefined - don't create the endpoint
    """

    api_delete_tokens_post_url : str
    """
    Whether to add the `api/deletetokens` POST endpoint.
    
    Default undefined - don't create the endpoint
    """

    mfa_otp_page : str
    """
    The template file for asking the user for an OTP in the password MFA
    flow.
    """

    mfa_oob_page : str
    """
    The template file for asking the user for an OOB in the password MFA
    flow.
    """

    authorized_page : str
    """
    The template file for telling the user that authorization was successful.
    """

    authorized_url : str
    """
    If the :meth:`FastApiOAuthClientOptions.token_response_type` is
    `save_in_session_and_redirect`, this is the relative URL that the usder
    will be redirected to after authorization is complete.
    """

    password_flow_url : str
    """
    The URL to create the password flow under.  Default `passwordflow`.
    """

    device_code_flow_url : str
    """
    The URL to to create the device code flow under.  Default `devicecodeflow`.
    """

    device_code_poll_url : str
    """
    The URL to to for polling until the device code flow completes.  
    Default `devicecodepoll`.
    """

    password_otp_url : str
    """
    The URL to create the otp endpoint for the password mfa flow under.  
    This endpoint asks the user for his or her OTP.
    Default `passwordflowotp`.
    """

    password_oob_url : str
    """
    The URL to create the otp endpoint for the password mfa flow under.  
    This endpoint asks the user for his or her OOB.
    Default `passwordflowoob`.
    """

    receive_token_fn: Callable[[OAuthTokenResponse,
        Self,
        Request,
        Response|None], Response|None] 
    """
    This function is called after successful authorization to pass the
    new tokens to.
    - oauthResponse the response from the OAuth `token` endpoint.
    - client the fastify OAuth client
    - request the FastApi request
    - response the FastApi response
    - returns the FastApi response
    """

    error_fn : FastApiErrorFn
    """
    The function to call when there is an OAuth error and
    :attr:`FastApiOAuthClientOptions.error_response_type`
    is `custom`.
    See :class:`FastApiErrorFn`.
    """

    token_response_type : Literal[
        "send_json",
        "save_in_session_and_load",
        "save_in_session_and_redirect",
        "send_in_page",
        "custom"]
    """
    What to do when receiving tokens.
    See :class:`FastApiOAuthClient` class documentation for full description.
    """

    error_response_type : Literal[
        "json_error", 
        "page_error", 
        "custom"]
    """
    What do do on receiving an OAuth error.
    See lass documentation for full description.
    """

    bff_endpoints: List[BffEndpoint]
    """ 
    Array of resource server endppints to serve through the
    BFF (backend-for-frontend) mechanism.
    See :class:`FastApiOAuthClient` class documentation for full description.
    """

    bff_endpoint_name : str
    """
    Prefix for BFF endpoints.  Default "bff".
    See:class:`FastApiOAuthClient` class documentation for full description.
    """

    bff_base_url : str
    """
    Base URL for resource server endpoints called through the BFF
    mechanism.
    See :class:`FastApiOAuthClient` class documentation for full description.
    """

    token_endpoints : List[Literal["access_token", "refresh_token", "id_token",
        "have_access_token", "have_refresh_token", "have_id_token"]]
    """
    Endpoints to provide to acces tokens through the BFF mechanism,
    See :class:`FastApiOAuthClient` class documentation for full description.
    """

    """
    Set of flows to enable (see :class:`crossauth_backend.OAuthFlows`).
    
    Defaults to empty.
    """

    valid_flows : List[str]
    """
    List of flows to create endpoints for.  See :class:´crossauth_backend.OAuthFlows`.
    Default none
    """

    jwt_tokens : List[Literal["access","id","refresh"]]
    """
    These token types will be treated as JWT.  Default all of them
    """

    user_creation_type : Literal["idToken", "merge", "embed", "custom"]
    """
    If using the BFF method, you can also create a user in the sesion
    when the token is received, just like session management 
    (`event.locals.user` for Sveltekit, `request.user`) for Fastify.
    
    Set this field to `merge` to do this by merging the ID token fields
    with the User fields.  `embed` will put the ID token fields in `idToken`
    in the user.  `custom` will call the user-defined function `userCreationFn`.
    th user will be set to undefined;  If it is set to `idToken` (the default)
    then a user object is created from the token without first checking
    for a user in storage.
    
    Matching is done in the fields given in `user_match_field` and
    `id_token_match_field`.

    Currently only `idToken` and `custom` are supported as user storage
    has not yet been implemented.
    """

    user_match_field : str
    """
    Field in user table to to match with idToken when `userCreationType`
    is set to `merge` or `embed`.  Default `username`.
    """

    id_token_match_field : str
    """
    Field in ID token to to match with idToken when `userCreationType`
    is set to `merge` or `embed`.  Default `sub`.
    """

    user_creation_fn: Callable[[Dict[str,Any],
        UserStorage|None,
        str,
        str], Awaitable[User|None]] 
    """
    Supply this function if you set `userCreationType` to `custom`.
    - id_token the response from the OAuth `token` endpoint.
    - user_storage the fastify OAuth client
    - user_match_field the FastApi response
    - id_token_match_field the FastApi request
    Returns the user if it exists and is active, None otherwise.
    """

async def idTokenUserCreateFn(id_token: Dict[str,Any], 
                        user_storage : UserStorage|None,
                        user_match_field : str, 
                        id_token_match_field : str):
    user : User = {
        "id" : cast(str, id_token["userid"] if "userid" in id_token else id_token["sub"]),
        "username" : cast(str, id_token["sub"]),
        "state" : cast(str, id_token["state"] if "state" in id_token else "active"),
        "factor1": "oidc",
    }
    return user

async def mergeUserCreateFn(id_token: Dict[str,Any], 
                        user_storage : UserStorage|None,
                        user_match_field : str, 
                        id_token_match_field : str):
    if (user_storage is None): raise CrossauthError(ErrorCode.Configuration, "user_creation_type set to merge but no user storage set")
    try:
        if (user_match_field == "username"): ret = await user_storage.get_user_by_username(id_token[id_token_match_field])
        elif (user_match_field == "username"): ret = await user_storage.get_user_by_email(id_token[id_token_match_field])
        #else: ret = await user_storage.get_user_by(user_match_field, id_token[id_token_match_field])
        else: ret = await user_storage.get_user_by_email(id_token[id_token_match_field])
        user : User = ret["user"]
        return cast(User, {**id_token, **user})
    except Exception as e:
        ce = CrossauthError.as_crossauth_error(e)
        if ce.code == ErrorCode.UserNotExist or ce.code == ErrorCode.UserNotActive:
            return None
        raise ce

async def embedUserCreateFn(id_token: Dict[str,Any], 
                        user_storage : UserStorage|None,
                        user_match_field : str, 
                        id_token_match_field : str):
    if (user_storage is None): raise CrossauthError(ErrorCode.Configuration, "user_creation_type set to embed but no user storage set")
    try:
        if (user_match_field == "username"): ret = await user_storage.get_user_by_username(id_token[id_token_match_field])
        elif (user_match_field == "username"): ret = await user_storage.get_user_by_email(id_token[id_token_match_field])
        #else: ret = await user_storage.get_user_by(user_match_field, id_token[id_token_match_field])
        else: ret = await user_storage.get_user_by_email(id_token[id_token_match_field])
        user : User = ret["user"]
        return cast(User, {**user, "id_token": id_token})
    except Exception as e:
        ce = CrossauthError.as_crossauth_error(e)
        if ce.code == ErrorCode.UserNotExist or ce.code == ErrorCode.UserNotActive:
            return None
        raise ce

##############################################################
## Class

class FastApiOAuthClient(OAuthClient):
    """
    The FastAPI implementation of the OAuth client.
    
    Makes requests to an authorization server, using a configurable set
    of flows, which sends back errors or tokens,
    
    You cannot construct this class directly.  It must be created through
    a :class:`FastApiServer` instance.
    
    **:attr:`FastApiOAuthClientOptions.token_response_type`**
    
      - `send_json` the token response is sent as-is in the reply to the FastApi 
         request.  In addition to the `token` endpoint response fields,
         `ok: true` and `id_payload` with the decoded 
         payload of the ID token are retruned.
      - `save_in_session_and_load` the response fields are saved in the `data`
         field of the session ID in key storage.  In addition, `expires_at` is 
         set to the number of seconds since Epoch that the access token expires
         at.  After saving, page defined in `authorized_page` is displayed.
         A consequence is the query parameters passed to the 
         redirect Uri are displayed in the address bar, as the response
         is to the redirect to the redirect Uri.
       - save_in_session_and_redirect` same as `save_in_session_and_load` except that 
         a redirect is done to the `authorized_url` rather than displaying
         `authorized_page` template.
       - `send_in_page` the `token` endpoint response is not saved in the session
         but just sent as template arguments when rendering the
         template in `authorized_page`.  The JSON response fields are sent
         verbatim, with the additional fild of `id_payload` which is the
         decoded payload from the ID token, if present.
       - `custom` the function in 
          :attr:`FastApiOAuthClientOptions.receiveTokenFn` is called.
         
    **:attr:`FastApiOAuthClientOptions.errorResponseType`**
    
       - `json_error` a JSON response is sent with fields
          `status`, `error_message`,
         `error_messages` and `error_code_name`.
       - `page_error` the template in :attr:FastApiOAuthClientOptions.error_page`
         is displayed with template parameters `status`, `error_message`,
         `error_messages` and `error_code_name`.
       - `custom` :class:`FastApiOAuthClientOptions.error_fn` is called.
    
    **Backend-for-Frontend (BFF)**
    
    This class supports the backend-for-frontend (BFF) model.  You create an
    endpoint for every resource server endpoint you want to be able to call, by
    setting them in :class:`FastApiOAuthClientOptions.bffEbdpoints`.  You set the
    :attr:`FastApiOAuthClientOptions.token_response_type` to `save_in_session_and_load`
    or `save_in_session_and_redirect` so that tokens are saved in the session.  
    You also set `bffBaseUrl` to the base URL of the resource server.
    When you want to call a resource server endpoint, you call
    `site_url` + `prefix` + `bff_endpoint_name` + *`url`*. The client will
    pull the access token from the session, put it in the `Authorization` header
    and called `bff_base_url` + *`url`* using fetch, and return the
    response verbatim.  
    
    This pattern avoids you having to store the access token in the frontend.
    
    **Middleware**

    This class provides middleware that works with the BFF method.

    If an ID token is saved in the session and it is valid, the following
    state attributes are set in the request object:

      - `id_payload` the payload from the ID token
      - `user` a :class:`crossauth_backend.User` object created from the ID
         token
      - `auth_type` set to `oidc`

    **Endpoints provided by this class**
    
    In addition to the BFF endpoints above, this class provides the following 
    endpoints. The ENDPOINT column values can be overridden in 
    :class:`FastApiOAuthClientOptions`. 
    All POST endpoints also require `csrf_token`.
    The Flow endpoints are only enabled if the corresponding flow is set
    in :attr:`FastApiOAuthClientOptions.valid_flows`. 
    Token endpoints are only enabled if the corresponding endpoint is set
    in :attr:`FastApiOAuthClientOptions.token_endpoints`. 
    
    | METHOD | ENDPOINT            |Description                                                   | GET/BODY PARAMS                                     | VARIABLES PASSED/RESPONSE                                 | FILE                     |
    | ------ | --------------------| ------------------------------------------------------------ | --------------------------------------------------- | --------------------------------------------------------- | ------------------------ |
    | GET    | `authzcode`         | Redirect URI for receiving authz code                        | *See OAuth authorization code flow spec*            | *See docs for`tokenResponseType`*                         |                          | 
    | GET    | `passwordflow`      | Displays page to request username/password for password flow | scope                                               | user, scope                                               | passwordFlowPage         | 
    | POST   | `passwordflow`      | Initiates the password flow                                  | *See OAuth password flow spec*                      | *See docs for`tokenResponseType`*                         |                          | 
    |        |                     | Requests an OTP from the user for the Password MFA OTP flow  | `mfa_token`, `scope`, `otp`                         | `mfa_token`, `scope`, `error`, `errorMessage`             | mfaOtpPage               | 
    |        |                     | Requests an OOB from the user for the Password MFA OOB flow  | `mfa_token`, `oob_code`, `scope`, `oob`             | `mfa_token`, `oob_code`, `scope`, `error`, `errorMessage` | mfaOobPage               | 
    | POST   | `passwordotp`       | Token request with the MFA OTP                               | *See Password MFA flow spec*                        | *See docs for`tokenResponseType`*                         |                          | 
    | POST   | `passwordoob`       | Token request with the MFA OOB                               | *See Password MFA flow spec*                        | *See docs for`tokenResponseType`*                         |                          | 
    | POST   | `authzcodeflow`     | Initiates the authorization code flow                        | *See OAuth authorization code flow spec*            | *See docs for`tokenResponseType`*                         |                          | 
    | POST   | `authzcodeflowpkce` | Initiates the authorization code flow with PKCE              | *See OAuth authorization code flow with PKCE spec*  | *See docs for`tokenResponseType`*                         |                          | 
    | POST   | `clientcredflow`    | Initiates the client credentials flow                        | *See OAuth client credentials flow spec*            | *See docs for`tokenResponseType`*                         |                          | 
    | POST   | `refreshtokenflow`  | Initiates the refresh token flow                             | *See OAuth refresh token flow spec*                 | *See docs for`tokenResponseType`*                         |                          | 
    | POST   | `devicecodeflow`    | Initiates the device code flow                               | See :class:`DeviceCodeBodyType`                      | See :class:`DeviceCodeFlowResponse`                        | `deviceCodeFlowPage`     | 
    | POST   | `api/devicecodeflow` | Initiates the device code flow                              | See :class:`DeviceCodeBodyType`                      | See :class:`DeviceCodeFlowResponse`                        |                          | 
    | POST   | `devicecodepoll`     | Initiates the device code flow                              | See :class:`DeviceCodePollBodyType`                  | Authorization complete: See docs for`tokenResponseType`.  Other cases, :class:`OAuthTokenResponse` |                          | 
    | POST   | `api/devicecodepoll` | Initiates the device code flow                              | See :class:`DeviceCodePollBodyType`                  | :class:`OAuthTokenResponse`              |                          | 
    | POST   | `access_token`      | For BFF mode, returns the saved access token                 | `decode`, default `true`                            | *Access token payload*                                    |                          | 
    | POST   | `refresh_token`     | For BFF mode, returns the saved refresh token                | `decode`, default `true`                            | `token` containing the refresh token                      |                          | 
    | POST   | `id_token     `     | For BFF mode, returns the saved ID token                     | `decode`, default `true`                            | *ID token payload*                                        |                          | 
    | POST   | `have_access_token` | For BFF mode, returns whether an acccess token is saved      |                                                     | `ok`                                                      |                          | 
    | POST   | `have_refresh_token`| For BFF mode, returns whether a refresh token is saved       |                                                     | `ok`                                                      |                          | 
    | POST   | `have_id_token`     | For BFF mode, returns whether an ID token is saved           |                                                     | `ok`                                                      |                          | 
    | POST   | `tokens`            | For BFF mode, returns all the saved tokens                   | `decode`, default `true`                            | *Token payloads                                         |                          | 
    | POST   | `deletetokens`      | Deletes all BFF tokens and displays a page                   | None                                                | `ok`                                                      | `deleteTokensPage`       | 
    | POST   | `api/deletetokens`  | Delertes all tokens and returns JSON                         | None                                                | `ok`                                                      |                          | 
    """

    @property
    def server(self):  return self._server
    
    @property
    def error_page(self): return self._error_page

    @property
    def password_flow_page(self): return self._password_flow_page

    @property
    def device_code_flow_page(self): return self._device_code_flow_page

    @property
    def delete_tokens_page(self): return self._delete_tokens_page

    @property
    def delete_tokens_get_url(self): return self._delete_tokens_get_url

    @property
    def delete_tokens_post_url(self): return self._delete_tokens_post_url

    @property
    def api_delete_tokens_post_url(self): return self._api_delete_tokens_post_url

    @property
    def mfa_otp_page(self): return self._mfa_otp_page

    @property
    def mfa_oob_page(self): return self._mfa_oob_page

    @property
    def authorized_page(self): return self._authorized_page

    @property
    def authorized_url(self): return self._authorized_url
    
    @property
    def session_data_name(self): return self._session_data_name

    @property
    def templates(self): return self._templates

    @property
    def user_creation_type(self): return self._user_creation_type

    @property
    def user_match_field(self): return self._user_match_field

    @property
    def id_token_match_field(self): return self._id_token_match_field

    @property
    def jwt_tokens(self): return self._jwt_tokens

    def __init__(self, server: FastApiServerBase, auth_server_base_url: str, options: FastApiOAuthClientOptions = {}, have_session_server: bool = False):

        """
        Constructor

        Do not try to construct this independently.  Construct a 
        :class:`FastApiServer` instance instead.

        :param FastApiServerBase server: This class does not work without a 
               parent server being instantiated.  It is passed here,
        :param str auth_server_base_url: The base URL for for calling the
               authorization server.  Eg `.well-known` will be appended to
               this URL.
        :param FastApiOAuthClientOptions options: See :class:`FastApiOAuthClientOptions`

        """
        super().__init__(auth_server_base_url, options)
        self._server = server
        self.__site_url = "/"
        self.__prefix : str = "/"
        self._error_page = "error.jinja2"
        self._password_flow_page = "passwordflow.jinja2"
        self._device_code_flow_page = "devicecodeflow.jinja2"
        self._delete_tokens_page = "deletetokens.jinja2"
        self._delete_tokens_get_url: Optional[str] = None
        self._delete_tokens_post_url: Optional[str] = None
        self._api_delete_tokens_post_url: Optional[str] = None
        self._mfa_otp_page = "mfaotp.jinja2"
        self._mfa_oob_page = "mfaoob.jinja2"
        self._authorized_page = "authorized.jinja2"
        self._authorized_url = "authorized"
        self._session_data_name = "oauth"
        self.__receive_token_fn: Callable[[OAuthTokenResponse|OAuthDeviceResponse,
            Self,
            Request,
            Response|None], Awaitable[Response|None]] = send_json
        self.__error_fn: FastApiErrorFn = json_error
        self.__valid_flows: List[str] = []
        self._token_response_type: str = "send_json"
        self._error_response_type: str = "json_error"
        self._password_flow_url = "passwordflow"
        self._password_otp_url = "passwordotp"
        self._password_oob_url = "passwordoob"
        self._device_code_flow_url = "devicecodeflow"
        self._device_code_poll_url = "devicecodepoll"
        self._bff_endpoints: List[BffEndpoint] = []
        self._bff_endpoint_name = "bff"
        self._bff_base_url: Optional[str] = None
        self.__token_endpoints: List[Literal["access_token", "refresh_token", "id_token",
        "have_access_token", "have_refresh_token", "have_id_token"]] = []
        self.__template_dir = "templates"
        self._jwt_tokens : List[Literal["access","id","refresh"]] = ["access", "id", "refresh"]

        self._test_middleware = False
        self._test_request : Request|None = None

        self._user_creation_type : Literal["idToken", "merge", "emded", "custom" ] = "idToken"
        self._user_match_field : str = "username"
        self._id_token_match_field : str = "sub"

        set_parameter("session_data_name", ParamType.String, self, options, "OAUTH_SESSION_DATA_NAME", protected=True)
        set_parameter("site_url", ParamType.String, self, options, "SITE_URL", True)
        set_parameter("token_response_type", ParamType.String, self, options, "OAUTH_TOKEN_RESPONSE_TYPE", protected=True)
        set_parameter("error_response_type", ParamType.String, self, options, "OAUTH_ERROR_RESPONSE_TYPE", protected=True)
        set_parameter("prefix", ParamType.String, self, options, "PREFIX")
        if not self.__prefix.endswith("/"): self.__prefix += "/"
        set_parameter("error_page", ParamType.String, self, options, "ERROR_PAGE", protected=True)
        set_parameter("authorized_page", ParamType.String, self, options, "AUTHORIZED_PAGE", protected=True)
        set_parameter("authorized_url", ParamType.String, self, options, "AUTHORIZED_URL", protected=True)
        set_parameter("password_flow_url", ParamType.String, self, options, "OAUTH_PASSWORD_FLOW_URL", protected=True)
        set_parameter("password_otp_url", ParamType.String, self, options, "OAUTH_PASSWORD_OTP_URL", protected=True)
        set_parameter("password_oob_url", ParamType.String, self, options, "OAUTH_PASSWORD_OOB_URL", protected=True)
        set_parameter("password_flow_page", ParamType.String, self, options, "OAUTH_PASSWORD_FLOW_PAGE", protected=True)
        set_parameter("device_code_flow_page", ParamType.String, self, options, "OAUTH_DEVICECODE_FLOW_PAGE", protected=True)
        set_parameter("delete_tokens_page", ParamType.String, self, options, "OAUTH_DELETE_TOKENS_PAGE", protected=True)
        set_parameter("delete_tokens_get_url", ParamType.String, self, options, "OAUTH_DELETE_TOKENS_GET_URL", protected=True)
        set_parameter("delete_tokens_post_url", ParamType.String, self, options, "OAUTH_DELETE_TOKENS_POST_URL", protected=True)
        set_parameter("api_delete_tokens_post_url", ParamType.String, self, options, "OAUTH_API_DELETE_TOKENS_POST_URL", protected=True)
        set_parameter("mfa_otp_page", ParamType.String, self, options, "OAUTH_MFA_OTP_PAGE", protected=True)
        set_parameter("mfa_oob_page", ParamType.String, self, options, "OAUTH_MFA_OOB_PAGE", protected=True)
        set_parameter("device_code_flow_url", ParamType.String, self, options, "OAUTH_DEVICECODE_FLOW_URL", protected=True)
        set_parameter("device_code_poll_url", ParamType.String, self, options, "OAUTH_DEVICECODE_POLL_URL", protected=True)
        set_parameter("bff_endpoint_name", ParamType.String, self, options, "OAUTH_BFF_ENDPOINT_NAME", protected=True)
        set_parameter("bff_base_url", ParamType.String, self, options, "OAUTH_BFF_BASEURL", protected=True)
        set_parameter("valid_flows", ParamType.JsonArray, self, options, "OAUTH_VALIFGLOWS")
        set_parameter("template_dir", ParamType.String, self, options, "TEMPLATE_DIR")
        set_parameter("jwt_tokens", ParamType.JsonArray, self, options, "OAUTH_JWT_TOKENS", protected=True)
        set_parameter("user_creation_type", ParamType.String, self, options, "OAUTH_USER_CREATION_TYPE", protected=True)
        set_parameter("user_match_field", ParamType.String, self, options, "OAUTH_USER_MATCH_FIELD", protected=True)
        set_parameter("id_token_match_field", ParamType.String, self, options, "OAUTH_IDTOKEN_CREATION_TYPE", protected=True)
    
        self.user_creation_fn : Callable[[Dict[str,Any],
            UserStorage|None,
            str,
            str], Awaitable[User|None]] = idTokenUserCreateFn
        if (self._user_creation_type == "merge"): # type: ignore
            self.user_creation_fn = mergeUserCreateFn
        elif (self._user_creation_type == "embed"): # type: ignore
            self.user_creation_fn = embedUserCreateFn
        elif (self._user_creation_type == "custom" and "user_creation_fn" in options): # type: ignore
            self.user_creation_fn = options["user_creation_fn"]
        else:
            self.user_creation_fn = idTokenUserCreateFn

        if (len(self.__valid_flows) == 1 and self.__valid_flows[0] == OAuthFlows.All):
            flows = OAuthFlows.all_flows()
            self.__valid_flows = [*flows]

        self._templates = Jinja2Templates(directory=self.__template_dir)

        if self._delete_tokens_get_url and self._delete_tokens_get_url.startswith("/"):
            self._delete_tokens_get_url = self._delete_tokens_get_url[1:]
        if self._delete_tokens_post_url and self._delete_tokens_post_url.startswith("/"):
            self._delete_tokens_post_url = self._delete_tokens_post_url[1:]
        if self._delete_tokens_post_url and self._delete_tokens_post_url.startswith("/"):
            self._delete_tokens_post_url = self._delete_tokens_post_url[1:]

        if len(self.__valid_flows) == 1 and self.__valid_flows[0] == "All":
            self.__valid_flows = OAuthFlows.all_flows()
        else:
            if not OAuthFlows.are_valid_flows(self.__valid_flows):
                raise CrossauthError(ErrorCode.Configuration, "Invalid flows specified in " + ",".join(self.__valid_flows))

        if "token_endpoints" in options:
            self.__token_endpoints = options["token_endpoints"]

        if self._bff_endpoint_name.endswith("/"):
            self._bff_endpoint_name = self._bff_endpoint_name[:-1]
        if "bff_endpoints" in options:
            self._bff_endpoints = options["bff_endpoints"]

        if self._token_response_type == "custom" and "receive_token_fn" not in options:  # type: ignore
            raise CrossauthError(ErrorCode.Configuration, "Token response type of custom selected but receive_token_fn not defined")
        if self._token_response_type == "custom" and "receive_token_fn" in options:  # type: ignore
            self._receive_token_fn = options["receive_token_fn"]
        elif self._token_response_type == "send_json": 
            self.__receive_token_fn = send_json
        elif self._token_response_type == "send_in_page":
            self.__receive_token_fn = send_in_page
        elif self._token_response_type == "save_in_session_and_load":
            self.__receive_token_fn = save_in_session_and_load
        elif self._token_response_type == "save_in_session_and_redirect": # type: ignore
            self.__receive_token_fn = save_in_session_and_redirect

        if self._error_response_type == "custom" and not options.get("error_fn"): # type: ignore
            raise CrossauthError(ErrorCode.Configuration, "Error response type of custom selected but error_fn not defined")
        if self._error_response_type == "custom" and options.get("error_fn"): # type: ignore
            self.__error_fn = options["error_fn"] # type: ignore
        elif self._error_response_type == "json_error":
            self.__error_fn = json_error
        elif self._error_response_type == "page_error":
            self.__error_fn = page_error

        self._redirect_uri = self.__site_url + self.__prefix + "authzcode"

        #####
        # Hooks

        app = self.server.app
        @app.middleware("http")
        async def pre_handler(request: Request, call_next): # type: ignore
            CrossauthLogger.logger().debug(j({"msg": "Calling OAuth client hook"}))
            if (request.state.user or not self._server.have_session_adapter):
                return cast(Response, await call_next(request))

            session_data = await self._server.get_session_data(request, self.session_data_name) 
            if (session_data is not None and "id_payload" in session_data):
                expiry = session_data["expires_at"]
                if (expiry is not None and expiry > datetime.now().timestamp()*1000 and session_data["id_payload"]["sub"]):
                    request.state.user = {
                        "id" : session_data["id_payload"]["userid"] if "userid" in session_data["id_payload"] else session_data["id_payload"]["sub"],
                        "username" : session_data["id_payload"]["sub"],
                        "state" : session_data["id_payload"]["state"] if "state" in session_data["id_payload"] else "active",
                    }
                    request.state.id_token_payload = session_data["id_payload"]
                    request.state.auth_type = "oidc"

            if self._test_middleware:
                self._test_request = request 

            return cast(Response, await call_next(request))


        #####
        # Authorization code flow
        async def authzcodeflow_endpoint(request: Request, response: Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'authzcodeflow',
                "ip": request.client.host if request.client else None,
                "user": FastApiSessionServer.username(request)
            }))
            state = self.random_value(self._state_length)
            session_data = {"scope": request.query_params.get("scope"), "state": state}
            await self.store_session_data(session_data, request, response)
            ret = await self.start_authorization_code_flow(state, request.query_params.get("scope"))
            if "error" in ret or "url" not in ret:
                ce = CrossauthError.from_oauth_error(ret["error"] or "server_error", ret["error_description"])
                return await self.__error_fn(self.server, request, response, ce)
            CrossauthLogger.logger().debug({
                "msg": "Authorization code flow: redirecting",
                "url": ret["url"]
            })
            return RedirectResponse(ret["url"], status_code=302, headers=response.headers)

        if OAuthFlows.AuthorizationCode in self.__valid_flows:
            self._server.app.get(self.__prefix + 'authzcodeflow')(authzcodeflow_endpoint)

        #####
        # Authorization code flow with PKCE
        async def authzcodeflowpkce_endpoint(request: Request, response: Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'authzcodeflowpkce',
                "ip": request.client.host if request.client is not None else None,
                "user": FastApiSessionServer.username(request)
            }))
            state = self.random_value(self._state_length)
            challengeVerifier = await self.code_challenge_and_verifier()
            session_data = {"scope": request.query_params.get("scope"), 
                            "state": state,
                            "code_challenge": challengeVerifier["code_challenge"],
                            "code_verifier": challengeVerifier["code_verifier"]}
            await self.store_session_data(session_data, request, response)
            ret = await self.start_authorization_code_flow(state, request.query_params.get("scope"), challengeVerifier["code_challenge"], True)
            if "error" in ret or "url" not in ret:
                ce = CrossauthError.from_oauth_error(ret["error"] or "server_error", ret["error_description"])
                return await self.__error_fn(self.server, request, response, ce)
            return RedirectResponse(ret["url"], status_code=302, headers=response.headers)


        if OAuthFlows.AuthorizationCodeWithPKCE in self.__valid_flows:
            self._server.app.get(self.__prefix + 'authzcodeflowpkce')(authzcodeflowpkce_endpoint)

        #####
        # Redirect Uri
        async def authzcode_endpoint(request: Request, response: Response):
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": 'GET',
                "url": self.__prefix + 'authzcode',
                "ip": request.client.host if request.client else None,
                "user": FastApiSessionServer.username(request)
            }))

            oauth_data =  await self.server.get_session_data(request, self.session_data_name)
            if (oauth_data is None or "state" not in oauth_data or oauth_data["state"] != request.query_params.get("state")):
                raise CrossauthError(ErrorCode.Unauthorized, "State does not match")
            verifier : str|None = None
            if (oauth_data and "code_verifier" in oauth_data):
                verifier = oauth_data["code_verifier"]
            resp = await self.redirect_endpoint(request.query_params.get("code"), request.query_params.get("state"), verifier, request.query_params.get("error"), request.query_params.get("error_description"))
            try:
                if ("id_token" in resp):
                    # This token is intended for us, so validate it
                    if (await self.validate_id_token(resp["id_token"]) is None):
                        resp : OAuthTokenResponse = {"error": "access_denied", "error_description": "Invalid ID token received"}
                if "error" in resp:
                    ce = CrossauthError.from_oauth_error(resp["error"], 
                        resp["error_description"] if "error_description" in resp else resp["error"])
                    return await self.__error_fn(self.server, request, response, ce)
                return await self.__receive_token_fn(resp, self, request, response)
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "msg": "Error receiving token",
                    "cerr": str(ce),
                    "user": FastApiSessionServer.username(request)
                }))
                CrossauthLogger.logger().debug({"err": ce})
                return await self.__error_fn(self.server, request, response, ce)

        if OAuthFlows.AuthorizationCode in self.__valid_flows or OAuthFlows.AuthorizationCodeWithPKCE in self.__valid_flows or "OidcAuthorizationCode" in self.__valid_flows:
            self._server.app.get(self.__prefix + 'authzcode')(authzcode_endpoint)

        #####
        # Client credentials flow
        async def clientcredflow_endpoint(request: Request, response: Response):
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": 'POST',
                "url": self.__prefix + 'clientcredflow',
                "ip": request.client.host if request.client else None,
                "user": FastApiSessionServer.username(request)
            }))
            if self._server.have_session_adapter:
                resp1 = await self._server.error_if_csrf_invalid(request, response, self.__error_fn)
                if resp1.error:
                    return resp1.response
            try:
                body = JsonOrFormData()
                await body.load(request)
                resp = await self.client_credentials_flow(body.getAsStr("scope", None))
                if ("id_token" in resp):
                    # This token is intended for us, so validate it
                    if (await self.validate_id_token(resp["id_token"]) is None):
                        resp : OAuthTokenResponse = {"error": "access_denied", "error_description": "Invalid ID token received"}
                if "error" in resp:
                    ce = CrossauthError.from_oauth_error(resp["error"], 
                        resp["error_description"] if "error_description" in resp else resp["error"])
                    return await self.__error_fn(self.server, request, response, ce)
                return await self.__receive_token_fn(resp, self, request, response)
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "msg": "Error receiving token",
                    "cerr": ce,
                    "user": FastApiSessionServer.username(request)
                }))
                CrossauthLogger.logger().debug(j({"err": e}))
                return await self.__error_fn(self.server, request, response, ce)
        if OAuthFlows.ClientCredentials in self.__valid_flows:
            self._server.app.post(self.__prefix + 'clientcredflow')(clientcredflow_endpoint)
            
        #####
        # Refresh token flow
        async def refreshtokenflow_endpoint(request: Request, response: Response):
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": f"{self.__prefix}refreshtokenflow",
                "ip": request.client.host if request.client else None,
                "user": FastApiSessionServer.username(request)
            }))

            # if sessions are enabled, require a csrf token
            resp1 = await self._server.error_if_csrf_invalid(request, response, self.__error_fn)
            if resp1.error:
                return resp1.response

            # get refresh token from body if present, otherwise try to find in session
            body = JsonOrFormData()
            await body.load(request)
            refresh_token: Optional[str] = body.get("refresh_token")
            if not refresh_token and self.server.have_session_adapter:
                if not self.server.have_session_adapter:
                    raise CrossauthError(ErrorCode.Configuration, 
                        "Cannot get session data if sessions not enabled")
                oauth_data = await self._server.get_session_data(request, self.session_data_name)

                if not oauth_data or not oauth_data.get("refresh_token"):
                    ce = CrossauthError(ErrorCode.BadRequest,
                        "No refresh token in session or in parameters")
                    return await self.__error_fn(self.server, request, response, ce)
                refresh_token = oauth_data["refresh_token"]

            if not refresh_token:
                # TODO: refresh token cookie - call with no refresh token?
                ce = CrossauthError(ErrorCode.BadRequest, "No refresh token supplied")
                return await self.__error_fn(self.server, request, response, ce)

            try:
                resp = await self.refresh_token_flow(refresh_token)
                if ("id_token" in resp):
                    # This token is intended for us, so validate it
                    if (await self.validate_id_token(resp["id_token"]) is None):
                        resp : OAuthTokenResponse = {"error": "access_denied", "error_description": "Invalid ID token received"}
                if "error" in resp:
                    ce = CrossauthError.from_oauth_error(resp["error"], 
                        resp["error_description"] if "error_description" in resp else resp["error"])
                    return await self.__error_fn(self.server, request, response, ce)
                return await self.__receive_token_fn(resp, self, request, response)
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({
                    "msg": "Error receiving token",
                    "cerr": str(ce),
                    "user": request.state.user.user if request.state.user else None
                }))
                CrossauthLogger.logger().debug(json.dumps({"err": str(e)}))
                return await self.__error_fn(self.server, request, response, ce)
        if OAuthFlows.RefreshToken in self.__valid_flows:
            self._server.app.post(self.__prefix + 'refreshtokenflow')(refreshtokenflow_endpoint)

        async def refreshtokensifexpired_endpoint(request: Request, response: Response):
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": f"{self.__prefix}refreshtokensifexpired",
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            return await self._refresh_tokens(request, response, False, True)
        if OAuthFlows.RefreshToken in self.__valid_flows:
            self._server.app.post(self.__prefix + 'refreshtokensifexpired')(refreshtokensifexpired_endpoint)

        async def api_refreshtokensifexpired_endpoint(request: Request, response: Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": f"{self.__prefix}refreshtokens",
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            resp = await self._refresh_tokens(request, response, True, True)
            if (isinstance(resp, Response)):
                return resp
            elif (resp is None):
                return JSONResponse({}, headers=response.headers)
            return JSONResponse(resp, headers=response.headers)
        if "RefreshToken" in self.__valid_flows:
            self._server.app.post(self.__prefix + 'api/refreshtokensifexpired')(api_refreshtokensifexpired_endpoint)

        async def refreshtokens_endpoint(request: Request, response: Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": f"{self.__prefix}refreshtokens",
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            resp = await self._refresh_tokens(request, response, False, False)
            if (isinstance(resp, Response)):
                return resp
            elif (resp is None):
                return JSONResponse({}, headers=response.headers)
            return JSONResponse(resp, headers=response.headers)
        if OAuthFlows.RefreshToken in self.__valid_flows:
            self._server.app.post(self.__prefix + 'refreshtokens')(refreshtokens_endpoint)

        async def api_refreshtokens_endpoint(request: Request, response: Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": f"{self.__prefix}refreshtokens",
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            resp = await self._refresh_tokens(request, response, True, False)
            if (isinstance(resp, Response)):
                return resp
            elif (resp is None):
                return JSONResponse({}, headers=response.headers)
            return JSONResponse(resp, headers=response.headers)
        if OAuthFlows.RefreshToken in self.__valid_flows:
            self._server.app.post(self.__prefix + 'api/refreshtokens')(api_refreshtokens_endpoint)


        #####
        # Password (and MFA) flow

        async def get_passwordflow_endpoint(request: Request, response: Response) -> Any:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "GET",
                "url": self.__prefix + self._password_flow_url,
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))

            return self.templates.TemplateResponse(
                request=request,
                name=self.password_flow_page,
                context={
                    "request": request,
                    "user": request.state.user,
                    "scope": request.query_params.get("scope"),
                    "csrfToken": request.state.csrf_token
                }
            )
        if OAuthFlows.Password in self.__valid_flows or OAuthFlows.PasswordMfa in self.__valid_flows:
            self._server.app.get(self.__prefix + self._password_flow_url)(get_passwordflow_endpoint)

        async def post_passwordflow_endpoint(request: Request, response: Response) -> Any:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + self._password_flow_url,
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))

            resp = await self._password_post(False, request, response)
            if (isinstance(resp, Response)):
                return resp
            elif (resp is None):
                return JSONResponse({}, headers=response.headers)
            return JSONResponse(resp, headers=response.headers)
        
        if OAuthFlows.Password in self.__valid_flows or OAuthFlows.PasswordMfa in self.__valid_flows:
            self._server.app.post(self.__prefix + self._password_flow_url)(post_passwordflow_endpoint)

        async def passwordotp_endpoint(request: Request, response: Response) -> Any:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + self._password_otp_url,
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            return await self._password_otp(False, request, response)

        if OAuthFlows.PasswordMfa in self.__valid_flows:
            self._server.app.post(self.__prefix + self._password_otp_url)(passwordotp_endpoint)

        async def passwordoob_endpoint(request: Request, response: Response) -> Any:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + self._password_oob_url,
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            return await self._password_oob(False, request, response)

        if OAuthFlows.PasswordMfa in self.__valid_flows:
            self._server.app.post(self.__prefix + self._password_oob_url)(passwordoob_endpoint)

        #####
        # Device code flow

        async def devicecodeflow_endpoint(request: Request, response: Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + self._device_code_flow_url,
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            return await self._device_code_post(False, request, response)

        if OAuthFlows.DeviceCode in self.__valid_flows:
            self._server.app.post(self.__prefix + self._device_code_flow_url)(devicecodeflow_endpoint)

        async def api_devicecodeflow_endpoint(request: Request, response: Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + "api/" + self._device_code_flow_url,
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            return await self._device_code_post(True, request, response)

        if OAuthFlows.DeviceCode in self.__valid_flows:
            self._server.app.post(self.__prefix + "api/" + self._device_code_flow_url)(api_devicecodeflow_endpoint)

        async def devicecodepoll_endpoint(request: Request, response: Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix +self._device_code_poll_url,
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            return await self._device_code_poll(False, request, response)

        if OAuthFlows.DeviceCode in self.__valid_flows:
            self._server.app.post(self.__prefix + self._device_code_poll_url)(devicecodepoll_endpoint)

        async def api_devicecodepoll_endpoint(request: Request, response: Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + "api/" + self._device_code_poll_url,
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            return await self._device_code_poll(False, request, response)

        if OAuthFlows.DeviceCode in self.__valid_flows:
            self._server.app.post(self.__prefix + "api/" + self._device_code_poll_url)(api_devicecodepoll_endpoint)

        #####
        # Delete tokens

        async def get_deletetokens_endpoint(request: Request, response: Response) -> Response:

            if (self.delete_tokens_get_url is None):
                return self.templates.TemplateResponse(
                    request=request,
                    name=self.error_page, 
                    context={
                    'errorMessage': "Delete tokens endpoint not given",
                    'errorCode': ErrorCode.Configuration.value,
                    'errorCodeName': ErrorCode.Configuration.name,
                    }
                )
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "GET",
                "url": self.__prefix +  self.delete_tokens_get_url,
                "ip": request.client.host if request.client else None,
                "user": getattr(request.state.user, 'username', None)
            }))
            return self.templates.TemplateResponse(
                request=request,
                name=self.delete_tokens_page, 
                context={
                "user": getattr(request.state.user, 'username', None),
                "csrfToken": request.state.csrf_token,
                }
            )
        if (self.delete_tokens_get_url is not None):
            self._server.app.get(self.__prefix + self.delete_tokens_get_url)(get_deletetokens_endpoint)

        async def post_deletetokens_endpoint(request: Request, response: Response) -> Response:
            if (self.delete_tokens_post_url is None):
                return self.templates.TemplateResponse(
                    request=request,
                    name=self.error_page, 
                    context={
                    'errorMessage': "Delete tokens endpoint not given",
                    'errorCode': ErrorCode.Configuration.value,
                    'errorCodeName': ErrorCode.Configuration.name,
                    }
                )
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + self.delete_tokens_post_url,
                "ip": request.client.host if request.client else None,
                "user": FastApiSessionServer.username(request)
            }))

            try:
                await self._delete_tokens(request)
                return self.templates.TemplateResponse(
                    request=request,
                    name=self.delete_tokens_page,
                    context={
                        "request": request,
                        "ok": True,
                        "user": FastApiSessionServer.username(request),
                        "csrfToken": request.state.csrf_token,
                    }
                )
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().debug(j({"err": e}))
                CrossauthLogger.logger().error(j({
                    "msg": "Couldn't delete oauth tokens",
                    "cerr": ce
                }))
                return self.templates.TemplateResponse(
                    request=request,
                    name=self.delete_tokens_page,
                    context={
                        "request": request,
                        "ok": False,
                        "user": FastApiSessionServer.username(request),
                        "csrfToken": request.state.csrf_token,
                        "error_message": ce.message,
                        "error_code": ce.code,
                        "error_code_name": ce.code_name,
                    }
                )
        if (self.delete_tokens_post_url is not None):
            self._server.app.post(self.__prefix + self.delete_tokens_post_url)(post_deletetokens_endpoint)

        async def api_deletetokens_endpoint(request: Request, response: Response) -> Response:
            if (self.api_delete_tokens_post_url is None):
                return self.templates.TemplateResponse(
                    request=request,
                    name=self.error_page, 
                    context={
                    'errorMessage': "Delete tokens endpoint not given",
                    'errorCode': ErrorCode.Configuration.value,
                    'errorCodeName': ErrorCode.Configuration.name,
                    }
                )
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": self.__prefix + self.api_delete_tokens_post_url,
                "ip": request.client.host if request.client else None,
                "user": FastApiSessionServer.username(request)
            }))

            try:
                await self._delete_tokens(request)
                return JSONResponse({"ok": True})
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().debug(j({"err": str(ce)}))
                CrossauthLogger.logger().error(j({
                    "msg": "Couldn't delete oauth tokens",
                    "cerr": ce
                }))
                return JSONResponse(
                    {
                        "ok": False,
                        "error_message": ce.message,
                        "error_code": ce.code,
                        "error_code_name": ce.code_name,
                    }
                )
        if (self.api_delete_tokens_post_url is not None):
            self._server.app.post(self.__prefix + self.api_delete_tokens_post_url)(api_deletetokens_endpoint)

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

        if (not have_session_server):
            self.server.app.get(self.__prefix + 'api/getcsrftoken')(api_getcsrftoken_endpoint)
            self.server.app.post(self.__prefix + 'api/getcsrftoken')(api_getcsrftoken_endpoint)

        #####
        # Token endpoints

        def token_endpoint(token_type : str) -> Callable[[Request, Response], Awaitable[Response]]:
            async def token_endpoint_inner(request: Request, Response: Response) -> Response:
                CrossauthLogger.logger().info(j({
                    "msg": "Page visit",
                    "method": "POST",
                    "url": f"{self.__prefix}{token_type}",
                    "ip": request.client.host if request.client else None,
                    "user": request.state.user.username if hasattr(request.state, 'user') else None
                }))

                is_have = False
                token_name = token_type
                if token_type.startswith("have_"):
                    token_name = token_type.replace("have_", "")
                    is_have = True

                token_name1 = token_name.replace("_token", "")
                decode_token = False
                if (token_name1 in self._jwt_tokens):
                    data = JsonOrFormData()
                    await data.load(request)
                    decode_token = data.getAsBool("decode") or True

                #if not request.headers.get("X-CSRF-Token"):
                if (not hasattr(request.state, "csrf_token") or not request.state.csrf_token):
                    return JSONResponse(status_code=401, content={"ok": False, "msg": "No csrf token given"})

                if self._server.have_session_adapter:
                    raise CrossauthError(ErrorCode.Configuration, "Cannot get session data if sessions not enabled")

                oauth_data = await self._server.get_session_data(request, self.session_data_name)
                if not oauth_data:
                    if is_have:
                        return JSONResponse(status_code=200, content={"ok": False})
                    return JSONResponse({}, status_code=204)

                token = oauth_data.get(token_name)
                payload = decode_payload(token) if decode_token else token

                if not payload:
                    if is_have:
                        return JSONResponse(status_code=200, content={"ok": False})
                    return JSONResponse({}, status_code=204)

                if is_have:
                    return JSONResponse(status_code=200, content={"ok": True})
                return JSONResponse(status_code=200, content=payload)
            
            return token_endpoint_inner

        for token_type in self.__token_endpoints:
            self._server.app.post(self.__prefix + token_type)(token_endpoint(token_type))

        async def tokens_endpoint(request: Request, response : Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": "POST",
                "url": f"{self.__prefix}tokens",
                "ip": request.client.host if request.client else None,
                "user": FastApiSessionServer.username(request)
            }))


            try:

                data = JsonOrFormData()
                await data.load(request)

                if (not hasattr(request.state, "csrf_token") or not request.state.csrf_token):
                    return JSONResponse(status_code=401, content={"ok": False, "msg": "No csrf token given"})

                if not self._server.have_session_adapter:
                    raise CrossauthError(ErrorCode.Configuration, 
                        "Cannot get session data if sessions not enabled")

                oauth_data = await self._server.get_session_data(request, self.session_data_name)
                if not oauth_data:
                    return JSONResponse({}, status_code=200)

                tokens_returning: Dict[str, Any] = {}
                for token_type in self.__token_endpoints:

                    is_have = False
                    token_name = token_type
                    if token_type.startswith("have_"):
                        token_name = token_type.replace("have_", "")
                        is_have = True

                    token_name1 = token_name.replace("_token", "")
                    decode_token = False
                    if (token_name1 in self._jwt_tokens):
                        decode_token = data.getAsBool("decode") or True

                    if token_name in oauth_data:
                        payload = oauth_data[token_name]
                        payload = decode_payload(oauth_data[token_name]) if decode_token else oauth_data[token_name]
                        if payload:
                            tokens_returning[token_type] = True if is_have else payload
                    elif is_have:
                        tokens_returning[token_type] = False

                return JSONResponse(status_code=200, content=tokens_returning)
            
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                CrossauthLogger.logger().error(j({"cerr": ce}))
                CrossauthLogger.logger().debug(j({"err": ce}))
                return JSONResponse(status_code=ce.http_status, content={"error": ce.message})


        self._server.app.post(self.__prefix + "tokens")(tokens_endpoint)

        async def bff_endpoint(request: Request, response : Response) -> Response:
            CrossauthLogger.logger().info(j({
                "msg": "Page visit",
                "method": request.method,
                "url": f"{self.__prefix}{self._bff_endpoint_name}",
                "ip": request.client.host if request.client else None,
                "user": request.state.user["username"] if hasattr(request.state, 'user') and request.state.user and "username" in request.state.user else None
            }))

            # Implement logging logic here
            url = request.url.path[len(self.__prefix) + len(self._bff_endpoint_name):]
            orig_url = str(request.url)
            query = ""
            if (orig_url.find("?") > 0):
                query = orig_url[orig_url.find("?"):]
            # Implement debug logging here

            csrf_required = request.method.upper() not in ["GET", "HEAD", "OPTIONS"]
            if self._server.have_session_adapter and csrf_required:
                resp = await self.server.error_if_csrf_invalid(request, response, self.__error_fn)
                if resp.error:
                    return resp.response

            try:
                if not self.server.have_session_adapter:
                    raise CrossauthError(ErrorCode.Configuration, "Cannot get session data if sessions not enabled")

                oauth_data = await self.server.get_session_data(request, self.session_data_name)
                if not oauth_data:
                    return JSONResponse(status_code=401, content={"ok": False})

                access_token = oauth_data.get("access_token")
                if oauth_data and oauth_data.get("access_token"):
                    resp = await self._refresh(request, response, True, True, oauth_data.get("refresh_token"), oauth_data.get("expires_at"))
                    if resp and not isinstance(resp, Response) and "access_token" in resp:
                        access_token = resp["access_token"]

                headers = {
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                }
                if access_token:
                    headers["Authorization"] = f"Bearer {access_token}"
                
                try:
                    body : str|None = None
                    try:
                        body = await request.json()
                    except: pass
                    async with aiohttp.ClientSession() as session:
                        if (body is None):
                            clientResponse = await session.request(
                                request.method,
                                f"{self._bff_base_url}{url}{query}",
                                headers=headers,
                            )
                        else:
                            clientResponse = await session.request(
                                request.method,
                                f"{self._bff_base_url}{url}{query}",
                                headers=headers,
                                json=await request.json(),
                            )

                        clientResponse.raise_for_status()
                        return JSONResponse(await clientResponse.json(), 
                                    status_code=clientResponse.status, 
                                    headers=clientResponse.headers)
                except Exception as e:
                    CrossauthLogger.logger().error(j({"err": e}))
                    return JSONResponse({}, status_code=500)

                body = resp.json()
                response.headers.update(resp.headers)
                return JSONResponse(status_code=resp.status_code, content=body)

            except Exception as e:
                CrossauthLogger.logger().error(j({"err": e}))
                return JSONResponse(status_code=500, content={})

        if (self._bff_endpoint_name != ""):
            if self._bff_base_url is None:
                raise CrossauthError(ErrorCode.Configuration, "If enabling BFF endpoints, must also define bff_base_url")

            if self._bff_base_url.endswith("/"):
                self._bff_base_url = self._bff_base_url[:-1]

            for endpoint in self._bff_endpoints:
                url = endpoint.url
                if "?" in url or "#" in url:
                    raise CrossauthError(ErrorCode.Configuration, "BFF urls may not contain query parameters or page fragments")

                if not url.startswith("/"):
                    raise CrossauthError(ErrorCode.Configuration, "BFF urls must be absolute and without the HTTP method, hostname or port")

                methods = endpoint.methods
                match_sub_urls = endpoint.match_sub_urls

                route = url
                if match_sub_urls:
                    if not route.endswith("/"):
                        route += "/"
                    route += "{full_path:path}"

                self._server.app.add_api_route(f"{self.__prefix}{self._bff_endpoint_name}{route}", bff_endpoint, methods=cast(List[str], methods))


    #################################################
    # Private methods

    async def _refresh(self, request: Request,
                    response: Response,
                    silent: bool,
                    only_if_expired: bool,
                    refresh_token: Optional[str] = None,
                    expires_at: Optional[int] = None) -> OAuthTokenResponseWithExpiry|Response|None:
        if not expires_at or not refresh_token:
            if not silent:
                return await self.__receive_token_fn({},
                                                self,
                                                request,
                                                response if not silent else None)
            return None

        if not only_if_expired or expires_at <= int(datetime.now().timestamp() * 1000):
            try:
                resp = await self.refresh_token_flow(refresh_token)
                if ("id_token" in resp):
                    # This token is intended for us, so validate it
                    if (await self.validate_id_token(resp["id_token"]) is None):
                        resp : OAuthTokenResponse = {"error": "access_denied", "error_description": "Invalid ID token received"}
                if not resp.get('error') and not resp.get('access_token'):
                    resp['error'] = "server_error"
                    resp['error_description'] = "Unexpectedly did not receive error or access token"
                if not resp.get('error'):
                    resp1 = await self.__receive_token_fn(resp,
                                                        self,
                                                        request,
                                                        response if not silent else None)
                    if not silent:
                        return resp1
                if not silent:
                    ce = CrossauthError.from_oauth_error(resp.get('error', 'server_error'),
                                                        resp.get('error_description'))
                    return await self.__error_fn(self.server, request, response, ce)
                expires_in = resp.get('expires_in')
                instance = JWT()
                if not expires_in and "access_token" in resp and "access" in self._jwt_tokens:
                    payload = instance.decode(resp['access_token'], None, do_verify=False, do_time_check=False)
                    if payload.get('exp'):
                        expires_in = payload['exp']
                if not expires_in:
                    raise CrossauthError(ErrorCode.BadRequest,
                                        "OAuth server did not return an expiry for the access token")
                expires_at = int((datetime.now() + timedelta(seconds=expires_in)).timestamp() * 1000)
                token_resp : OAuthTokenResponseWithExpiry = {
                }
                if ("access_token" in resp): token_resp["access_token"] = resp["access_token"]
                if ("refresh_token" in resp): token_resp["refresh_token"] = resp["refresh_token"]
                if ("expires_in" in resp): 
                    token_resp["expires_in"] = resp["expires_in"]
                    token_resp["expires_at"] = expires_at
                if ("error" in resp): token_resp["error"] = resp["error"]
                if ("error_description" in resp): token_resp["error_description"] = resp["error_description"]
                return token_resp
            except Exception as e:
                CrossauthLogger.logger().debug(j({'err': e}))
                CrossauthLogger.logger().error(j({
                    'cerr': e,
                    'msg': "Failed refreshing access token"
                }))
                if not silent:
                    ce = CrossauthError.as_crossauth_error(e)
                    return await self.__error_fn(self.server, request, response, ce)
                return {
                    'error': "server_error",
                    'error_description': "Failed refreshing access token"
                }
        return None

    async def _refresh_tokens(self, request: Request,
                            response: Response,
                            silent: bool,
                            only_if_expired: bool):
        if (not hasattr(request.state, "csrf_token") or not request.state.csrf_token):
            return JSONResponse(content={"ok": False, "msg": "No csrf token given"},
                            status_code=401,
                            headers=response.headers)
        if not self.server.have_session_adapter:
            raise CrossauthError(ErrorCode.Configuration,
                                "Cannot get session data if sessions not enabled")
        oauth_data = await self.server.get_session_data(request, self.session_data_name)
        if not oauth_data or not oauth_data.get('refresh_token'):
            if silent:
                return Response(status_code=204, headers=response.headers)
            else:
                ce = CrossauthError(ErrorCode.InvalidSession,
                                    "No tokens found in session")
                return await self.__error_fn(self.server,
                                        request,
                                        response,
                                        ce)

        resp = await self._refresh(request,
                                response,
                                silent,
                                only_if_expired,
                                oauth_data['refresh_token'],
                                oauth_data.get('expires_at'))
        if not silent:
            if resp is None:
                return await self.__receive_token_fn({}, self, request, response)
            return resp
        return JSONResponse(content={"ok": True, "expires_at": resp['expires_at'] if resp and not isinstance(resp, Response) and 'expires_at' in resp else None},
                        status_code=200,
                        headers=response.headers)

    async def _delete_tokens(self, request: Request) -> None:
        if not self._server.have_session_adapter:
            raise CrossauthError(ErrorCode.Configuration, 
                "Cannot delete tokens if sessions not enabled")
        
        if not request.state.csrf_token:
            raise CrossauthError(ErrorCode.InvalidSession,
                "Missing or incorrect CSRF token")
        
        await self._server.delete_session_data(request, self.session_data_name)

    async def _password_post(self, is_api: bool, request : Request, response : Response) -> Response|None:
        if self.server.have_session_adapter:
            # if sessions are enabled, require a csrf token
            resp1 = await self._server.error_if_csrf_invalid(request, response, self.__error_fn)
            if resp1.error:
                return resp1.response
        body = JsonOrFormData()
        await body.load(request)
        try:
            if (body.getAsStr("username") is None or body.getAsStr("password") is None):
                raise CrossauthError(ErrorCode.BadRequest, "Username and password must be given for the password flow")
            resp = await self.password_flow(body.getAsStr("username") or "", body.getAsStr("password") or "", body.getAsStr("scope"))
            if ("id_token" in resp):
                # This token is intended for us, so validate it
                if (await self.validate_id_token(resp["id_token"]) is None):
                    resp : OAuthTokenResponse = {"error": "access_denied", "error_description": "Invalid ID token received"}
            if "error" in resp and resp["error"] == "mfa_required" and "mfa_token" in resp and resp["mfa_token"] and OAuthFlows.PasswordMfa in self.__valid_flows:
                mfa_token = resp["mfa_token"]
                resp2 = await self._password_mfa(is_api, mfa_token, body.getAsStr("scope", None), request, response)
                if ("id_token" in resp2):
                    # This token is intended for us, so validate it
                    if (await self.validate_id_token(resp2["id_token"]) is None):
                        resp2 : OAuthTokenResponse = {"error": "access_denied", "error_description": "Invalid ID token received"}
                if "error" in resp2:
                    ce = CrossauthError.from_oauth_error(resp2["error"], resp2["error_description"] if "error_description" in resp2 else resp2["error"])
                    if is_api:
                        return await self.__error_fn(self.server, request, response, ce)
                        
                    return self.templates.TemplateResponse(
                        request=request,
                        name=self.password_flow_page,
                        context={
                            'user': request.state.user,
                            'username': body.getAsStr("username"),
                            'scope': body.getAsStr("scope"),
                            'errorMessage': ce.message,
                            'errorCode': ce.code,
                            'errorCodeName': ce.code_name,
                            'csrfToken': request.state.csrf_token
                        })
                return await self.__receive_token_fn(resp2, self, request, response)

            elif "error" in resp:
                ce = CrossauthError.from_oauth_error(resp["error"], resp["error_description"] if "error_description" in resp else resp["error"])
                if is_api:
                    return await self.__error_fn(self.server, request, response, ce)
                return self.templates.TemplateResponse(
                    request=request,
                    name=self.password_flow_page, 
                    context={
                    'user': request.state.user,
                    'username': body.getAsStr("username"),
                    'scope': body.getAsStr("scope"),
                    'errorMessage': ce.message,
                    'errorCode': ce.code,
                    'errorCodeName': ce.code_name,
                    'csrfToken': request.state.csrf_token
                })
            return await self.__receive_token_fn(resp, self, request, response)
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().error(j({
                'msg': "Error receiving token",
                'cerr': ce,
                'user': request.state.user.user if request.state.user else None
            }))
            CrossauthLogger.logger().debug(j({'err': e}))
            if is_api:
                return await self.__error_fn(self.server, request, response, ce)
            return self.templates.TemplateResponse(
                request=request,
                name=self.password_flow_page, 
                context={
                'user': request.state.user,
                'username': body.getAsStr("username"),
                'scope': body.getAsStr("scope"),
                'errorMessage': ce.message,
                'errorCode': ce.code,
                'errorCodeName': ce.code_name,
                'csrfToken': request.state.csrf_token
            })

    async def _password_mfa(self, is_api: bool, mfa_token: str, scope: str|None, request : Request, response : Response) -> OAuthMfaAuthenticatorsOrTokenResponse:
        authenticators_response = await self.mfa_authenticators(mfa_token)
        if ("error" in authenticators_response or
                "authenticators" not in authenticators_response or
                len(authenticators_response["authenticators"]) == 0 or
                (len(authenticators_response["authenticators"]) > 1 and
                ("active" not in authenticators_response["authenticators"][0] or authenticators_response["authenticators"][0]["active"] == False))):
            if "error" in authenticators_response:
                return cast(OAuthMfaAuthenticatorsOrTokenResponse, authenticators_response)
            else:
                return {
                    'error': "access_denied",
                    'error_description': "No MFA authenticators available"
                }

        auth = authenticators_response["authenticators"][0]
        if "authenticator_type" in auth and auth["authenticator_type"] == "otp" and "id" in auth:
            resp = await self.mfa_otp_request(mfa_token, auth["id"])
            if "error" in resp or "challenge_type" not in resp or resp["challenge_type"] != "otp":
                error = resp["error"] if "error" in resp else "server_error"
                error_description = resp["error_description"] if "error_description" in resp else "Invalid response from MFA OTP challenge"
                return {
                    "error": error,
                    "error_description": error_description
                }
            
            ret : OAuthMfaAuthenticatorsOrTokenResponse = {
                'mfa_token': mfa_token,
            }
            if (scope): ret["scope"] = scope
            return ret
        if "authenticator_type" in auth and auth["authenticator_type"] == "oob" and "id" in auth and "oob_channel" in auth:
            resp = await self.mfa_oob_request(mfa_token, auth["id"])
            if ("error" in resp or "challenge_type" not in resp or resp["challenge_type"] != "oob" or
                    not resp["oob_code"] or resp["binding_method"] != "prompt"):
                error = resp["error"] if "error" in resp else "server_error"
                error_description = resp["error_description"] if "error_description" in resp else "Invalid response from MFA OOB challenge"
                return {
                    "error": error,
                    "error_description": error_description
                }

            ret : OAuthMfaAuthenticatorsOrTokenResponse = {
                'mfa_token': mfa_token,
                'oob_channel': auth["oob_channel"],
                'challenge_type': resp.challenge_type,
                'binding_method': resp.binding_method,
                'oob_code': resp.oob_code,
                'name': auth["name"] if "name" in auth else auth["id"],
            }
            if (scope): ret["scope"] = scope

        ce = CrossauthError(ErrorCode.UnknownError, "Unsupported MFA type " + (auth["authenticator_type"] if "authenticator_type" in auth else "") + " returned")
        return {
            "error": ce.oauthErrorCode,
            "error_description": ce.message
        }
    
    async def _password_otp(self, is_api: bool, request : Request, response : Response) -> Response:
        body = JsonOrFormData()
        await body.load(request)
        if (body.getAsStr("mfa_token") is None or body.getAsStr("otp") is None):
            raise CrossauthError(ErrorCode.BadRequest, "mfa_token or otp missing in Password OTP request")
        resp = await self.mfa_otp_complete(body.getAsStr("mfa_token") or "", body.getAsStr("otp") or "")
        if ("id_token" in resp):
            # This token is intended for us, so validate it
            if (await self.validate_id_token(resp["id_token"]) is None):
                resp : OAuthTokenResponse = {"error": "access_denied", "error_description": "Invalid ID token received"}
        if "error" in resp:
            error = resp["error"] if "error" in resp else "server_error"
            error_description = resp["error_description"] if "error_description" in resp else "Error completing MFA"
            ce = CrossauthError.from_oauth_error(error, error_description)
            CrossauthLogger.logger().warn(j({
                'msg': "Error completing MFA",
                'cerr': ce,
                'user': request.state.user.user if request.state.user else None,
                'hashed_mfa_token': Crypto.hash(body.getAsStr("mfa_token") or ""),
            }))
            CrossauthLogger.logger().debug(json.dumps({'err': ce}))
            if is_api:
                return await self.__error_fn(self.server, request, response, ce)
            return self.templates.TemplateResponse(
                request=request,
                name=self.mfa_otp_page, 
                context={
                'user': request.state.user,
                'scope': body.getAsStr("scope"),
                'mfa_token': body.getAsBool("mfa_token"),
                'challenge_type': body.getAsStr("challenge_type"),
                'errorMessage': ce.message,
                'errorCode': ce.code,
                'errorCodeName': ce.code_name,
                'csrfToken': request.state.csrf_token
            })
        return await self.__receive_token_fn(resp, self, request, response) or response

    async def _password_oob(self, is_api: bool, request : Request, response : Response) -> Response:
        body = JsonOrFormData()
        await body.load(request)
        if (body.getAsStr("mfa_token") is None or body.getAsStr("oob_code") is None or body.getAsStr("binding_code") is None):
            raise CrossauthError(ErrorCode.BadRequest, "mfa_token, oob_code and binding_code required for OOB request")
        resp = await self.mfa_oob_complete(body.getAsStr("mfa_token") or "", body.getAsStr("oob_code") or "", body.getAsStr("binding_code") or "")
        if ("id_token" in resp):
            # This token is intended for us, so validate it
            if (await self.validate_id_token(resp["id_token"]) is None):
                resp : OAuthTokenResponse = {"error": "access_denied", "error_description": "Invalid ID token received"}
        if "error" in resp:
            error = resp["error"] if "error" in resp else "server_error"
            error_description = resp["error_description"] if "error_description" in resp else "Error completing MFA"
            ce = CrossauthError.from_oauth_error(error, error_description)
            CrossauthLogger.logger().warn(j({
                'msg': "Error completing MFA",
                'cerr': ce,
                'user': request.state.user.user if request.state.user else None,
                'hashed_mfa_token': Crypto.hash(body.getAsStr("mga_token") or ""),
            }))
            CrossauthLogger.logger().debug(j({'err': ce}))
            if is_api:
                return await self.__error_fn(self.server, request, response, ce)
            return self.templates.TemplateResponse(
                request=request,
                name=self.mfa_oob_page, 
                context={
                'user': request.state.user,
                'scope': body.getAsStr("scope"),
                'oob_code': body.getAsStr("oob_code"),
                'name': body.getAsStr("name"),
                'challenge_type': body.getAsStr("challenge_type"),
                'mfa_token': body.getAsStr("mfa_token"),
                'errorMessage': ce.message,
                'errorCode': ce.code,
                'errorCodeName': ce.code_name,
                'csrfToken': request.state.csrf_token
            })
        return await self.__receive_token_fn(resp, self, request, response) or response

    async def _device_code_post(self, is_api: bool, request: Request, response : Response) -> Response:
        if self._server.have_session_adapter:
            # if sessions are enabled, require a csrf token
            ret = await self._server.error_if_csrf_invalid(request, response, self.__error_fn)
            if ret.error:
                return ret.response
            
        body = JsonOrFormData()
        await body.load(request)

        try:
            if not request.state.csrf_token:
                raise CrossauthError(ErrorCode.Unauthorized, "CSRF token missing or invalid")

            if not self._device_authorization_url:
                raise CrossauthError(ErrorCode.Configuration, "Must set device authorization url to use device code flow")
            url = self.auth_server_base_url
            if not url.endswith("/"):
                url += "/"
            url += self._device_authorization_url
            resp = await self.start_device_code_flow(url, body.getAsStr("scope"))

            if "error" in resp:
                ce = CrossauthError.from_oauth_error(resp["error"], resp["error_description"] if "error_description" in resp else resp["error"])
                data : Dict[str,Any] = {
                    "user": request.state.user,
                    "scope": body.getAsStr("scope"),
                    "error_message": ce.message,
                    "error_code": ce.code,
                    "error_code_name": ce.code_name,
                    "csrfToken": request.state.csrf_token,
                    "error": resp["error"],
                    "error_description": resp.get("error_description"),
                }
                if is_api:
                    return JSONResponse(content=resp, status_code=ce.http_status, headers=response.headers)
                else:
                    return self.templates.TemplateResponse(
                        request=request,
                        name=self.device_code_flow_page, 
                        context=data)

            qr_url : str|None = None
            if "verification_uri_complete" in resp:
                try:
                    qr = qrcode.QRCode(version=1, box_size=10, border=5) 
                    qr.add_data(resp["verification_uri_complete"]) 
                    qr.make(fit=True) 
                    img = qr.make_image(fill_color="black", back_color="white") 
                    img1 = img.get_image()
                    buffered = io.BytesIO()
                    img1.save(buffered, format="PNG")
                    qr_url = "data:image/png;base64, " + base64.b64encode(buffered.getvalue()).decode("utf-8")

                except Exception as err:
                    CrossauthLogger.logger().debug(json.dumps({"err": str(err)}))
                    CrossauthLogger.logger().warn(json.dumps({"msg": "Couldn't generate verification URL QR Code"}))

            if is_api:
                return JSONResponse(content=resp, headers=response.headers)
            else:
                context : Dict[str,Any] = {
                    "user": request.state.user,
                    "scope": body.getAsStr("scope"),
                    "verification_uri_qrdata": qr_url,
                    **resp
                }
                return self.templates.TemplateResponse(
                    request=request,
                    name=self.device_code_flow_page, 
                    context=context)

        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().error(j({
                "msg": "Error receiving token",
                "cerr": ce,
                "user": request.state.user.user if request.state.user else None
            }))
            CrossauthLogger.logger().debug(json.dumps({"err": str(e)}))
            data = {
                "error_message": ce.message,
                "error_code": ce.code,
                "error_code_name": ce.code_name,
                "error": ce.oauthErrorCode,
                "error_description": ce.message,
            }
            if is_api:
                return JSONResponse(content=data, status_code=ce.http_status, headers=response.headers)

            return self.templates.TemplateResponse(
                request=request,
                name=self.device_code_flow_page, 
                context={
                "user": request.state.user,
                "csrfToken": request.state.csrf_token,
                "scope": body.getAsStr("scope"),
                **data,
            })

    async def _device_code_poll(self, is_api: bool, request: Request, response: Response) -> Response:

        body = JsonOrFormData()
        await body.load(request)
        device_code = body.getAsStr("device_code")
        if (device_code is None):
            raise CrossauthError(ErrorCode.BadRequest, "device_code not present")
        try:
            resp = await self.poll_device_code_flow(device_code)
            if ("id_token" in resp):
                # This token is intended for us, so validate it
                if (await self.validate_id_token(resp["id_token"]) is None):
                    resp : OAuthDeviceResponse = {"error": "access_denied", "error_description": "Invalid ID token received"}

            if resp.get("error"):
                return JSONResponse(content=resp, headers=response.headers)

            ret = await self.__receive_token_fn(resp, self, request, None if is_api else response)
            return ret or JSONResponse({})
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().error(json.dumps({
                "msg": "Error receiving token",
                "cerr": ce,
                "user": request.state.user.user if request.state.user else None
            }))
            CrossauthLogger.logger().debug(json.dumps({"err": str(e)}))
            return await self.__error_fn(self.server, request, response, ce)

    async def store_session_data(self, session_data : Dict[str, Any], request: Request, response: Response|None):
        if self.server.have_session_server:
            session_cookie_value = self.server.get_session_cookie_value(request)
            if not session_cookie_value and response is not None:
                session_cookie_value = await self.server.create_anonymous_session(request, response, {
                    self.session_data_name: session_data
                })
            else:
                await self.server.update_session_data(request, self.session_data_name, session_data)
        else:
            if not self.server.have_session_adapter:
                raise CrossauthError(ErrorCode.Configuration, "Cannot get session data if sessions not enabled")
            await self.server.update_session_data(request, self.session_data_name, session_data)


##############################################################
## Default functions

async def json_error(server: FastApiServerBase, 
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

async def page_error(server: FastApiServerBase,
    request: Request,
    response: Response,
    ce: CrossauthError) -> Response : 
    CrossauthLogger.logger().debug(j({"err": ce}))
    templates = server.templates

    return templates.TemplateResponse(
        request=request,
        name=server.error_page,
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
            CrossauthLogger.logger().debug(j({"err": e}))
            CrossauthLogger.logger().error(j({"msg": "Couldn't decode id token"}))
    return payload

async def send_json(oauth_response: OAuthTokenResponse|OAuthDeviceResponse,
                    client: FastApiOAuthClient,
                    request: Request,
                    response: Response|None = None) -> Response|None:
    if response is not None:
        resp : Dict[str,Any] = {
            "ok": True,
            **oauth_response,
        }
        if "id_token" in oauth_response and "id" in client.jwt_tokens:
            resp["id_payload"] = decode_payload(oauth_response["id_token"])
        return JSONResponse(resp, 200, headers=response.headers)

def log_tokens(oauth_response: OAuthTokenResponse|OAuthDeviceResponse, client: FastApiOAuthClient):
    instance = JWT()
    if "access_token" in oauth_response and "access" in client.jwt_tokens:
        try:
            jwt = instance.decode(oauth_response["access_token"], None, do_verify=False, do_time_check=False)
            jti : str|None = jwt.get("jti")
            if (jti == None):
                jti = jwt.get("sid")
            hash_value = Crypto.hash(jti) if jti else None
            CrossauthLogger.logger().debug(j({"msg": "Got access token", "accessTokenHash": hash_value}))
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": e}))

    if "id_token" in oauth_response and "id" in client.jwt_tokens:
        try:
            jwt = instance.decode(oauth_response["id_token"], None, do_verify=False, do_time_check=False)
            jti : str|None = jwt.get("jti")
            if (jti == None):
                jti = jwt.get("sid")
            hash_value = Crypto.hash(jti) if jti else None
            CrossauthLogger.logger().debug(j({"msg": "Got id token", "idTokenHash": hash_value}))
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": e}))

    if "refresh_token" in oauth_response and "refresh" in client.jwt_tokens:
        try:
            jwt = instance.decode(oauth_response["refresh_token"], None, do_verify=False, do_time_check=False)
            jti : str|None = jwt.get("jti")
            if (jti == None):
                jti = jwt.get("sid")
            hash_value = Crypto.hash(jti) if jti else None
            CrossauthLogger.logger().debug(j({"msg": "Got refresh token", "refreshTokenHash": hash_value}))
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": e}))

async def send_in_page(oauth_response: OAuthTokenResponse|OAuthDeviceResponse,
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

    log_tokens(oauth_response, client)

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
    if not client.server.have_session_adapter:
        raise CrossauthError(ErrorCode.Configuration, "Cannot update session data if sessions not enabled")
    
    expires_in : int|None = oauth_response["expires_in"] if "expires_in" in oauth_response else None
    if expires_in is None and "access_token" in oauth_response and "access" in client.jwt_tokens:
        instance = JWT()
        payload = instance.decode(oauth_response["access_token"], None, do_verify=False, do_time_check=False)
        if 'exp' in payload:
            expires_in = payload['exp']
    
    if not expires_in:
        raise CrossauthError(ErrorCode.BadRequest, "OAuth server did not return an expiry for the access token")
    
    expires_at = int(datetime.now().timestamp()*1000) + (expires_in * 1000)
    
    session_data : dict[str,Any] = {**oauth_response, "expires_at": expires_at}
    if ("id_token" in oauth_response and "id" in client.jwt_tokens):
        # this was already validated before receive_token_fn was called
        id_payload = decode_payload(oauth_response["id_token"])
        session_data["id_payload"] = id_payload

    await client.store_session_data(session_data, request, response)
    if client.server.have_session_server:
        session_cookie_value = client.server.get_session_cookie_value(request)
        if not session_cookie_value and response is not None:
            session_cookie_value = await client.server.create_anonymous_session(request, response, {
                client.session_data_name: session_data
            })
        else:
            await client.server.update_session_data(request, client.session_data_name, session_data)
    else:
        if not client.server.have_session_adapter:
            raise CrossauthError(ErrorCode.Configuration, "Cannot get session data if sessions not enabled")
        await client.server.update_session_data(request, client.session_data_name, {**oauth_response, "expires_at": expires_at})

async def save_in_session_and_load(oauth_response: OAuthTokenResponse|OAuthDeviceResponse,
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

    log_tokens(oauth_response, client)
    templates = client.templates
    try:
        if "access_token" in oauth_response or "id_token" in oauth_response or "refresh_token" in oauth_response:
            await update_session_data(oauth_response, client, request, response)

        if response:

            context : Dict[str,Any] = {**oauth_response}
            if ("id_token" in oauth_response):
                context["id_payload"] = decode_payload(oauth_response["id_token"])

            return templates.TemplateResponse(
                    request=request,
                    name=client.authorized_page,
                    context = context,
                    status_code=200, headers=response.headers)
    except Exception as e:
        ce = CrossauthError.as_crossauth_error(e)
        CrossauthLogger.logger().debug(j({"err": e}))
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

async def save_in_session_and_redirect(oauth_response: OAuthTokenResponse|OAuthDeviceResponse,
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

    log_tokens(oauth_response, client)

    templates = client.templates
    try:
        if "access_token" in oauth_response or "id_token" in oauth_response or "refresh_token" in oauth_response:
            await update_session_data(oauth_response, client, request, response)

        if response:
            context : Dict[str,Any] = {**oauth_response}
            if ("id_token" in oauth_response):
                context["id_payload"] = oauth_response["id_token"]

            return RedirectResponse(client.authorized_url, headers=response.headers, status_code=302)
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

