# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import List, Dict, Any, Optional, cast, Mapping, TypedDict, Literal
from fastapi import FastAPI, Request, Response
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.interfaces import User
from crossauth_backend.storage import UserStorage
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.oauth.resserver import OAuthResourceServer, OAuthResourceServerOptions
from crossauth_backend.oauth.client import OAuthTokenConsumer
from crossauth_fastapi.fastapisessionadapter import FastApiSessionAdapter
from fastapi.responses import JSONResponse
import re
from datetime import datetime

class ProtectedEndpoint(TypedDict, total=False):
    scope: List[str]
    accept_session_authorization: bool
    suburls: bool

class FastApiOAuthResourceServerOptions(OAuthResourceServerOptions, total=False):
    """
    Options for :class:`FastApiOAuthResourceServer`
    """

    user_storage : UserStorage
    """ 
    If you set this and your access tokens have a user (`sub` claim), 
    the `user` field in the request will be populated with a valid
    access token.

    Not currently supported
    """

    error_body : Mapping[str, Any]
    """
    If you enabled `protected_endpoints` in 
    :class:`FastApiOAuthResourceServer`
    and the access token is invalid, a 401 reply will be sent before
    your endpoint is hit.  This will be the body,  Default {}.
    """

    protected_endpoints : Mapping[str, ProtectedEndpoint]
    """
    If you define this, matching resource server endpoints will return
    a status code of 401 Access Denied if the key is invalid or the 
    given scopes are not present.
    """

    token_locations : List[Literal["beader","session"]]
    """
    Where access tokens may be found (in this order).
    
    If this contains `session`, must also provide the session adapter
    
    Default `header`
    """

    session_data_name : str
    """
    If token_locations contains `session`, tokens are keyed on this name.
    
    Default `oauth` 
    """

    session_adapter : FastApiSessionAdapter
    """
    If `token_locations` contains `session`, must provide a session adapter
    """
   

class Authorization(TypedDict, total=False):
    authorized: bool
    token_payload: Mapping[str, Any]
    user: User
    error: str
    error_description: str

class FastApiOAuthResourceServer(OAuthResourceServer):
    """
    OAuth resource server. 
    
    You can subclass this, simply instantiate it, or create it through
    :class:`FastApiServer`.  
    
    There are two way of using this class.  If you don't set
    `protected_endpoints` in 
    the constructor, then in your
    protected endpoints, call :attr:`FastApiOAuthResourceServer.authorized`
    to check if the access token is valid and get any user credentials.
    
    If you do set `protected_endpoints` in 
    the constructor
    then a `preHandler` iscreated.

    ** Middleware **
    The middleware
    hook will set the `access_token_payload`, `user` and `scope` fields 
    on the FastApi request object based on the content
    of the access token in the `Authorization` header if it is valid.
    It will also set `auth_type` to `oauth`.  
    If a user storage is provided,
    it will be used to look the user up.  Otherwise a minimal user object
    is created.
    If it is not valid it will set the `auth_error` and `auth_error_description`.
    If the access token is invalid, or there is an error, a 401 or 500
    response is sent before executing your endpoint code.  As per
    OAuth requirements, if the response is a 401, the WWW-Authenticate header
    is set.  If a scope is required this is included in that header.
    """

    def __init__(self, app: FastAPI, token_consumers: List[OAuthTokenConsumer], options: FastApiOAuthResourceServerOptions = {}):
        """
        Constructor

        :param FastAPI app: the FastAPI app
        :param token_consumers: A list of token consumers, one per issuer and audience
        :param FastApiOAuthResourceServerOptions options: See :class:`FastApiOAuthResourceServerOptions`
        
        """
        super().__init__(token_consumers, options)
        self.user_storage = options["user_storage"] if "user_storage" in options else None
        self.session_adapter = options["session_adapter"] if "session_adapter" in options else None

        self._protected_endpoints: Mapping[str, ProtectedEndpoint] = {}
        self._protected_endpoint_prefixes: List[str] = []
        self.__error_body : Dict[str, Any] = {}
        self.__token_locations : List[Literal["header","session"]] = ["header",]
        self.__session_data_name : str = "oauth"
        set_parameter("error_body", ParamType.Json, self, options, "OAUTH_RESSERVER_ACCESS_DENIED_BODY")
        set_parameter("token_locations", ParamType.JsonArray, self, options, "OAUTH_TOKEN_LOCATIONS")
        set_parameter("session_data_name", ParamType.String, self, options, "OAUTH_SESSION_DATA_NAME")

        self._access_token_is_jwt = options["access_token_is_jwt"] if "access_token_is_jwt" in options else True
        if 'protected_endpoints' in options:
            regex = re.compile(r'^[!#\$%&\'\(\)\*\+,\.\/a-zA-Z\[\]\^_`-]+')
            for key, value in options['protected_endpoints'].items():
                if not key.startswith("/"):
                    raise ValueError("protected endpoints must be absolute paths without the protocol and hostname")
                if 'scope' in value:
                    for s in value['scope']:
                        if not regex.match(s):
                            raise ValueError(f"Illegal characters in scope {s}")
            self._protected_endpoints = {**options['protected_endpoints']}
            for name in options['protected_endpoints']:
                endpoint = self._protected_endpoints[name]
                if ("suburls" in endpoint and endpoint["suburls"]):
                    if (not name.endswith("/")):
                        name += "/"
                        self._protected_endpoints[name] = endpoint
                    self._protected_endpoint_prefixes.append(name)

        if 'protected_endpoints' in options:
            @app.middleware("http")
            async def pre_handler(request: Request, call_next): # type: ignore
                url_without_query = request.url.path
                matches = False
                matching_endpoint = ""
                if (url_without_query in self._protected_endpoints):
                    matches = True
                    matching_endpoint = url_without_query
                else:
                    for name in self._protected_endpoint_prefixes:
                        if url_without_query.startswith(name):
                            matches = True
                            matching_endpoint = name
                if not matches:
                    return cast(Response, await call_next(request))

                auth_response = await self.authorized(request)
                statedict = request.state.__dict__["_state"]
                if not ("user" in statedict and statedict["user"] is not None and "auth_type" in statedict and statedict["auth_type"] == "cookie" 
                        and self._protected_endpoints[matching_endpoint].get('accept_session_authorization') != True):
                    if not auth_response:
                        request.state.auth_error = "access_denied"
                        request.state.auth_error_description = "No access token"
                        authenticate_header = self.authenticate_header(request);
                        return JSONResponse(content=self.__error_body, status_code=401, headers={"WWW-Authenticate": authenticate_header})

                    if not auth_response['authorized']:
                        authenticate_header = self.authenticate_header(request)
                        return JSONResponse(content=self.__error_body, status_code=401, headers={"WWW-Authenticate": authenticate_header})

                if auth_response:
                    request.state.access_token_payload = auth_response.get('token_payload')
                    request.state.user = auth_response.get('user')
                    if 'scope' in auth_response.get('token_payload', {}):
                        if isinstance(auth_response['token_payload']['scope'], list):
                            request.state.scope = [token_scope for token_scope in auth_response['token_payload']['scope'] if isinstance(token_scope, str)]
                        elif isinstance(auth_response['token_payload']['scope'], str):
                            request.state.scope = auth_response['token_payload']['scope'].split(" ")

                    endpoint = self._protected_endpoints[matching_endpoint]
                    if 'scope' in endpoint:
                        scopes = endpoint["scope"]
                        for scope in scopes:
                            if not request.state.scope or (scope not in request.state.scope and self._protected_endpoints[url_without_query].get('accept_session_authorization') != True):
                                request.state.scope = None
                                request.state.access_token_payload = None
                                request.state.user = None
                                request.state.auth_error = "access_denied"
                                request.state.auth_error_description = "Access token does not have sufficient scope"
                                return JSONResponse(content=self.__error_body, status_code=401)

                    request.state.auth_type = "oauth"
                    request.state.auth_error = auth_response.get('error')
                    if request.state.auth_error == "access_denied":
                        authenticate_header = self.authenticate_header(request)
                        return JSONResponse(content=self.__error_body, status_code=401, headers={"WWW-Authenticate": authenticate_header})
                    elif request.state.auth_error:
                        return JSONResponse(content=self.__error_body, status_code=500)

                    request.state.auth_error_description = auth_response.get('error_description')

                return cast(Response, await call_next(request))

            self.app = app

    def authenticate_header(self, request: Request) -> str:
        url_without_query = request.url.path
        if url_without_query in self._protected_endpoints:
            header = "Bearer"
            if 'scope' in self._protected_endpoints[url_without_query]:
                header += ' scope="' + " ".join(self._protected_endpoints[url_without_query].get('scope', [])) + '"'
            return header
        return ""

    async def authorized(self, request: Request) -> Optional[Dict[str, Any]]:
        """
        If there is no bearer token, returns `undefinerd`.  If there is a
        bearer token and it is a valid access token, returns the token
        payload.  If there was an error, returns it in OAuth form.
        
        :param Request request: the FastAPI Request object

        :return: an object with the following fiekds
          - `authorized` : `true` or `false`
          - `tokenPayload` : the token payload if the token is valid
          - `error` : if the token is not valid
          - `error_description` : if the token is not valid
          - `user` set if `sub` is defined in the token, a userStorage has
            been defined and it matches
        If there was no valid token, None is returned
        """
        try:

            payload : Dict[str,Any] | None = None

            for loc in self.__token_locations:
                if loc == "header":
                    resp = await self.token_from_header(request)
                    if resp is not None:
                        payload = resp
                        break
                else:
                    resp = await self.token_from_session(request)
                    if resp is not None:
                        payload = resp
                        break

            user : User|None = None
            if payload is not None:
                if 'sub' in payload:
                    if self.user_storage:
                        user_resp = await self.user_storage.get_user_by_username(payload['sub'])
                        if user_resp:
                            user = user_resp["user"]
                        request.state.user = user
                    else:
                        user = {
                            "id": payload["userid"] if "userid" in payload else payload["sub"],
                            "username": payload["sub"],
                            "state": payload["state"] if "state" in payload else "active",
                            "factor1": payload["factor1"] if "factor1" in payload else ""
                        }
                        request.state.user = user
                return {'authorized': True, 'token_payload': payload, 'user': user}
            return {'authorized': False}

        except Exception as e:
            return {'authorized': False, 'error': "server_error", 'error_description': str(e)}
        return None

    async def token_from_header(self, request: Request) -> Optional[Dict[str, Any]]:
        header = request.headers.get("authorization")
        if header and header.startswith("Bearer "):
            parts = header.split(" ")
            if len(parts) == 2:
                return await self.access_token_authorized(parts[1])
        return None

    async def token_from_session(self, request: Request) -> Optional[Dict[str, Any]]:
        if not self.session_adapter:
            raise CrossauthError(ErrorCode.Configuration, 
                "Cannot get session data if sessions not enabled")
        oauth_data = await self.session_adapter.get_session_data(request, self.__session_data_name)
        if oauth_data and oauth_data.get("session_token"):
            if oauth_data.get("expires_at") and oauth_data["expires_at"] < datetime.now().timestamp() * 1000:
                return None
            return await self.access_token_authorized(oauth_data["session_token"])
        return None
