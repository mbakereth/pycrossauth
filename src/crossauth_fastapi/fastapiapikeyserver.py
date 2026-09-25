# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import List, Dict, Any, Optional, cast, Mapping, TypedDict
from fastapi import FastAPI, Request, Response
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.common.interfaces import User
from crossauth_backend.storage import UserStorage, KeyStorage
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.apikey import ApiKeyManager, ApiKeyManagerOptions
from fastapi.responses import JSONResponse
from crossauth_backend.common.interfaces import ApiKey
from nulltype import NullType

class ProtectedEndpoint(TypedDict, total=False):
    scope: List[str]
    accept_session_authorization: bool
    suburls: bool

class FastApiApiKeyServerOptions(ApiKeyManagerOptions, total=False):
    """
    Options for FastApiApiKeyServer
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
   

class Authorization(TypedDict, total=False):
    authorized: bool
    token_payload: Mapping[str, Any]
    user: User
    error: str
    error_description: str

class FastApiApiKeyServer(ApiKeyManager):
    """
    ApiKeyServer
    
    You can subclass this, simply instantiate it, or create it through
    :class:`FastApiServer`.  
    
    """

    def __init__(self, app: FastAPI, key_storage: KeyStorage, user_storage: UserStorage, options: FastApiApiKeyServerOptions = {}):
        """
        Constructor

        :param FastAPI app: the FastAPI app
        :param token_consumers: A list of token consumers, one per issuer and audience
        :param FastApiOAuthResourceServerOptions options: See :class:`FastApiOAuthResourceServerOptions`
        
        """
        super().__init__(key_storage, options)
        self.user_storage = user_storage;
        self.session_adapter = options["session_adapter"] if "session_adapter" in options else None

        self._protected_endpoints: Mapping[str, ProtectedEndpoint] = {}
        self._protected_endpoint_prefixes: List[str] = []
        self.__error_body : Dict[str, Any] = {}
        set_parameter("error_body", ParamType.Json, self, options, "OAUTH_RESSERVER_ACCESS_DENIED_BODY")

        self._access_token_is_jwt = options["access_token_is_jwt"] if "access_token_is_jwt" in options else True
        if 'protected_endpoints' in options:
            for key, _value in options['protected_endpoints'].items():
                if not key.startswith("/"):
                    raise ValueError("protected endpoints must be absolute paths without the protocol and hostname")
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
                        authenticate_header = self.authenticate_header(request)
                        return JSONResponse(content=self.__error_body, status_code=401, headers={"WWW-Authenticate": authenticate_header})

                    if not auth_response['authorized']:
                        authenticate_header = self.authenticate_header(request)
                        return JSONResponse(content=self.__error_body, status_code=401, headers={"WWW-Authenticate": authenticate_header})

                if auth_response:
                    request.state.access_token_payload = auth_response.get('token_payload')
                    request.state.user = auth_response.get('user')

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

                    request.state.auth_type = "apikey"
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
            header = "ApiKey"
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

            key : ApiKey | None = None

            resp = await self.token_from_header(request)
            if resp is not None:
                key = resp

            user : User|None = None
            if key is not None:
                if ("userid" in key and type(key["userid"]) != NullType):
                    userid : int|str = key["userid"] if type(key["userid"]) == int else str(key["userid"])
                    user_resp = await self.user_storage.get_user_by_id(userid)
                    if user_resp:
                        user = user_resp["user"]
                request.state.user = user
                CrossauthLogger.logger().debug(j({"msg": "Got user from sub claim and user storage"}))
                CrossauthLogger.logger().debug(j({"msg": "Got user from sub claim"}))
                request.state.user = user
                return {'authorized': True, 'api_key_name': key["name"], 'user': user}
            CrossauthLogger.logger().warn(j({"msg": "Did not receive a valid token"}))
            return {'authorized': False}

        except Exception as e:
            return {'authorized': False, 'error': "server_error", 'error_description': str(e)}
        return None

    async def token_from_header(self, request: Request) -> Optional[ApiKey]:
        header = request.headers.get("authorization")
        if (header is None):
            return None
        return await self.validate_token(header)
        return None
