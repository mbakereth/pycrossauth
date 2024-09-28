# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import List, Dict, Any, Optional, cast, Mapping, TypedDict
from fastapi import FastAPI, Request, Response
from crossauth_backend.common.interfaces import User
from crossauth_backend.storage import UserStorage
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.oauth.resserver import OAuthResourceServer, OAuthResourceServerOptions
from crossauth_backend.oauth.client import OAuthTokenConsumer
from fastapi.responses import JSONResponse
import re

class ProtectedEndpoint(TypedDict, total=False):
    scope: List[str]
    acceptSessionAuthorization: bool

class FastApiOAuthResourceServerOptions(OAuthResourceServerOptions, total=False):
    """
    Options for {@link FastifyOAuthResourceServer}
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

class Authorization(TypedDict, total=False):
    authorized: bool
    token_payload: Mapping[str, Any]
    user: User
    error: str
    error_description: str

class FastApiOAuthResourceServer(OAuthResourceServer):

    def __init__(self, app: FastAPI, token_consumers: List[OAuthTokenConsumer], options: FastApiOAuthResourceServerOptions = {}):
        
        super().__init__(token_consumers, options)
        self.user_storage = options["user_storage"] if "user_storage" in options else None
        self._protected_endpoints: Mapping[str, ProtectedEndpoint] = {}
        self.__error_body : Dict[str, Any] = {}
        set_parameter("error_body", ParamType.Json, self, options, "OAUTH_RESSERVER_ACCESS_DENIED_BODY")
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
            self._protected_endpoints = options['protected_endpoints']

        if 'protected_endpoints' in options:
            @app.middleware("http")
            async def pre_handler(request: Request, call_next): # type: ignore
                url_without_query = request.url.path
                if url_without_query not in self._protected_endpoints:
                    return cast(Response, await call_next(request))

                auth_response = await self.authorized(request)

                statedict = request.state.__dict__["_state"]
                if not ("user" in statedict and statedict["user"] is not None and "auth_type" in statedict and statedict["authtype"] == "cookie" 
                        and self._protected_endpoints[url_without_query].get('acceptSessionAuthorization') != True):
                    if not auth_response:
                        request.state.auth_error = "access_denied"
                        request.state.auth_error_description = "No access token"
                        authenticate_header = self.authenticate_header(request)
                        return Response(content=self.__error_body, status_code=401, headers={"WWW-Authenticate": authenticate_header})

                    if not auth_response['authorized']:
                        authenticate_header = self.authenticate_header(request)
                        return Response(content=self.__error_body, status_code=401, headers={"WWW-Authenticate": authenticate_header})

                if auth_response:
                    request.state.access_token_payload = auth_response.get('token_payload')
                    request.state.user = auth_response.get('user')
                    if 'scope' in auth_response.get('token_payload', {}):
                        if isinstance(auth_response['token_payload']['scope'], list):
                            request.state.scope = [token_scope for token_scope in auth_response['token_payload']['scope'] if isinstance(token_scope, str)]
                        elif isinstance(auth_response['token_payload']['scope'], str):
                            request.scope = auth_response['token_payload']['scope'].split(" ")

                    if 'scope' in self._protected_endpoints[url_without_query]:
                        for scope in self._protected_endpoints[url_without_query].get('scope', []):
                            if not request.scope or (scope not in request.scope and self._protected_endpoints[url_without_query].get('acceptSessionAuthorization') != True):
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
        try:
            header = request.headers.get('Authorization')
            if header and header.startswith("Bearer "):
                parts = header.split(" ")
                if len(parts) == 2:
                    user : User|None = None
                    resp = await self.access_token_authorized(parts[1])
                    if resp:
                        if 'sub' in resp:
                            if self.user_storage:
                                user_resp = await self.user_storage.get_user_by_username(resp['sub'])
                                if user_resp:
                                    user = user_resp["user"]
                                request.state.user = user
                            else:
                                user = {
                                    "id": resp["userid"] if "userid" in resp else resp["sub"],
                                    "username": resp["sub"],
                                    "state": resp["state"] if "state" in resp else "active",
                                    "factor1": resp["factor1"] if "factor1" in resp else ""
                                }
                                request.state.user = user
                        return {'authorized': True, 'token_payload': resp, 'user': user}
                    return {'authorized': False}

        except Exception as e:
            return {'authorized': False, 'error': "server_error", 'error_description': str(e)}
        return None
