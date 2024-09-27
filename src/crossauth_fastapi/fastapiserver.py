# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import Optional, Dict, Any, cast, Callable, TypedDict, Required, Mapping
from fastapi import Request, Response, FastAPI
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.common.interfaces import User
from crossauth_backend.storage import KeyStorage
from crossauth_backend.auth import Authenticator
from crossauth_fastapi.fastapisessionadapter import FastApiSessionAdapter
from crossauth_fastapi.fastapisession import FastApiSessionServer, FastApiSessionServerOptions
from crossauth_fastapi.fastapioauthclient import FastApiOAuthClientOptions, FastApiOAuthClient
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_fastapi.fastapiserverbase import FastApiServerBase, FastApiErrorFn, MaybeErrorResponse


"""
Type for the function that is called to pass an error back to the user

The function is passed this instance, the request that generated the
error, the response object for sending the respons to and the
exception that was raised.
"""

ERROR_400 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>400 Bad Request</h1>
<p>The server was unable to handle your request.</p>
</body></html>
"""

ERROR_401 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>401 Unauthorized</title>
</head><body>
<h1>401 Unauthorized</h1>
<p>You are not authorized to access this URL.</p>
</body></html>
"""

ERROR_403= """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>403 Forbidden</title>
</head><body>
<h1>403 Forbidden</h1>
<p>You are not authorized to make this request.</p>
</body></html>
"""

ERROR_500 = """<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>500 Server Error</title>
</head><body>
<h1>500 Error</h1>
<p>Sorry, an unknown error has occured</p>
</body></html>
"""

DEFAULT_ERROR = {
    400: ERROR_400,
    401: ERROR_401,
    500: ERROR_500
}

class FastApiServerOptions(FastApiSessionServerOptions,
                           FastApiOAuthClientOptions, total=False):
    """
    Options for :class:`FastApiServer`.
    """

    app : FastAPI
    """
    You can pass your own FastAPI instance or omit this, in which case Crossauth will create one
    """

    is_admin_fn : Callable[[User], bool]
    """
    Function to return whether given user is an admin.  If not set, 
    the `admin` field of the user is used, which is assumed to be
    bool
    """

    template_dir : str
    """ If this is passed, it is registered as a Jinja2 view folder """

    authenticators : Mapping[str, Authenticator]

class FastApiSessionServerParams(TypedDict, total=False):
    key_storage: Required[KeyStorage]
    options: FastApiSessionServerOptions

class FastApiOAuthClientParams(TypedDict, total=False):
    auth_server_base_url: Required[str]
    options: FastApiOAuthClientOptions

class FastApiServerParams(TypedDict, total=False):
    """ Configuration for the FastAPI server - which services to instantiate """

    session : FastApiSessionServerParams
    """ Parameters to create a session server """

    session_adapter: FastApiSessionAdapter
    """ If you are using a different session, implement 
        :class:`FastApiSessionAdapter` to use it, and pass it here
    """
    oauth_client: FastApiOAuthClientParams
    """ Paramneters to create an OAuth client """

    options: FastApiServerOptions
    """ Global options which will be passed to all of the above (and
        be overridden by their own options if present)
    """

class FastApiServer(FastApiServerBase):
    @property
    def app(self): return self._app

    @property
    def session_adapter(self): return self._session_adapter

    @property
    def session_server(self): return self._session_server

    @property
    def oauth_client(self): return self._oauth_client

    @property 
    def have_session_server(self) -> bool: return self._session_server is not None

    @property 
    def have_session_adapter(self) -> bool: return self._session_adapter is not None

    @property
    def templates(self): return self._templates

    @property
    def error_page(self): return self._error_page

    def get_session_cookie_value(self, request: Request) -> Optional[str]: 
        if (self._session_server is None): return None
        return self._session_server.get_session_cookie_value(request)
    
    async def create_anonymous_session(self, request: Request, response: Response, data: Optional[Dict[str, Any]] = None) -> str: 
        if self._session_server is None: raise CrossauthError(ErrorCode.Configuration, "Cannot create anonymous session as session server not instantiated")
        return await self._session_server.create_anonymous_session(request, response, data)

    async def update_session_data(self, request: Request, name: str, value: Any):
        if self._session_adapter is None: raise CrossauthError(ErrorCode.Configuration, "Cannot create update data as no session server or adapter given")
        return await self._session_adapter.update_session_data(request, name, value)

    async def get_session_data(self, request: Request, name: str) -> Optional[Dict[str, Any]]:
        if self._session_adapter is None: raise CrossauthError(ErrorCode.Configuration, "Cannot create update data as no session server or adapter given")
        return await self._session_adapter.get_session_data(request, name)

    async def delete_session_data(self, request: Request, name: str): 
        if self._session_adapter is None: raise CrossauthError(ErrorCode.Configuration, "Cannot create update data as no session server or adapter given")
        return await self._session_adapter.delete_session_data(request, name)

    def __init__(self, params : FastApiServerParams, options : FastApiServerOptions = {}):

        if ("app" in options): 
            self._app = options["app"]
        else:
            self._app = FastAPI()
        authenticators : Mapping[str, Authenticator] = {}
        if ("authenticators" in options):
            authenticators = options["authenticators"]

        session_server_params = params["session"] if "session" in params else None
        session_adapter = params["session_adapter"] if "session_adapter" in params else None
        client_params = params["oauth_client"] if "oauth_client" in params else None
        if (session_adapter is not None and session_server_params is not None):
            raise CrossauthError(ErrorCode.Configuration, "Cannot have both a session server and session adapter")
        
        self._session_adapter : FastApiSessionAdapter|None = None
        self._session_server : FastApiSessionServer|None = None
        if (session_adapter is not None):
            self._session_adapter = session_adapter
        elif (session_server_params is not None):
            session_server_options : FastApiSessionServerOptions = session_server_params["options"] if "options" in session_server_params else {}
            session_options : FastApiSessionServerOptions = {**session_server_options, **options}
            self._session_server = FastApiSessionServer(self._app, 
                session_server_params["key_storage"], 
                authenticators, 
                session_options)
            self._session_adapter  = self._session_server
        self.__template_dir = "templates"
        self._error_page = "error.jinja2"
        
        if (client_params is not None):
            oauth_client_options : FastApiOAuthClientOptions = client_params["options"] if "options" in client_params else {}
            client_options : FastApiOAuthClientOptions = {**oauth_client_options, **options}
            self._oauth_client = FastApiOAuthClient(self, client_params["auth_server_base_url"], client_options)
        app = self._app

        @app.middleware("http") 
        async def pre_handler(request: Request, call_next): # type: ignore
            request.state.user = None
            request.state.csrf_token = None
            request.state.session_id = None
            return cast(Response, await call_next(request))

        set_parameter("template_dir", ParamType.JsonArray, self, options, "TEMPLATE_DIR")
        self._templates = Jinja2Templates(directory=self.__template_dir)
        set_parameter("error_page", ParamType.String, self, options, "ERROR_PAGE", protected=True)

    """
    Calls the passed error function passed if the CSRF
    token in the request is invalid.  
    
    Use this to require a CSRF token in your endpoints.
    
    @param request the Fastify request
    @param reply the Fastify reply object
    @param errorFn the error function to call if the CSRF token is invalid
    @returns if no error, returns an object with `error` set to false and
    `reply` set to the passed reply object.  Otherwise returns the reply
    from calling `errorFn`.
    """
    async def error_if_csrf_invalid(self, request: Request,
        response: Response,
        error_fn: FastApiErrorFn|None) -> MaybeErrorResponse:
        try:
            if (request.state.csrf_token is None): raise CrossauthError(ErrorCode.InvalidCsrf)
            return MaybeErrorResponse(response, False)
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": e}))
            CrossauthLogger.logger().warn(j({
                "msg": "Attempt to access url without csrf token",
                "url": str(request.url)
            }))
            try:
                if (error_fn):
                    ce = CrossauthError.as_crossauth_error(e)
                    response = await error_fn(self, request, response, ce)
                    return MaybeErrorResponse(response, True)
                elif (self._session_server is not None and self._session_server.error_page):

                    ce = CrossauthError(ErrorCode.InvalidCsrf, "CSRF Token not provided")
                    response = self._templates.TemplateResponse(
                        request=request,
                        name=self._error_page,
                        context = {
                            "status": ce.http_status,
                            "error_message": ce.message,
                            "error_messages": ce.messages,
                            "error_code": ce.code.value,
                            "error_code_name": ce.code_name
                        },
                    headers=response.headers,
                    status_code=ce.http_status)

                    return MaybeErrorResponse(response, True)
            except Exception as e2:
                CrossauthLogger.logger().error(j({"err": e2}));
                response = HTMLResponse(ERROR_401, status_code=401)
                return MaybeErrorResponse(response, True)                
            
            response = HTMLResponse(ERROR_401, status_code=401)
            return MaybeErrorResponse(response, True)                
        
    

def default_is_admin_fn(user : User) -> bool:
    """
    The function to determine if a user has admin rights can be set
    externally.  This is the default function if none other is set.
    It returns true iff the `admin` field in the passed user is set to true.

    :param User user: the user to test
    :return true or false
    """
    return "admin" in user and user["admin"] == True

