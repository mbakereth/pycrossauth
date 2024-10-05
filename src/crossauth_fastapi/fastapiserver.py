# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import Optional, Dict, Any, cast, Callable, TypedDict, Required, Mapping, List
from fastapi import Request, Response, FastAPI
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.common.interfaces import User
from crossauth_backend.storage import KeyStorage
from crossauth_backend.auth import Authenticator
from crossauth_backend.oauth.client import OAuthTokenConsumer
from crossauth_fastapi.fastapisessionadapter import FastApiSessionAdapter
from crossauth_fastapi.fastapisession import FastApiSessionServer, FastApiSessionServerOptions
from crossauth_fastapi.fastapioauthclient import FastApiOAuthClientOptions, FastApiOAuthClient
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_fastapi.fastapiserverbase import FastApiServerBase, FastApiErrorFn, MaybeErrorResponse
from crossauth_fastapi.fastapiresserver import FastApiOAuthResourceServerOptions, FastApiOAuthResourceServer
from crossauth_backend.utils import set_parameter, ParamType

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
                           FastApiOAuthClientOptions, 
                           FastApiOAuthResourceServerOptions, total=False):
    """
    Options for :class:`FastApiServer` and it's component subservers
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
    """
    Parameters that are used to create a session server
    """
    key_storage: Required[KeyStorage]
    options: FastApiSessionServerOptions

class FastApiOAuthClientParams(TypedDict, total=False):
    """
    Parameters that are used to create an OAuth client
    """
    auth_server_base_url: Required[str]
    options: FastApiOAuthClientOptions

class FastApiOAuthResServerParams(TypedDict, total=False):
    """
    Parameters that are used to create an OAuth resource server
    """
    options: FastApiOAuthResourceServerOptions

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

    oauth_clients: List[FastApiOAuthClientParams]
    """ Paramneters to create an OAuth client """

    oauth_resserver: FastApiOAuthResServerParams
    """ Paramneters to create an OAuth resource server """

    options: FastApiServerOptions
    """ Global options which will be passed to all of the above (and
        be overridden by their own options if present)
    """

class FastApiServer(FastApiServerBase):
    """
    This class provides a complete (but without HTML files) auth backend server 
    for FastApi applications

    If you do not pass a FastAPI app to this class, it will create one.  
    Pages are rendered with Jinja2.  

    By default, all views are expected to be in a directory called `templates` 
    relative to the directory the
    server is started in.  This can be overwritten by setting the `templates` option.

    Note that `templates`, and the Jinja2 pages are not used by the API 
    endpoints (those starting in /api).  These just return JSON.

    **Component Servers**

    This class contains a number of servers which don't all have to be
    created, depending on what authentication you want to support.  If
    instantiated, they can work together.

    - `session_server`   Session cookie management server.  Uses sesion ID
                         and CSRF cookies.  See :class:`FastApiSessionServer`.
    - `session_adapter`  If you want an OAuth client but not want to use
                         Crossauth's session server, you can provide your own
                         with this.  Won't work with auth server.
    - `oauth_auth_server` OAuth authorization server.  See 
                         :class:`FastApiAuthorizationServer`
    - `oauth_client`     OAuth client.  See :class:`FastApiOAuthClient`.
    - `oauth_clients`    An array of OAuthClients if you want more than one.  
                         Use either this or `oAuthClient` but not both.  
                         See :class:`FastApiOAuthClient`.
    - `o_uth_res_server`  OAuth resource server.  See 
                         :class:`FastApiOAuthResourceServer`.

    There is also an API key server which is not available as a variable as
    it has no functions other than the hook it registers.
    See :class:`FastApiApiKeyServer`.

    For a list of user-level URLs that can be enabled, and their input and output 
    requirements, see  :class:`FastApiSessionServer`.  FOr a list of
    admin endpoints that can be enabled, see  :class:`FastApiAdminEndpoints`.

    """

    @property
    def app(self): return self._app

    @property
    def session_adapter(self): return self._session_adapter

    @property
    def session_server(self): return self._session_server

    @property
    def oauth_client(self): return self._oauth_client

    @property
    def oauth_clients(self): return self._oauth_clients

    @property
    def oauth_resserver(self): return self._oauth_resserver

    @property 
    def have_session_server(self) -> bool: return self._session_server is not None

    @property 
    def have_session_adapter(self) -> bool: return self._session_adapter is not None

    @property
    def templates(self): return self._templates

    @property
    def error_page(self): return self._error_page

    def get_session_cookie_value(self, request: Request) -> Optional[str]: 
        """
        See :meth:`FastApiSessionServer.get_session_cookie_value`.  

        Only available if there is a session server, not if you just providfe
        a session adapter.  In this case, None is returned.
        """
        if (self._session_server is None): return None
        return self._session_server.get_session_cookie_value(request)
    
    async def create_anonymous_session(self, request: Request, response: Response, data: Optional[Dict[str, Any]] = None) -> str: 
        """
        See :meth:`FastApiSessionServer.create_anonymous_session`.  

        Only available if there is a session server, not if you just providfe
        a session adapter.  In this case, None is returned.
        """
        if self._session_server is None: raise CrossauthError(ErrorCode.Configuration, "Cannot create anonymous session as session server not instantiated")
        return await self._session_server.create_anonymous_session(request, response, data)

    async def update_session_data(self, request: Request, name: str, value: Any):
        """
        See :meth:`FastApiSessionServer.update_session_data`.  

        This is also available if you use a session adapter instead of a session server.
        """
        if self._session_adapter is None: raise CrossauthError(ErrorCode.Configuration, "Cannot create update data as no session server or adapter given")
        return await self._session_adapter.update_session_data(request, name, value)

    async def get_session_data(self, request: Request, name: str) -> Optional[Dict[str, Any]]:
        """
        See :meth:`FastApiSessionServer.get_session_data`.  

        This is also available if you use a session adapter instead of a session server.
        """
        if self._session_adapter is None: raise CrossauthError(ErrorCode.Configuration, "Cannot create update data as no session server or adapter given")
        return await self._session_adapter.get_session_data(request, name)

    async def delete_session_data(self, request: Request, name: str): 
        """
        See :meth:`FastApiSessionServer.delete_session_data`.  

        This is also available if you use a session adapter instead of a session server.
        """
        if self._session_adapter is None: raise CrossauthError(ErrorCode.Configuration, "Cannot create update data as no session server or adapter given")
        return await self._session_adapter.delete_session_data(request, name)

    def __init__(self, params : FastApiServerParams, options : FastApiServerOptions = {}):
        """
        Integrates fastify session, API key and OAuth servers

        :param FastApiServerParams params: entries as follow:
           - `session` if passed, instantiate the session server (see class
             documentation).  The value is an object with a `keyStorage` field
             which must be present and should be the :class:`KeyStorage` instance
             where session IDs are stored.  A field called `options` whose
             value is an :class:`FastifySessionServerOptions` may also be
             provided.
           - `oauth_client` if present, an OAuth client will be created.
             There must be a field called `auth_server_base_url` and is the 
             bsae URL for the authorization server.  When validating access
             tokens, the `iss` claim must match this.
           - `o_auth_clients` if present, an array of OAuth clients will be created.
             There must be a field called `auth_server_base_url` and is the 
             bsae URL for the authorization serve for each.  When validating access
             tokens, the `iss` claim must match this.
             Do not use both this and `oAuthClient`.
           - `oauth_res_server` if present. an OAuth resource server will be
             created.  It has one optional field: `protected_endpoints`.  The
             value is an object whose key is a URL (relative to the base
             URL of the application).  The value is an object that contains
             one optional parameter: `scope`, a string.  The client/user calling
             the endpoint must have authorized this scope to call this endpoint,
             otherwise an access denied error is returned. 
        @param options application-wide options of type
             :class:`FastifyServerOptions`.
     
        """

        if ("app" in options): 
            self._app = options["app"]
        else:
            self._app = FastAPI()
        authenticators : Mapping[str, Authenticator] = {}
        if ("authenticators" in options):
            authenticators = options["authenticators"]

        # Create session server or adapter
        session_server_params = params["session"] if "session" in params else None
        session_adapter = params["session_adapter"] if "session_adapter" in params else None
        client_params = params["oauth_client"] if "oauth_client" in params else None
        clients_params = params["oauth_clients"] if "oauth_clients" in params else None
        if (client_params is not None and clients_params is not None):
            raise CrossauthError(ErrorCode.Configuration, "Cannot provide both oauth_client and oauth_clients")
        resserver_params = params["oauth_resserver"] if "oauth_resserver" in params else None
        if (session_adapter is not None and session_server_params is not None):
            raise CrossauthError(ErrorCode.Configuration, "Cannot have both a session server and session adapter")
        
        # Create OAuth client
        self._oauth_client : FastApiOAuthClient|None = None
        if (client_params is not None):
            oauth_client_options : FastApiOAuthClientOptions = client_params["options"] if "options" in client_params else {}
            client_options : FastApiOAuthClientOptions = {**oauth_client_options, **options}
            self._oauth_client = FastApiOAuthClient(self, client_params["auth_server_base_url"], client_options, session_server_params is not None)

        # Create multiple OAuth clients
        self._oauth_clients : List[FastApiOAuthClient]|None = None
        if (clients_params is not None):
            self._oauth_clients = []
            for cparams in clients_params:
                oauth_clients_options : FastApiOAuthClientOptions = cparams["options"] if "options" in cparams else {}
                clients_options : FastApiOAuthClientOptions = {**oauth_clients_options, **options}
                self._oauth_clients.append(FastApiOAuthClient(self, cparams["auth_server_base_url"], clients_options))

        # Create OAuth resource server
        self._oauth_resserver : FastApiOAuthResourceServer|None = None
        if (resserver_params is not None):
            oauth_resserver_options : FastApiOAuthResourceServerOptions = resserver_params["options"] if "options" in resserver_params else {}
            resserver_options : FastApiOAuthResourceServerOptions = {**oauth_resserver_options, **options}
            self.__audience : str = ""
            set_parameter("audience", ParamType.String, self, options, "OAUTH_AUDIENCE", required=True)
            consumers = OAuthTokenConsumer(self.__audience, options)
            self._oauth_resserver = FastApiOAuthResourceServer(self._app, [consumers], resserver_options)
        
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
        
        app = self._app

        if (self.oauth_resserver is not None and self.session_adapter is not None and self.oauth_resserver.session_adapter is None):
            self.oauth_resserver.session_adapter = self.session_adapter

        # Create middleware to initialize everything to None
        @app.middleware("http") 
        async def pre_handler(request: Request, call_next): # type: ignore
            request.state.user = None
            request.state.csrf_token = None
            request.state.session_id = None
            request.state.auth_type = None
            request.state.id_token_payload = None
            request.state.auth_error = None
            request.state.auth_error_description = None
            request.state.access_token_payload = None
            request.state.scope = None
            return cast(Response, await call_next(request))

        set_parameter("template_dir", ParamType.JsonArray, self, options, "TEMPLATE_DIR")
        self._templates = Jinja2Templates(directory=self.__template_dir)
        set_parameter("error_page", ParamType.String, self, options, "ERROR_PAGE", protected=True)

    async def error_if_csrf_invalid(self, request: Request,
        response: Response,
        error_fn: FastApiErrorFn|None) -> MaybeErrorResponse:
        """
        Calls the passed error function passed if the CSRF
        token in the request is invalid.  
        
        Use this to require a CSRF token in your endpoints.
        
        :param Request request: the FastAPI request
        :param Response response: the FastAPI response object
        :param FastApiErrorFn|None error_fn: the error function to call if the CSRF token is invalid

        :return: if no error, returns an object with `error` set to false and
        `response` set to the passed reply object.  Otherwise returns the reply
        from calling `error_fn`.
        """
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

    :param crossauth_backend.User user: the user to test

    :return true or false
    """
    return "admin" in user and user["admin"] == True

