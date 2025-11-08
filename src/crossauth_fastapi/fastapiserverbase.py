from typing import Callable, Awaitable, NamedTuple, Optional, Dict, Any
from abc import ABC, abstractmethod
from fastapi import Request, Response, FastAPI
from crossauth_backend.common.error import CrossauthError
from fastapi.templating import Jinja2Templates
from crossauth_backend.common.interfaces import User
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j

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

class MaybeErrorResponse(NamedTuple):
    response: Response
    error: bool

type FastApiErrorFn = Callable[[FastApiServerBase,
    Request,
    Response,
    CrossauthError], Awaitable[Response]]

def default_is_admin_fn(user : User) -> bool:
    """
    The function to determine if a user has admin rights can be set
    externally.  This is the default function if none other is set.
    It returns true iff the `admin` field in the passed user is set to true.

    :param crossauth_backend.User user: the user to test

    :return true or false
    """
    return "admin" in user and user["admin"] == True

class FastApiServerBase(ABC):
    """
    This is an abstract base class for the :class:`FastApiServer` which only
    exists to avoid cyclic references.  You should not have to use it
    """
    
    @abstractmethod
    async def error_if_csrf_invalid(self, request: Request,
        response: Response,
        error_fn: FastApiErrorFn|None) -> MaybeErrorResponse:
        pass
    
    @property 
    @abstractmethod
    def app(self) -> FastAPI: pass

    @property 
    @abstractmethod
    def have_session_server(self) -> bool: pass

    @property 
    @abstractmethod
    def have_session_adapter(self) -> bool: pass

    @abstractmethod
    def get_session_cookie_value(self, request: Request) -> Optional[str]: pass

    @abstractmethod
    async def create_anonymous_session(self, request: Request, response: Response, data: Optional[Dict[str, Any]] = None) -> str: pass

    @abstractmethod
    async def update_session_data(self, request: Request, name: str, value: Any): pass

    @abstractmethod
    async def get_session_data(self, request: Request, name: str) -> Optional[Dict[str, Any]]: pass

    @abstractmethod
    async def delete_session_data(self, request: Request, name: str): pass

    @property 
    @abstractmethod
    def templates(self) -> Jinja2Templates: pass

    @property 
    @abstractmethod
    def error_page(self) -> str: pass

    is_admin: Callable[[User], bool] = default_is_admin_fn


    @staticmethod
    def send_page_error(templates: Jinja2Templates,
                        request: Request,
                        reply: Response,
                       status: int,
                       error_page: Optional[str] = None,
                       error: Optional[str] = None,
                       e: Optional[Any] = None) -> Response:
        """
        Sends a reply by rendering the `errorPage` if present, or a standard
        error page if it isn't.
        
        The renderer configured for the reply object is called (Nunjucks
        by default) with the following data parameters:
        - `errorCode` See ErrorCode.
        - `errorCodeName` the text version of `errorCode`.
        - `msg` the error message
        - `httpStatus` the HTTP status code.
        
        :param reply: the Fastify reply object
        :param status: the HTTP status code to return
        :param error_page: the error page to render.
        :param error: an error message string. Ignored if `e` is defined.
        :param e: optionally, an exception. This will be logged and the message
               will be sent to the error page.
               
        Returns:
            the reply from rendering the error page.
        """
        if not error or not e:
            CrossauthLogger.logger().warn(j({
                "msg": error,
                "errorCode": ErrorCode.UnknownError,
                "errorCodeName": ErrorCode(ErrorCode.UnknownError).name,
                "httpStatus": status
            }))
            if error_page:

                return templates.TemplateResponse(
            
                    request,
                    error_page, 
                    {
                        "status": status,
                        "errorCodeName": ErrorCode(ErrorCode.UnknownError).name
                    })

            else:
                return Response(ERROR_401 if status == 401 else ERROR_500, status)
        
        try:
            code = 0
            code_name = "UnknownError"
            if hasattr(e, "isCrossAuthError"):
                ce = CrossauthError.as_crossauth_error(e)
                code = ce.code
                code_name = ce.code_name
                if not error:
                    error = str(e)
            
            if not error:
                if status == 401:
                    error = "You are not authorized to access this page"
                    code = ErrorCode.Unauthorized
                    code_name = ErrorCode(code).name
                elif status == 403:
                    error = "You do not have permission to access this page"
                    code = ErrorCode.Forbidden
                    code_name = ErrorCode(code).name
                else:
                    error = "An unknwon error has occurred"
            
            CrossauthLogger.logger().warn(j({
                "msg": error,
                "errorCode": code,
                "errorCodeName": code_name,
                "httpStatus": status
            }))
            
            if error_page:
                return templates.TemplateResponse(
            
                    request,
                    error_page, 
                    {
                        "status": status,
                        "errorMessage": error,
                        "errorCode": code,
                        "errorCodeName": code_name
                    })

            else:
                return Response(ERROR_401 if status == 401 else ERROR_500, status)
                
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return Response(ERROR_401 if status == 401 else ERROR_500, status)

