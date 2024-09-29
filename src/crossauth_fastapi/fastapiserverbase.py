from typing import Callable, Awaitable, NamedTuple, Optional, Dict, Any
from abc import ABC, abstractmethod
from fastapi import Request, Response, FastAPI
from crossauth_backend.common.error import CrossauthError
from fastapi.templating import Jinja2Templates

class MaybeErrorResponse(NamedTuple):
    response: Response
    error: bool

type FastApiErrorFn = Callable[[FastApiServerBase,
    Request,
    Response,
    CrossauthError], Awaitable[Response]]

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

