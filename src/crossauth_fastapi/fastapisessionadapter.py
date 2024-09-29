# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from fastapi import Request
from crossauth_backend.storage import KeyDataEntry
from crossauth_backend.common.interfaces import User

class FastApiSessionAdapter(ABC):
    """
    This class provides a minimal API that Crossauth needs from a cookie-based
    session management.  
    
    Its own :class:`FastApiSessionServer` implements this.

    If you want to your your favourite frameworks' own session management,
    implement this adapter to use it and pass it to :class:`FastApiServer` as
    `session_adapter` instead of `session_manager`.

    """
    @abstractmethod
    def csrf_protection_enabled(self) -> bool:
        """
        Returns whether CSRF protection has been enabled,.  Some backends
        provide this automatically in which case you can return False in 
        your adapter.  If your backend does not do this automatically, you
        should always implement it and return True
        """
        pass
    
    @abstractmethod
    def get_csrf_token(self, request: Request) -> Optional[str]:
        """
        Return the CSRF token if one has been set or None
        """
        pass

    @abstractmethod
    def get_user(self, request: Request) -> Optional[User]:
        """
        Return the logged in user if there is one or None
        """
        pass

    @abstractmethod
    async def update_session_data(self, request: Request, name: str, value: Any) -> None:
        """
        Updates a field in the session data in the key storage record,
        
        The `data` field is assumed to be JSON.  Just the field with the given
        name is updated and the rest is unchanged.
        :param request: the FastAPI request
        :param name: the field within `data` to update
        :param value: the value to set it to

        """
        pass

    @abstractmethod
    async def update_many_session_data(self, request: Request, data_array: List[KeyDataEntry]):
        """
        Same as `update_data` but updates many within same transaction
        
        The `data` field is assumed to be JSON.  Just the field with the given
        name is updated and the rest is unchanged.
        :param request: the FastAPI request
        :param data_array: data to update

        """
        pass

    @abstractmethod
    async def delete_session_data(self, request: Request, name: str) -> None:
        """
        Deletes a field from the session data in the key storage record,
        
        The `data` field is assumed to be JSON.  Just the field with the given
        name is updated and the rest is unchanged.
        :param request: the FastAPI request
        :param name: the field within `data` to update
        
        """
        pass

    @abstractmethod
    async def get_session_data(self, request: Request, name: str) -> Optional[Dict[str, Any]]:
        """
        Return data stored in the session with key `name` or None if not present
        :param request: the FastAPI request
        :param name: name of the data to fetch

        :return: a dictionary of the data, or None
        """
        pass

