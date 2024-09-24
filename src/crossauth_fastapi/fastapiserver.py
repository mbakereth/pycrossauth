# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import Callable
from fastapi import Request, Response
from crossauth_backend.common.error import CrossauthError
from crossauth_backend.common.interfaces import User
from crossauth_fastapi.fastapisessionadapter import FastApiSessionAdapter
from crossauth_fastapi.fastapisession import FastApiSessionServer

class FastApiServer:
    @property
    def session_adapter(self): return self._session_adapter

    @property
    def session_server(self): return self._session_server

    def __init__(self, session_server : FastApiSessionServer | None = None):
        self._session_adapter : FastApiSessionAdapter|None = session_server
        self._session_server : FastApiSessionServer|None = session_server

"""
Type for the function that is called to pass an error back to the user

The function is passed this instance, the request that generated the
error, the response object for sending the respons to and the
exception that was raised.
"""
type FastApiErrorFn = Callable[[FastApiServer,
    Request,
    Response,
    CrossauthError], Response]

def default_is_admin_fn(user : User) -> bool:
    """
    The function to determine if a user has admin rights can be set
    externally.  This is the default function if none other is set.
    It returns true iff the `admin` field in the passed user is set to true.

    :param User user: the user to test
    :return true or false
    """
    return "admin" in user and user["admin"] == True

