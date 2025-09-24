from typing import TypedDict

from typing import TypedDict, Optional
from pydantic import BaseModel

class CsrfBodyType(BaseModel):
    csrfToken: str

class CsrfBaseBodyType(BaseModel):
    csrfToken: Optional[str] = None

##############################################################################
# REQUEST INTERFACES

class LoginBodyType(CsrfBaseBodyType):
    """
    Body parameters for the /login URL
    """
    username: str
    password: Optional[str] = None
    persist: Optional[bool]
    next: Optional[str]

class LoginFactor2BodyType(CsrfBaseBodyType):
    """
    Body parameters for the /loginfactor2 URL
    """
    persist: Optional[bool]
    next: Optional[str]
    otp: Optional[str]
    token: Optional[str]

class SignupBodyType(LoginBodyType):
    """
    Fastidy body type for users signing up
    """
    repeatPassword: Optional[str]
    email: Optional[str]
    factor2: Optional[str]
    # For extensible user object fields

class LoginQueryType(TypedDict):
    """
    Fastidy query type for users logging in (just a parameter for next page to load)
    """
    next: Optional[str]

class Factor2QueryType(TypedDict):
    """
    Fastidy query type for entering second factor (just an optional error parameter)
    """
    error: Optional[str]

class AuthenticatorDetails(TypedDict):
    """
    For passing authenticator details to page templates.
    """
    name: str
    friendlyName: str
    hasSecrets: bool
