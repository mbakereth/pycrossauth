
from crossauth_backend.auth import Authenticator, AuthenticationOptions, AuthenticationParameters
from typing import List
import re

def default_password_validator(params: AuthenticationParameters) -> List[str]:
    errors : List[str] = []
    if ("password" not in params):
        errors.append("Password not provided")
    else:
        password = params["password"]
        if (len(password) < 8):
            errors.append("Password must be at least 8 characters")
        if (re.match(r'.*[a-z].*', password) == None):
            errors.append("Password must contain at least one lowercase character")
        if (re.match(r'.*[A-Z].*', password) == None):
            errors.append("Password must contain at least one uppercase character")
        if (re.match(r'.*[0-9].*', password) == None):
            errors.append("Password must contain at least one digit")
    
    return errors
