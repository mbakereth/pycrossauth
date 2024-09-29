# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from __future__ import annotations
from enum import Enum, auto
from typing import Any

class ErrorCode(Enum):
    """
        Indicates the type of error reported by :class:`crossauth_backend.CrossauthError`
    """

    UserNotExist = auto()
    """ Thrown when a given username does not exist, eg during login """

    PasswordInvalid = auto()
    """ Thrown when a password does not match, eg during login or signup """

    EmailNotExist = auto()
    """ Thrown when a a password reset is requested and the email does not 
    exist """

    UsernameOrPasswordInvalid = auto()
    """ For endpoints provided by servers in this package, this is returned 
    instead of UserNotExist or PasswordNotMatch, for security reasons """

    InvalidClientId = auto()
    """ This is returned if an OAuth2 client id is invalid """

    ClientExists = auto()
    """ This is returned if attempting to make a client which already exists 
    (client_id or name/userid) """

    InvalidClientSecret = auto()
    """ This is returned if an OAuth2 client secret is invalid """

    InvalidClientIdOrSecret = auto()
    """ Server endpoints in this package will return this instead of 
    InvalidClientId or InvalidClientSecret for security purposes """

    InvalidRedirectUri = auto()
    """ This is returned a request is made with a redirect Uri that is not 
    registered """

    InvalidOAuthFlow = auto()
    """ This is returned a request is made with a an oauth flow name that is 
    not recognized """

    UserNotActive = auto()
    """ Thrown on login attempt with a user account marked inactive """

    EmailNotVerified = auto()
    """ Thrown on login attempt with a user account marked not having had the 
    email address validated """

    TwoFactorIncomplete = auto()
    """ Thrown on login attempt with a user account marked not having 
    completed 2FA setup """

    Unauthorized = auto()
    """ Thrown when a resource expecting user authorization was access and 
    authorization not provided or wrong """

    UnauthorizedClient = auto()
    """ Thrown for the OAuth unauthorized_client error (when the client is 
    unauthorized as opposed to the user) """

    InvalidScope = auto()
    """ Thrown for the OAuth invalid_scope error  """

    InsufficientScope = auto()
    """ Thrown for the OAuth insufficient_scope error  """

    InsufficientPriviledges = auto()
    """ Returned if user is valid but doesn't have permission to access 
    resource """

    Forbidden = auto()
    """ Returned with an HTTP 403 response """

    InvalidKey = auto()
    """ 
    Thrown when a session or API key was provided that is not in the key 
    table.
    For CSRF and sesison key, an InvalidCsrf or InvalidSession will be thrown 
    instead
    """

    InvalidCsrf = auto()
    """ Thrown if the CSRF token is invalid """

    InvalidSession = auto()
    """ Thrown if the session cookie is invalid """

    Expired = auto()
    """ Thrown when a session or API key has expired """

    Connection = auto()
    """ Thrown when there is a connection error, eg to a database """

    InvalidHash = auto()
    """ Thrown when a hash, eg password, is not in the given format """

    UnsupportedAlgorithm = auto()
    """ Thrown when an algorithm is requested but not supported, eg hashing 
    algorithm """

    KeyExists = auto()
    """ Thrown if you try to create a key which already exists in key 
    storage """

    PasswordChangeNeeded = auto()
    """ Thrown if the user needs to reset his or her password """

    PasswordResetNeeded = auto()
    """ Thrown if the user needs to reset his or her password """

    Factor2ResetNeeded = auto()
    """ Thrown if the user needs to reset factor2 before logging in """

    Configuration = auto()
    """ Thrown when something is missing or inconsistent in configuration """

    InvalidEmail = auto()
    """ Thrown if an email address in invalid """

    InvalidPhoneNumber = auto()
    """ Thrown if a phone number in invalid """

    InvalidUsername = auto()
    """ Thrown if an email address in invalid """

    PasswordMatch = auto()
    """ Thrown when two passwords do not match each other (eg signup) """

    InvalidToken = auto()
    """ Thrown when a token (eg TOTP or OTP) is invalid """

    MfaRequired = auto()
    """ Thrown during OAuth password flow if an MFA step is needed """

    PasswordFormat = auto()
    """ Thrown when a password does not match rules (length, 
    uppercase/lowercase/digits) """

    DataFormat = auto()
    """ Thrown when a the data field of key storage is not valid json """

    FetchError = auto()
    """ Thrown if a fetch failed """

    UserExists = auto()
    """ Thrown when attempting to create a user that already exists """

    FormEntry = auto()
    """ Thrown by user-supplied validation functions if a user details form 
    was incorrectly filled out """

    BadRequest = auto()
    """ Thrown when an invalid request is made, eg configure 2FA when 2FA is 
    switched off for user """

    AuthorizationPending = auto()
    """ Thrown in the OAuth device code flow """

    SlowDown = auto()
    """ Thrown in the OAuth device code flow """

    ExpiredToken = auto()
    """ Thrown in the OAuth device code flow """

    ConstraintViolation = auto()
    """ Thrown in database handlers where an insert causes a constraint 
    violation """

    NotImplemented = auto()
    """ Thrown if a method is unimplemented, typically when a feature
    is not yet supported in this language. """

    ValueError = auto()
    """ Thrown a dict field is unexpectedly missing or wrong type """

    UnknownError = auto()
    """ Thrown for an condition not convered above. """

_FRIENDLY_HTTP_STATUS : dict[str, str] = {
    '200': 'OK',
    '201': 'Created',
    '202': 'Accepted',
    '203': 'Non-Authoritative Information',
    '204': 'No Content',
    '205': 'Reset Content',
    '206': 'Partial Content',
    '300': 'Multiple Choices',
    '301': 'Moved Permanently',
    '302': 'Found',
    '303': 'See Other',
    '304': 'Not Modified',
    '305': 'Use Proxy',
    '306': 'Unused',
    '307': 'Temporary Redirect',
    '400': 'Bad Request',
    '401': 'Unauthorized',
    '402': 'Payment Required',
    '403': 'Forbidden',
    '404': 'Not Found',
    '405': 'Method Not Allowed',
    '406': 'Not Acceptable',
    '407': 'Proxy Authentication Required',
    '408': 'Request Timeout',
    '409': 'Conflict',
    '410': 'Gone',
    '411': 'Length Required',
    '412': 'Precondition Required',
    '413': 'Request Entry Too Large',
    '414': 'Request-URI Too Long',
    '415': 'Unsupported Media Type',
    '416': 'Requested Range Not Satisfiable',
    '417': 'Expectation Failed',
    '418': 'I\'m a teapot',
    '429': 'Too Many Requests',
    '500': 'Internal Server Error',
    '501': 'Not Implemented',
    '502': 'Bad Gateway',
    '503': 'Service Unavailable',
    '504': 'Gateway Timeout',
    '505': 'HTTP Version Not Supported',

}

class CrossauthError(Exception):
    """
    Thrown by Crossauth functions whenever it encounters an error.
    """

    def __init__(self, code : ErrorCode, message : str | list[str] | None = None):        
        """
        Construct a CrossauthError object.

        ## Arguments
        - :param ErrorCode code: Return this type of error
        - :param str message: Return this method.  If omitted, a default
          will be returned.  You can also return an array of messages 
        """    

        _message : str | None = None
        _http_status : int = 500

        if (code == ErrorCode.UserNotExist):
            _message = "User does not exist"
            _http_status = 401
        elif (code == ErrorCode.PasswordInvalid):
            _message = "Password doesn't match"
            _http_status = 401
        elif (code == ErrorCode.UsernameOrPasswordInvalid):
            _message = "Username or password incorrect"
            _http_status = 401
        elif (code == ErrorCode.InvalidClientId):
            _message = "Client id is invalid"
            _http_status = 401
        elif (code == ErrorCode.ClientExists):
            _message = "Client ID or name already exists"
            _http_status = 500
        elif (code == ErrorCode.InvalidClientSecret):
            _message = "Client secret is invalid"
            _http_status = 401
        elif (code == ErrorCode.InvalidClientIdOrSecret):
            _message = "Client id or secret is invalid"
            _http_status = 401
        elif (code == ErrorCode.InvalidRedirectUri):
            _message = "Redirect Uri is not registered"
            _http_status = 401
        elif (code == ErrorCode.InvalidOAuthFlow):
            _message = "Invalid OAuth flow type"
            _http_status = 500
        elif (code == ErrorCode.EmailNotExist):
            _message = "No user exists with that email address"
            _http_status = 401
        elif (code == ErrorCode.UserNotActive):
            _message = "Account is not active"
            _http_status = 403
        elif (code == ErrorCode.InvalidUsername):
            _message = "Username is not in an allowed format"
            _http_status = 400
        elif (code == ErrorCode.InvalidEmail):
            _message = "Email is not in an allowed format"
            _http_status = 400
        elif (code == ErrorCode.InvalidPhoneNumber):
            _message = "Phone number is not in an allowed format"
            _http_status = 400
        elif (code == ErrorCode.EmailNotVerified):
            _message = "Email address has not been verified"
            _http_status = 403
        elif (code == ErrorCode.TwoFactorIncomplete):
            _message = "Two-factor setup is not complete"
            _http_status = 403
        elif (code == ErrorCode.Unauthorized):
            _message = "Not authorized"
            _http_status = 401
        elif (code == ErrorCode.UnauthorizedClient):
            _message = "Client not authorized"
            _http_status = 401
        elif (code == ErrorCode.InvalidScope):
            _message = "Invalid scope"
            _http_status = 403
        elif (code == ErrorCode.InsufficientScope):
            _message = "Insufficient scope"
            _http_status = 403
        elif (code == ErrorCode.Connection):
            _message = "Connection failure"
        elif (code == ErrorCode.Expired):
            _message = "Token has expired"
            _http_status = 401
        elif (code == ErrorCode.InvalidHash):
            _message = "Hash is not in a valid format"
        elif (code == ErrorCode.InvalidKey):
            _message = "Key is invalid"
            _http_status = 401
        elif (code == ErrorCode.Forbidden):
            _message = "You do not have permission to access this resource"
            _http_status = 403
        elif (code == ErrorCode.InsufficientPriviledges):
            _message = "You do not have the right privileges to access this "\
                 + "resource"
            _http_status = 401
        elif (code == ErrorCode.InvalidCsrf):
            _message = "CSRF token is invalid"
            _http_status = 401
        elif (code == ErrorCode.InvalidSession):
            _message = "Session cookie is invalid"
            _http_status = 401
        elif (code == ErrorCode.UnsupportedAlgorithm):
            _message = "Algorithm not supported"
        elif (code == ErrorCode.KeyExists):
            _message = "Attempt to create a key that already exists"
        elif (code == ErrorCode.PasswordChangeNeeded):
            _message = "User must change password"
            _http_status = 403
        elif (code == ErrorCode.PasswordResetNeeded):
            _message = "User must reset password"
            _http_status = 403
        elif (code == ErrorCode.Factor2ResetNeeded):
            _message = "User must reset 2FA"
            _http_status = 403
        elif (code == ErrorCode.Configuration):
            _message = "There was an error in the configuration"
        elif (code == ErrorCode.PasswordMatch):
            _message = "Passwords do not match"
            _http_status = 401
        elif (code == ErrorCode.InvalidToken):
            _message = "Token is not valid"
            _http_status = 401
        elif (code == ErrorCode.MfaRequired):
            _message = "MFA is required"
            _http_status = 401
        elif (code == ErrorCode.PasswordFormat):
            _message = "Password format was incorrect"
            _http_status = 401
        elif (code == ErrorCode.UserExists):
            _message = "User already exists"
            _http_status = 400
        elif (code == ErrorCode.BadRequest):
            _message = "The request is invalid"
            _http_status = 400
        elif (code == ErrorCode.DataFormat):
            _message = "Session data has unexpected format"
            _http_status = 500
        elif (code == ErrorCode.FetchError):
            _message = "Couldn't execute a fetch"
            _http_status = 500
        elif (code == ErrorCode.AuthorizationPending):
            _message = "Waiting for authorization"
            _http_status = 200
        elif (code == ErrorCode.SlowDown):
            _message = "Slow polling down by 5 seconds"
            _http_status = 200
        elif (code == ErrorCode.ExpiredToken):
            _message = "Token has expired"
            _http_status = 401
        elif (code == ErrorCode.ConstraintViolation):
            _message = "Database update/insert caused a constraint violation"
            _http_status = 500
        elif (code == ErrorCode.NotImplemented):
            _message = "This method has not been implemented"
            _http_status = 500
        elif (code == ErrorCode.ValueError):
            _message = "Field is missing or wrong type"
            _http_status = 500
        else:
            _message = "Unknown error"
            _http_status = 500
           
        self.messages : list[str] | None = None
        if (message != None and type(message) is str):
            _message = message  
            self.messages = [message]  
        elif (type(message) is list[str]):
            _message = ".".join(message)
            self.messages = message

        # Call the base class constructor with the parameters it needs
        super(CrossauthError, self).__init__(_message)
        self.message : str = _message
        self.http_status : int = _http_status
        self.code : ErrorCode = code

    @staticmethod
    def from_oauth_error(error : str, error_description: str | None = None) -> CrossauthError:
        """
        OAuth defines certain error types.  To convert the error in an OAuth
        response into a CrossauthError object, call this function.
        
        :param str error: as returned by an OAuth call (converted to an 
               :class:`ErrorCode`).
        :param str error_description as returned by an OAuth call (put in the 
               `message`)

        :return a `crossauth_backend.CrossauthError` instance.
        """
        code = ErrorCode.UnknownError
        
        match error:
            case "invalid_request": code = ErrorCode.BadRequest 
            case "unauthorized_client": code = ErrorCode.UnauthorizedClient
            case "access_denied": code = ErrorCode.Unauthorized
            case "unsupported_response_type": code = ErrorCode.BadRequest
            case "invalid_scope": code = ErrorCode.InvalidScope
            case "server_error": code = ErrorCode.UnknownError
            case "temporarily_unavailable": code = ErrorCode.Connection
            case "invalid_token": code = ErrorCode.InvalidToken
            case "expired_token": code = ErrorCode.ExpiredToken
            case "insufficient_scope": code = ErrorCode.InvalidToken
            case "mfa_required": code = ErrorCode.MfaRequired
            case "authorization_pending": code = ErrorCode.AuthorizationPending
            case "slow_down": code = ErrorCode.SlowDown
            case _: code = ErrorCode.UnknownError
        return CrossauthError(code, error_description)

    @property
    def code_name(self):
        """ Return the name of the error code """
        return self.code.name
    
    @property
    def oauthErrorCode(self) -> str:
        """ Return the OAuth name of an error code (eg "server_error")"""
        match (self.code):
            case ErrorCode.BadRequest: return "invalid_request"
            case ErrorCode.UnauthorizedClient: return "unauthorized_client"
            case ErrorCode.Unauthorized: return  "access_denied"
            case ErrorCode.InvalidScope: return "invalid_scope"
            case ErrorCode.Connection: return "temporarily_unavailable"
            case ErrorCode.InvalidToken: return "invalid_token"
            case ErrorCode.MfaRequired: return "mfa_required"
            case ErrorCode.AuthorizationPending: return "authorization_pending"
            case ErrorCode.SlowDown: return "slow_down"
            case ErrorCode.ExpiredToken: return "expired_token"
            case ErrorCode.Expired: return "expired_token"
            case _: return "server_error"
    
    @staticmethod
    def as_crossauth_error(e : Any, default_message : str | None= None) -> CrossauthError:
        """
        If the passed object is a `crossauth_backend.CrossauthError` instance, simply returns
        it.  
        If not and it is an object with `errorCode` in it, creates a 
        CrossauthError from that and `errorMessage`, if present.
        Otherwise creates a `crossauth_backend.CrossauthError` object with :class:`ErrorCode`
        of `Unknown` from it, setting the `message` if possible.
        
        :param Any e: the error to convert.
        :param str|None default_message: message to use if there was none in the original exception.

        :return:  a :class:`crossauth_backend.CrossauthError` instance.
        """
        if isinstance(e, CrossauthError):
            return e
        elif (isinstance(e, Exception)):
            return CrossauthError(ErrorCode.UnknownError, str(e))

        error_message = default_message if default_message is not None else ErrorCode.UnknownError.name
        if 'message' in e:
            error_message = e["message"]
        return CrossauthError(ErrorCode.UnknownError, error_message)

    @staticmethod
    def http_status_name(status : str|int) -> str:
        """
        Returns the friendly name for an HTTP response code.  
        
        If it is not a recognized one, returns the friendly name for 500.
        @param status the HTTP response code, which, while being numeric,
            can be in a string or number.
        @returns the string version of the response code.
        """
        if (type(status) == int):
            status = str(status)
        if (status in _FRIENDLY_HTTP_STATUS):
            return _FRIENDLY_HTTP_STATUS[status]
        return _FRIENDLY_HTTP_STATUS['500']
