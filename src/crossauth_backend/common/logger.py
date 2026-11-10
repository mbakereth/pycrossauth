# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from .. import CrossauthError, ErrorCode

import json
import os
from typing import Any, Dict, Mapping, TypedDict
from enum import Enum
import traceback

class CrossauthLoggerInterface:
    """
    You can implement your own logger.  Crossauth only needs these functions
    and variables to be present.
    """

    def error(self, output: Any) -> None:
        """ Report a message at error level """
        pass

    def warn(self, output: Any) -> None:
        """ Report a message at warning level """
        pass

    def info(self, output: Any) -> None:
        """ Report a message at info level """
        pass

    def debug(self, output: Any) -> None:
        """ Report a message at debug level """
        pass

    def set_level(self, level: int) -> None:
        """ Set logging level """
        pass

    NoLogging = 0
    Error = 1
    Warn = 2
    Info = 3
    Debug = 4

    level: int = NoLogging

class CrossauthLogger(CrossauthLoggerInterface):
    """ 
    A very simple logging class with no dependencies.
    
    Logs to console. 
    
    The logging API is designed so that you can replace this with other common loggers, eg Pino.
    To change it, use the global :func:`CrossauthLogger.set_logger` function.  This has a parameter to tell 
    Crossauth whether your logger accepts JSON input or not.
    
    When writing logs, we use the helper function :func:`j` to send JSON to the logger if it is
    supprted, and a stringified JSON otherwise.
    
    **Crossauth logs**
    
    All Crossauth log messages are JSON (or stringified JSON, depending on whether the logger supports
    JSON input - this one does).  The following fields may be present depending on context
    (`msg` is always present):
    
    - `msg` : main contents of the log
    - `err` : an error object.  If a subclass of Error, it wil contain at least `message` and
                a stack trace in `stack`.  If the error is of type :class:`crossauth_backend.CrossauthError` 
                it also will also contain `code` and `http_status`.
    - `hashedSessionCookie` : for security reasons, session cookies are not included in logs.
                                However, so that errors can be correlated with each other, a hash
                                of it is included in errors originating from a session.
    - `hashedCsrfCookie`    : for security reasons, csrf cookies are not included in logs.
                                However, so that errors can be correlated with each other, a hash
                                of it is included in errors originating from a session.
    - `user` : username
    - `emailMessageId` : internal id of any email that is sent
    - `email` : email address
    - `userid` : sometimes provided in addition to username, or when username not available
    - `hahedApiKey` : a hash of an API key.  The unhashed version is not logged for security,
                        but a hash of it is logged for correlation purposes.
    - `header`      : an HTTP header that relates to an error (eg `Authorization`), only if
                        it is non-secret or invalid
    - `accessTokenHash` : hash of the JTI of an access token.  For security reasons, the 
                            unhashed version is not logged.
    - `method`: request method (GET, PUT etc)
    - `url` : relevant URL
    - `ip`  : relevant IP address           
    - `scope` : OAuth scope
    - `error_code` : Crossauth error code
    - `error_code_name` : String version of Crossauth error code
    - `http_status` : HTTP status that will be returned
    - `port` port service is running on (only for starting a service)
    - `prefix` prefix for endpoints (only when starting a service)
    - `authorized` whether or not a valid OAuth access token was provided
    """

    level_name = ["NONE", "ERROR", "WARN", "INFO", "DEBUG"]
    ecs_level_name = ["none", "error", "warn", "info", "debug"]
    extra_fields : Dict[str, Any] = {}
    log_as_ecs = False

    _instance : CrossauthLoggerInterface

    @staticmethod
    def logger() -> CrossauthLoggerInterface:
        """ Returns the static logger instance"""
        global _crossauth_logger, _crossauth_logger_accepts_json
        return _crossauth_logger

    def __init__(self, level: int|None = None):
        """
        Constructor

        :param int|None level the level to report to

        """
        if level is not None:
            self.level = level
        elif "CROSSAUTH_LOG_LEVEL" in os.environ:
            level_name = os.environ["CROSSAUTH_LOG_LEVEL"].upper()
            if level_name in CrossauthLogger.level_name:
                self.level = CrossauthLogger.level_name.index(level_name)
            else:
                self.level = CrossauthLogger.Error
        else:
            self.level = CrossauthLogger.Error
        CrossauthLogger.rossauth_logger_accepts_json = True

    def set_level(self, level: int) -> None:
        """ Set the level to report down to """
        self.level = level

    def set_extra_fields(self, fields: Dict[str, Any]) -> None:
        CrossauthLogger.extra_fields = fields

    def set_log_as_ecs(self, val: bool) -> None:
        CrossauthLogger.log_as_ecs = val

    def _log(self, level: int, output: Any) -> None:
        if level <= self.level:
            if isinstance(output, str):
                print(f"Crossauth {CrossauthLogger.level_name[level]} {self._current_time_iso()} {output}")
            else:
                if (CrossauthLogger.log_as_ecs):
                    output = to_ecs(level, {**output, "time": self._current_time_iso()})
                else:
                    output = {"level": CrossauthLogger.level_name[level], "time": self._current_time_iso(), **output}
                print(json.dumps(output))

    def error(self, output: Any) -> None:
        """ Log an error """
        self._log(CrossauthLogger.Error, output)

    def warn(self, output: Any) -> None:
        """ Log a warning """
        self._log(CrossauthLogger.Warn, output)

    def info(self, output: Any) -> None:
        """ Log an info message """
        self._log(CrossauthLogger.Info, output)

    def debug(self, output: Any) -> None:
        """ Log a debug message """
        self._log(CrossauthLogger.Debug, output)

    @staticmethod
    def set_logger(logger: CrossauthLoggerInterface, accepts_json: bool) -> None:
        """ Set the static logger instance """
        global _crossauth_logger, _crossauth_logger_accepts_json
        _crossauth_logger = logger
        _crossauth_logger_accepts_json = accepts_json

    @staticmethod
    def _current_time_iso() -> str:
        from datetime import datetime
        return datetime.now().isoformat()

def to_ecs(level: int, input: Mapping[str, Any]) -> Dict[str, Any]:
    output = {**input}

    output["log.level"] = CrossauthLogger.ecs_level_name[level]; del output["level"]
    output["@timestamp"] = input["time"]; del output["time"]
    output["log.logger"] = "CrossauthLogger"
    if (output["method"]):
        output["http.request.method"] = input["method"]
        del output["method"]
    
    if (output["response_code"]):
        output["http.response.status_code"] = output["response_code"];
        del output["responseCode"]
    
    if (output["ip"]):
        output["client.address"] = output["ip"]
        output["client.ip"] = output["ip"]
        del output["ip"]
    
        if (input["url"]):
            output["url.original"] = input["url"]
        del output["url"]
    

    if (output["email"]):
        output["user.email"] = output["email"]
        del output["email"]
    
    if (output["user"]):
        output["user.name"] = output["user"]
        del output["user"]
    
    if (output["userid"]):
        output["user.id"] = output["userid"]
        del output["userid"]
    
    if (output["target_user"]):
        output["crossauth.target.user.name"] = output["target_user"]
        del output["target_user"]
    
    if (output["target_userid"]):
        output["crossauth.target.user.id"] = output["target_userid"]
        del output["target_userid"]
    
    if (output["action_code_name"]):
        output["crossauth.actioncode"] = output["action_code_name"]
        del output["action_code_name"]
        if (output["action_code"]):
            del output["action_code"]
    
    if (output["error_message"]):
        output["error.message"] = output["error_message"]
        del output["error_message"]
        if (output["error_messages"]):
            del output["error_messages"]
    elif (output["message"] and output["errorCode"]):
        output["error.message"] = output["message"]
        del output["message"]
        if (output["messages"]):
            del output["messages"]
    
    if (output["error_code_name"]):
        output["error.code"] = output["error_code_name"]
        del output["error_code_name"]
        if (output["errorCode"]):
            del  output["errorCode"]
    
    if (output["stack"]):
        output["error.stack"] = output["stack"]
        del output["stack"]

    return output

def j(arg: Mapping[str, Any] | str) -> Dict[str, Any] | str:
    """ Helper function that returns JSON if the error log supports it,
        otherwise a string """
    global _crossauth_logger_accepts_json
    argcopy : Mapping[str,Any] = {}
    if (type(arg) == str):
        argcopy = {"message": arg}
    elif (isinstance(arg, Mapping)):
        argcopy = {**arg}
    if isinstance(arg, dict) and "cerr" in arg and isinstance(arg["cerr"], CrossauthError):
        argcopy["error_code"] = arg["cerr"].code.value
        argcopy["error_code_name"] = arg["cerr"].code_name
        argcopy["http_status"] = arg["cerr"].http_status
        if "message" not in argcopy:
            argcopy["message"] = argcopy["cerr"].message

    if isinstance(arg, dict) and "err" in arg and isinstance(arg["err"], CrossauthError):
        argcopy["error_code"] = arg["err"].code.value
        argcopy["error_code_name"] = arg["err"].code_name
        argcopy["http_status"] = arg["err"].http_status
        if "message" not in argcopy:
            if ("cerr" in argcopy):
                argcopy["message"] = argcopy["cerr"].message
            elif ("err" in argcopy):
                argcopy["message"] = argcopy["err"].message
        argcopy["stack"] = str(traceback.format_exception(arg["err"]))

    elif isinstance(arg, dict) and "err" in arg and isinstance(arg["err"], Exception):
        argcopy["stack"] = str(traceback.format_exception(arg["err"]))
        if "message" not in argcopy:
            argcopy["message"]  = str(str(arg["err"]))

    if ("err" in argcopy): del argcopy["err"]
    if ("cerr" in argcopy): del argcopy["cerr"]

    if (type(arg) == str):
        return arg
    if (_crossauth_logger_accepts_json):
        return argcopy
    return json.dumps(argcopy)


_crossauth_logger = CrossauthLogger(None)
_crossauth_logger_accepts_json = True

class LoggedActionCode(Enum):
    """
        Used when logging user-instigated actions
    """

    Login = 0
    """ A user attempted to log in """

    Logout = 1
    """ A user attempted to log out """

    LoginWithoutEmailVerification = 2
    """ User attempted to log in when they have not verified their email """

    PasswordChangeRedirect = 3
    """ User got redirected to mandatory password change"""

    LoginWhenPasswordResetNeeded = 4
    """ User logged in when password reset is needed """

    LoginWhenFactor2ResetNeeded = 5
    """ User logged in when factor2 reset is needed """

    LoginWhenPasswordAndFactor2ResetNeeded = 6
    """ User logged in when password and factor2 reset is needed """

    EmailVerificationTokenSent = 7
    """ Email verification message sent """

    EmailVerificationTokenComplete = 8
    """ Email verified """

    InvalidCookieOrToken = 9
    """ Invalid session or CSRF cookie """

    UnauthorizedPageOrAPICall = 10
    """ User visited page they do not have permission to """

    OAuthAuthorize = 11
    """ User attempted OAuth authorization """

    PasswordChange = 102
    """ A user attempted to change his or her password """

    StartPasswordReset = 103
    """ A user attempted to get a password reset token """

    FinishPasswordReset = 104
    """ A user attempted to get a reset password using the token """

    ChangeFactor2 = 105
    """ A user attempted to get a change their factor2 """

    ResetFactor2 = 106
    """ A user attempted to get a reset their factor2 """

    UpdateUser = 107
    """ A user attempted to update their account """

    DeleteUser = 108
    """ A user attempted to delete their account """

    CreateApiKey = 109
    """ A user attempted to create an ApiKey """

    DeleteApiKey = 110
    """ A user attempted to delete an ApiKey """

    UpdateApiKey = 111
    """ A user attempted to update an ApiKey """

    CreateOAuthClient = 112
    """ A user attempted to create an OAuthClient """

    DeleteOAuthClient = 113
    """ A user attempted to delete an OAuthClient """

    UpdateOAuthClient = 114
    """ A user attempted to update an OAuthClient """

    CreateUser = 115
    """ A user attempted signup """

    ConfigureFactor2 = 116
    """ A user attempted to get a configure their factor2 """

    AdminPasswordChange = 202
    """ Admin attempted to change user's password """

    AdminStartPasswordReset = 203
    """ Admin attempted to get a password reset token for a user """

    AdminChangeFactor2 = 205
    """ Admin attempted to get a change user's factor2 """

    AdminResetFactor2 = 206
    """ Admin attempted to get a reset user's factor2 """

    AdminUpdateUser = 207
    """ Admin attempted to update user's account """

    AdminDeleteUser = 208
    """ Admin attempted to delete user's account """

    AdminCreateApiKey = 209
    """ Admin attempted to create an ApiKey for a user """

    AdminDeleteApiKey = 210
    """ Admin attempted to delete a user's ApiKey """

    AdminUpdateApiKey = 211
    """ Admin attempted to update a user's ApiKey """

    AdminCreateOAuthClient = 212
    """ Admin attempted to create an OAuthClient for a user """

    AdminDeleteOAuthClient = 213
    """ Admin attempted to delete a user's OAuthClient """

    AdminUpdateOAuthClient = 214
    """ Admin attempted to update a user's OAuthClient """

    AdminCreateUser = 215
    """ Admin attempted to create a user """

    AdminConfigureFactor2 = 216
    """ Admin attempted to get a configure user's factor2 """

class LoggedActionCodeResponse(TypedDict):
    action_code: int
    action_code_name: str

def logged_action_code(code: LoggedActionCode) -> LoggedActionCodeResponse:
    return {
        "action_code": code.value,
        "action_code_name": code.name
    }

def log_as_warn_or_error(ce: CrossauthError, message: str|Dict[str,Any]):
    if (ce.code in [
        ErrorCode.InvalidCsrf,
        ErrorCode.UserNotExist,
        ErrorCode.UserNotActive,
        ErrorCode.InvalidKey,
        ErrorCode.InvalidToken,
        ErrorCode.Forbidden,
        ErrorCode.PasswordFormat,
        ErrorCode.PasswordInvalid,
        ErrorCode.PasswordMatch,
        ErrorCode.Forbidden,
        ErrorCode.Expired,
        ErrorCode.ExpiredToken,
    ]): 
        CrossauthLogger.logger().warn(message)
    else:
        CrossauthLogger.logger().error(message)