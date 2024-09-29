# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from .. import CrossauthError

import json
import os
from typing import Any, Dict, Mapping
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

    levelName = ["NONE", "ERROR", "WARN", "INFO", "DEBUG"]

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
            if level_name in CrossauthLogger.levelName:
                self.level = CrossauthLogger.levelName.index(level_name)
            else:
                self.level = CrossauthLogger.Error
        else:
            self.level = CrossauthLogger.Error
        CrossauthLogger.rossauth_logger_accepts_json = True

    def set_level(self, level: int) -> None:
        """ Set the level to report down to """
        self.level = level

    def _log(self, level: int, output: Any) -> None:
        if level <= self.level:
            if isinstance(output, str):
                print(f"Crossauth {CrossauthLogger.levelName[level]} {self._current_time_iso()} {output}")
            else:
                print(json.dumps({"level": CrossauthLogger.levelName[level], "time": self._current_time_iso(), **output}))

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


def j(arg: Mapping[str, Any] | str) -> Dict[str, Any] | str:
    """ Helper function that returns JSON if the error log supports it,
        otherwise a string """
    global _crossauth_logger_accepts_json
    argcopy : Mapping[str,Any] = {}
    if (type(arg) == str):
        argcopy = {"msg": arg}
    elif (isinstance(arg, Mapping)):
        argcopy = {**arg}
    if isinstance(arg, dict) and "cerr" in arg and isinstance(arg["cerr"], CrossauthError):
        argcopy["error_code"] = arg["cerr"].code.value
        argcopy["error_code_name"] = arg["cerr"].code_name
        argcopy["http_status"] = arg["cerr"].http_status
        if "msg" not in argcopy:
            argcopy["msg"] = argcopy["cerr"].message

    if isinstance(arg, dict) and "err" in arg and isinstance(arg["err"], CrossauthError):
        argcopy["error_code"] = arg["err"].code.value
        argcopy["error_code_name"] = arg["err"].code_name
        argcopy["http_status"] = arg["err"].http_status
        if "msg" not in argcopy:
            if ("cerr" in argcopy):
                argcopy["msg"] = argcopy["cerr"].message
            elif ("err" in argcopy):
                argcopy["msg"] = argcopy["err"].message
        argcopy["stack"] = str(traceback.format_exception(arg["err"]))

    elif isinstance(arg, dict) and "err" in arg and isinstance(arg["err"], Exception):
        argcopy["stack"] = str(traceback.format_exception(arg["err"]))
        if "msg" not in argcopy:
            argcopy["msg"]  = str(str(arg["err"]))

    if ("err" in argcopy): del argcopy["err"]
    if ("cerr" in argcopy): del argcopy["cerr"]

    if (type(arg) == str):
        return arg
    if (_crossauth_logger_accepts_json):
        return argcopy
    return json.dumps(argcopy)


_crossauth_logger = CrossauthLogger(None)
_crossauth_logger_accepts_json = True
