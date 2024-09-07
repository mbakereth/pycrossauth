# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import json
import base64
from typing import Dict, Optional, Any

from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j

class JWT:
    """
    Encapsulates the payload of a JWT, with both the token and
    decoded JSON payload.
    """

    def __init__(self, token: Optional[str] = None, payload: Dict[str, Any] = {}):
        """
        Constructor. Pass either `token` or `payload`.
        
        Args:
            token: the string JWT token - the payload will be parsed from it
            payload: the JSON payload. The payload will be set but not
                     the string `token`.
        """
        self.token: Optional[str] = token
        
        if payload:
            self.payload = payload
        elif self.token:
            parts = self.token.split(".")
            if len(parts) != 3:
                raise CrossauthError(ErrorCode.InvalidToken, "JWT not in correct format")
            try:
                self.payload = json.loads(base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8'))
            except Exception as e:
                CrossauthLogger.logger().error(j({"err": str(e)}))
                if len(parts) != 3:
                    raise CrossauthError(ErrorCode.InvalidToken, "JWT payload not in correct format")
                json_string = base64.urlsafe_b64decode(parts[1] + '==').decode('utf-8')
                self.payload = json.loads(json_string)
        else:
            self.payload = {}
