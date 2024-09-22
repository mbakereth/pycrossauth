# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.common.error import CrossauthError, ErrorCode 
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.oauth.tokenconsumer import OAuthTokenConsumer
from typing import TypedDict, Dict, Optional, Any, List
from jwt import JWT
class OAuthResourceServerOptions(TypedDict):
    pass

class OAuthResourceServer:

    @property
    def token_consumers(self):
        return self._token_consumers
    
    def __init__(self, token_consumers : list[OAuthTokenConsumer], options : OAuthResourceServerOptions = {}):
        
        self._token_consumers : List[OAuthTokenConsumer]

        self._token_consumers = [*token_consumers]

    async def access_token_authorized(self, access_token : str) -> Optional[Dict[str, Any]]:
        try:
            instance = JWT()
            payload = instance.decode(access_token, None, do_verify=False, do_time_check=False)
            for consumer in self._token_consumers:
                if (payload.get('iss') == consumer.auth_server_base_url and \
                    ((payload.get('aud') == consumer.audience) or \
                     ('aud' not in payload and consumer.audience == ""))):
                    return await consumer.token_authorized(access_token, "access")
            raise CrossauthError(ErrorCode.Unauthorized, "Invalid issuer in access token")
        except Exception as e:
            CrossauthLogger.logger().warn(j({"err": str(e)}))
            return None