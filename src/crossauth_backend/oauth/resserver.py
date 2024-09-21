# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.common.error import CrossauthError, ErrorCode 
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.oauth.tokenconsumer import OAuthTokenConsumer
from typing import TypedDict, Dict
from jwt import JWT
class OAuthResourceServerOptions(TypedDict):
    pass

class OAuthResourceServer:

    @property
    def token_consumers(self):
        return self._token_consumers
    
    def __init__(self, token_consumers : list[OAuthTokenConsumer], options : OAuthResourceServerOptions = {}):
        
        self._token_consumers : Dict[str, OAuthTokenConsumer] = {}

        for consumer in token_consumers:
            self._token_consumers[consumer.auth_server_base_url] = consumer

    async def access_token_authorized(self, access_token : str):
        try:
            instance = JWT()
            payload = instance.decode(access_token, None, do_verify=False, do_time_check=False)
            if payload.get('aud') and payload['aud'] in self.token_consumers:
                return await self.token_consumers[payload['aud']].token_authorized(access_token, "access")
            raise CrossauthError(ErrorCode.Unauthorized, "Invalid issuer in access token")
        except Exception as e:
            CrossauthLogger.logger().warn(j({"err": str(e)}))
            return None