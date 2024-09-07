# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.oauth.wellknown import OpenIdConfiguration
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.interfaces import KeyPrefix
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.crypto import Crypto
from crossauth_backend.storage import KeyStorage
from crossauth_backend.utils import MapGetter

from typing import TypedDict, Optional, Dict, Any, Literal
import json
from datetime import datetime 
import aiohttp

type EncryptionKey = Dict[str, Any] | str

class OAuthTokenConsumerOptions(TypedDict, total=False):
    """
    Options that can be passed to:@link OAuthTokenConsumerBase}.
    """

    """ 
    Secret key if using a symmetric cipher for signing the JWT.  
    Either this or `jwt_secret_key_file` is required when using self kind of 
    cipher """
    jwt_key_type : str

    """ Secret key if using a symmetric cipher for signing the JWT.  
    Either this or `jwt_secret_key_file` is required when using self kind of 
    cipher """
    jwt_secret_key : str

    """ The public key if using a public key cipher for signing the JWT.  
    Either this or `jwt_public_key_file` is required when using self kind of 
    cipher.  privateKey or privateKeyFile is also required."""
    jwt_public_key : str

    """ Number of seconds tolerance when checking expiration.  Default 10"""
    clock_tolerance : int

    """ The value to expect in the iss
    claim.  If the iss does not match self, the token is rejected.
    No default (required)"""
    auth_server_base_url : str

    """
    For initializing the token consumer with a static OpenID Connect 
    configuration.
    """
    oidc_config : Optional[OpenIdConfiguration|Dict[str,Any]]

    """ Whether to persist access tokens in key storage.  Default false.
        
        If you set self to True, you must also set `key_storage`.
    """
    persist_access_token : bool

    """ If persisting tokens, you need to provide a storage to persist them to"""
    key_storage : Optional[KeyStorage]

    """ Filename with secret key if using a symmetric cipher for signing the 
        JWT.  Either self or `jwt_secret_key` is required when using self kind 
        of cipher"""
    jwt_secret_key_file : str

    """ Filename for the public key if using a public key cipher for signing the 
        JWT.  Either self or `jwt_public_key` is required when using self kind of 
        cipher.  privateKey or privateKeyFile is also required."""
    jwt_public_key_file : str

    """
        The aud claim needs to match self value.
        No default (required)
    """
    audience : str

class OAuthTokenConsumer:
    
    def __init__(self, audience: str, session: aiohttp.ClientSession, options: OAuthTokenConsumerOptions = {}):
        
        set_parameter("jwt_key_type", ParamType.String, self, options, "JWT_KEY_TYPE", protected=True)
        set_parameter("audience", ParamType.String, self, options, "OAUTH_AUDIENCE", required=True, protected=True)

        self._auth_server_base_url = ""
        self._jwt_key_type : str|None =None
        self._jwt_public_key_file : str|None = None
        self._jwt_secret_key : str|None = None
        self._jwt_public_key : str|None = None
        self._jwt_secret_key_file : str|None = None
        self._jwt_public_key_file : str|None = None
        self._clock_tolerance = 10
        self.persist_access_token = False

        self._audience = audience
        self.oidc_config = options.get('oidc_config')
        self.keys : Dict[str, Any] = {}
        self.__key_storage : KeyStorage|None = None
        if (options.get("key_storage") is not None):
            self.__key_storage = options.get("key_storage")
        self._session : aiohttp.ClientSession = session

        set_parameter("auth_server_base_url", ParamType.String, self, options, "AUTH_SERVER_BASE_URL", required=True, public=True)
        set_parameter("jwt_key_type", ParamType.String, self, options, "JWT_KEY_TYPE", protected=True)
        set_parameter("jwt_public_key_file", ParamType.String, self, options, "JWT_PUBLIC_KEY_FILE", protected=True)
        set_parameter("jwt_secret_key_file", ParamType.String, self, options, "JWT_SECRET_KEY_FILE", protected=True)
        set_parameter("jwt_secret_key", ParamType.String, self, options, "JWT_SECRET_KEY", protected=True)
        set_parameter("jwt_public_key", ParamType.String, self, options, "JWT_PUBLIC_KEY", protected=True)
        set_parameter("clock_tolerance", ParamType.Number, self, options, "OAUTH_CLOCK_TOLERANCE", protected=True)
        set_parameter("persist_access_token", ParamType.Boolean, self, options, "OAUTH_PERSIST_ACCESS_TOKEN", protected=True)

        if self._jwt_public_key and not self._jwt_key_type:
            raise ValueError("If specifying jwtPublic key, must also specify jwtKeyType")

        if (self._jwt_secret_key or self._jwt_secret_key_file):
            if (self._jwt_public_key or self._jwt_public_key_file):
                raise CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify symmetric and public/private JWT keys")
            
            if (self._jwt_secret_key and self._jwt_secret_key_file):
                raise CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify symmetric key and file")
            
            if (self._jwt_secret_key_file is not None):
                with open(self._jwt_secret_key_file, 'r', encoding='utf-8') as f:
                    self._jwt_secret_key = \
                        f.read(self._jwt_secret_key_file)
            
        elif ((self._jwt_public_key is not None or self._jwt_public_key_file is not None)):
            if (self._jwt_public_key_file is not None and self._jwt_public_key is not None):
                raise CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify both public key and public key file")
            
            if (self._jwt_public_key_file):
                with open(self._jwt_public_key_file, 'r', encoding='utf-8') as f:
                    self._jwt_public_key = \
                        f.read(self._jwt_public_key_file)
            


    async def load_keys(self):
        try:
            if self._jwt_secret_key:
                if not self._jwt_key_type:
                    raise ValueError("Must specify jwtKeyType if setting jwt_secret_key")
                self.keys["_default"] = await self._import_pkcs8(self._jwt_secret_key, self._jwt_key_type)
            elif self._jwt_public_key:
                if not self._jwt_key_type:
                    raise ValueError("Must specify jwtKeyType if setting jwt_public_key")
                key = await self._import_spki(self._jwt_public_key, self._jwt_key_type)
                self.keys["_default"] = key
            else:
                if not self.oidc_config:
                    await self.load_config()
                if not self.oidc_config:
                    raise ValueError("Load OIDC config before Jwks")
                await self.load_jwks()
        except Exception as e:
            print(f"Error loading keys: {e}")
            raise ValueError("Couldn't load keys")

    async def load_config(self, oidc_config: Optional[Dict[str, Any]] = None):
        if oidc_config:
            self.oidc_config = oidc_config
            return

        if not self._auth_server_base_url:
            raise ValueError("Couldn't get OIDC configuration. Either set authServerBaseUrl or set config manually")

        try:
            resp = await self._session.get(f"{self._auth_server_base_url}/.well-known/openid-configuration")
            if not resp:
                raise ValueError("Couldn't get OIDC configuration")
            self.oidc_config = {}

            body = await resp.json()
            self.oidc_config = {**body}
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": e}))
            raise ValueError("Unrecognized response from OIDC configuration endpoint")

    async def load_jwks(self, jwks: Optional[Dict[str, Any]] = None):
        if jwks:
            self.keys = {}
            for key in jwks['keys']:
                self.keys[key.get('kid', "_default")] = await self._import_jwk(key)
        else:
            if not self.oidc_config:
                raise ValueError("Load OIDC config before Jwks")
            try:
                resp = await self._session.get(self.oidc_config['jwks_uri'])
                if not resp:
                    raise ValueError("Couldn't get OIDC configuration")
                self.keys = {}
                body = await resp.json()
                if 'keys' not in body or not isinstance(body['keys'], list):
                    raise ValueError("Couldn't fetch keys")
                for key in body['keys']:
                    kid = key.get('kid', "_default")
                    self.keys[kid] = await self._import_jwk(key)
            except Exception as e:
                CrossauthLogger.logger().debug(j({"cerr": e}))
                raise ValueError("Unrecognized response from OIDC jwks endpoint")

    async def _token_authorized(self, token: str, token_type: str) -> Optional[Dict[str, Any]]:
        if not self.keys or len(self.keys) == 0:
            await self.load_keys()
        decoded = await self._validate_token(token)
        if not decoded:
            return None
        if decoded.get('type') != token_type:
            print(f"{token_type} expected but got: {decoded.get('type')}")
        if decoded.get('iss') != self._auth_server_base_url:
            print(f"Invalid issuer: {decoded.get('iss')} in access token")
            return None
        if 'aud' in decoded:
            if (isinstance(decoded['aud'], list) and self._audience not in decoded['aud']) or \
               (not isinstance(decoded['aud'], list) and decoded['aud'] != self._audience):
                print(f"Invalid audience: {decoded['aud']} in access token")
                return None
        return decoded
    
    async def token_authorized(self, token: str, tokenType: Literal["access", "refresh", "id"]) -> Optional[Dict[str, Any]]:
        payload = await self._token_authorized(token, tokenType)
        if payload:
            if tokenType == "access" and self.persist_access_token and self.__key_storage:
                try:
                    key = KeyPrefix.access_token + Crypto.hash(payload['jti'])
                    token_in_storage = await self.__key_storage.get_key(key)
                    now = datetime.now()
                    if "expires" in token_in_storage and MapGetter[datetime].get(token_in_storage, "expires", now).timestamp() < now.timestamp():
                        CrossauthLogger.logger().error(j({"msg":"Access token expired in storage but not in JWT"}))
                        return None
                except Exception as e:
                    CrossauthLogger.logger().warn(j({
                        "msg": "Couldn't get token from database - is it valid?",
                        "hashedAccessToken": Crypto.hash(payload['jti'])
                    }))
                    CrossauthLogger.logger().debug(j({"err": str(e)}))
                    return None
        return payload

    async def _validate_token(self, access_token: str) -> Optional[Dict[str, Any]]:
        if not self.keys or len(self.keys) == 0:
            print("No keys loaded so cannot validate tokens")
        kid = None
        try:
            header = self._decode_protected_header(access_token)
            kid = header.get('kid')
        except:
            print("Invalid access token format")
            return None
        key = self.keys.get("_default")
        for loaded_kid in self.keys:
            if kid == loaded_kid:
                key = self.keys[loaded_kid]
                break
        if not key:
            print("No matching keys found for access token")
            return None
        try:
            payload = await self._compact_verify(access_token, key)
            decoded_payload = json.loads(payload.decode())
            if decoded_payload['exp'] * 1000 < (datetime.now().timestamp() + self._clock_tolerance):
                print("Access token has expired")
                return None
            return decoded_payload
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err":e}))
            return None

    async def _import_pkcs8(self, key: str, key_type: str):
        # Implement the import logic here
        pass

    async def _import_spki(self, key: str, key_type: str):
        # Implement the import logic here
        pass

    async def _import_jwk(self, key: Dict[str, Any]):
        # Implement the import logic here
        pass

    def _decode_protected_header(self, token: str) -> Dict[str, Any]:
        # Implement the decode logic here
        return {}

    async def _compact_verify(self, token: str, key: Any) -> bytes:
        # Implement the verification logic here
        return b""
