from crossauth_backend.oauth.wellknown import OpenIdConfiguration
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.interfaces import KeyPrefix
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.crypto import Crypto
from crossauth_backend.storage import KeyStorage
from crossauth_backend.utils import MapGetter

from typing import TypedDict, Optional, Dict, Any, Literal, List
import json
from datetime import datetime
import aiohttp
from jwt import (
    JWT,
    jwk_from_dict,
    jwk_from_pem,
    AbstractJWKBase
)

type EncryptionKey = Dict[str, Any] | str

class Keys(TypedDict, total=True):
    keys: List[AbstractJWKBase]

class OAuthTokenConsumerOptions(TypedDict, total=False):
    """
    Options that can be passed to: :class:`OAuthTokenConsumerBase`.
    """

    jwt_key_type : str
    """ 
    Secret key if using a symmetric cipher for signing the JWT.  
    Either this or `jwt_secret_key_file` is required when using self kind of 
    cipher """

    jwt_secret_key : str
    """ Secret key if using a symmetric cipher for signing the JWT.  
    Either this or `jwt_secret_key_file` is required when using self kind of 
    cipher """

    jwt_public_key : str
    """ The public key if using a public key cipher for signing the JWT.  
    Either this or `jwt_public_key_file` is required when using self kind of 
    cipher.  privateKey or privateKeyFile is also required."""

    clock_tolerance : int
    """ Number of seconds tolerance when checking expiration.  Default 10"""

    auth_server_base_url : str
    """ The value to expect in the iss
    claim.  If the iss does not match self, the token is rejected.
    No default (required)"""

    oidc_config : Optional[OpenIdConfiguration|Dict[str,Any]]
    """
    For initializing the token consumer with a static OpenID Connect 
    configuration.
    """

    persist_access_token : bool
    """ Whether to persist access tokens in key storage.  Default false.
        
        If you set self to True, you must also set `key_storage`.
    """

    key_storage : Optional[KeyStorage]
    """ If persisting tokens, you need to provide a storage to persist them to"""

    jwt_secret_key_file : str
    """ Filename with secret key if using a symmetric cipher for signing the 
        JWT.  Either self or `jwt_secret_key` is required when using self kind 
        of cipher"""

    jwt_public_key_file : str
    """ Filename for the public key if using a public key cipher for signing the 
        JWT.  Either self or `jwt_public_key` is required when using self kind of 
        cipher.  privateKey or privateKeyFile is also required."""

    audience : str
    """
        The aud claim needs to match self value.
        No default (required)
    """

class OAuthTokenConsumer:
    """
    This abstract class is for validating OAuth JWTs. 
    """
    
    @property
    def auth_server_base_url(self):
        return self._auth_server_base_url

    @property
    def audience(self):
        return self._audience
    @audience.setter
    def audience(self, val : str):
        self._audience = val

    @property
    def _jwt_key_type(self):
        return self.__jwt_key_type
    @_jwt_key_type.setter
    def _jwt_key_type(self, val : str|None):
        self.__jwt_key_type = val

    @property
    def _jwt_public_key_file(self):
        return self.__jwt_public_key_file
    @_jwt_public_key_file.setter
    def _jwt_public_key_file(self, val : str|None):
        self.__jwt_public_key_file = val

    @property
    def _jwt_public_key(self):
        return self.__jwt_public_key
    @_jwt_public_key.setter
    def _jwt_public_key(self, val : bytes|None):
        self.__jwt_public_key = val

    @property
    def _jwt_secret_key(self):
        return self.__jwt_secret_key
    @_jwt_secret_key.setter
    def _jwt_secret_key(self, val : bytes|None):
        self.__jwt_secret_key = val

    @property
    def _clock_tolerance(self):
        return self.__clock_tolerance
    @_clock_tolerance.setter
    def _clock_tolerance(self, val : int):
        self.__clock_tolerance = val

    @property
    def _persist_access_token(self):
        return self.__persist_access_token
    @_persist_access_token.setter
    def _persist_access_token(self, val : bool):
        self.__persist_access_token = val

    @property
    def oidc_config(self):
        return self._oidc_config
    @oidc_config.setter
    def oidc_config(self, val : OpenIdConfiguration|None):
        self._oidc_config = val

    @property
    def keys(self):
        return self._keys
    @keys.setter
    def keys(self, val : Dict[str, AbstractJWKBase]):
        self._keys = val

    def __init__(self, audience: str, options: OAuthTokenConsumerOptions = {}):
        """
        The OpenID Connect configuration for the authorization server,
        either passed to the constructor or fetched from the authorization
        server.
        """


        self._audience = audience
        self.__jwt_key_type : str|None = ""
        self._auth_server_base_url : str = ""
        self.__jwt_secret_key : bytes|None = None
        self.__jwt_public_key : bytes|None = None
        self.__jwt_secret_key_file : str|None = None
        self.__jwt_public_key_file : str|None = None
        self.__clock_tolerance = 10

        set_parameter("jwt_key_type", ParamType.String, self, options, "JWT_KEY_TYPE")

        self.__persist_access_token = False


        self._oidc_config = options.get('oidc_config')
        self._keys : Dict[str, AbstractJWKBase] = {}

        self.__key_storage : KeyStorage|None = None
        if (options.get("key_storage") is not None):
            self.__key_storage = options.get("key_storage")

        set_parameter("auth_server_base_url", ParamType.String, self, options, "AUTH_SERVER_BASE_URL", required=True, protected=True)
        set_parameter("jwt_key_type", ParamType.String, self, options, "JWT_KEY_TYPE")
        set_parameter("jwt_public_key_file", ParamType.String, self, options, "JWT_PUBLIC_KEY_FILE",)
        set_parameter("jwt_secret_key_file", ParamType.String, self, options, "JWT_SECRET_KEY_FILE")
        set_parameter("jwt_secret_key", ParamType.String, self, options, "JWT_SECRET_KEY")
        set_parameter("jwt_public_key", ParamType.String, self, options, "JWT_PUBLIC_KEY")
        set_parameter("clock_tolerance", ParamType.Number, self, options, "OAUTH_CLOCK_TOLERANCE")
        set_parameter("persist_access_token", ParamType.Boolean, self, options, "OAUTH_PERSIST_ACCESS_TOKEN")

        if self._jwt_public_key and not self._jwt_key_type:
            raise ValueError("If specifying jwtPublic key, must also specify jwtKeyType")

        if (self._jwt_secret_key or self.__jwt_secret_key_file):
            if (self._jwt_public_key or self.__jwt_public_key_file):
                raise CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify symmetric and public/private JWT keys")
            
            if (self._jwt_secret_key and self.__jwt_secret_key_file):
                raise CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify symmetric key and file")
            
            if (self.__jwt_secret_key_file is not None):
                with open(self.__jwt_secret_key_file, 'rb') as f:
                    self._jwt_secret_key = f.read()
            
        elif ((self._jwt_public_key is not None or self._jwt_public_key_file is not None)):
            if (self._jwt_public_key_file is not None and self._jwt_public_key is not None):
                raise CrossauthError(ErrorCode.Configuration, 
                    "Cannot specify both public key and public key file")
            
            if (self._jwt_public_key_file):
                with open(self._jwt_public_key_file, 'rb') as f:
                    self._jwt_public_key = f.read()
            
    async def load_keys(self):
        """
        The RSA public keys or symmetric keys for the authorization server,
        either passed to the constructor or fetched from the authorization
        server.
        """
        try:
            if self._jwt_secret_key:
                #if not self._jwt_key_type:
                #    raise ValueError("Must specify jwtKeyType if setting jwt_secret_key")
                jwk : AbstractJWKBase = jwk_from_pem(self._jwt_secret_key)
                self.keys["_default"] = jwk
            elif self._jwt_public_key:
                #if not self._jwt_key_type:
                #    raise ValueError("Must specify jwtKeyType if setting jwt_public_key")
                jwk : AbstractJWKBase = jwk_from_pem(self._jwt_public_key)
                self.keys["_default"] = jwk
            else:
                if not self.oidc_config:
                    await self.load_config()
                if not self.oidc_config:
                    raise ValueError("Load OIDC config before Jwks")
                await self.load_jwks()
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": e}))
            CrossauthLogger.logger().error(j({"msg": "Couldn't load keys", "cerr": ce}))
            raise ValueError("Couldn't load keys")

    async def load_config(self, oidc_config: Optional[Dict[str, Any]] = None):
        """
        Loads OpenID Connect configuration, or fetches it from the 
        authorization server (using the well-known enpoint appended
        to `authServerBaseUrl` )
        :param Dict[str, Any]|None oidcConfig: the configuration, or undefined to load it from
              the authorization server
        :raises :class:`common!CrossauthError`: object with :class:`ErrorCode` of
          - `Connection` if the fetch to the authorization server failed.
        """
        if oidc_config:
            self._oidc_config = oidc_config
            return

        if not self._auth_server_base_url:
            raise ValueError("Couldn't get OIDC configuration. Either set authServerBaseUrl or set config manually")

        try:
            async with aiohttp.ClientSession() as session:

                resp = await session.get(f"{self._auth_server_base_url}/.well-known/openid-configuration")
                if not resp:
                    raise ValueError("Couldn't get OIDC configuration")
                self._oidc_config = {}

                body = await resp.json()
                self._oidc_config = {**body}
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": e}))
            raise ValueError("Unrecognized response from OIDC configuration endpoint")

    async def load_jwks(self, jwks: Optional[Keys] = None):
        """
        Loads the JWT signature validation keys, or fetches them from the 
        authorization server (using the URL in the OIDC configuration).
        :param Dict[str, Any]|None jwks: the keys to load, or undefined to fetch them from
               the authorization server.
        :raises :class:`crossauth_backend.CrossauthError`: object with :class:`ErrorCode` of
          - `Connection` if the fetch to the authorization server failed,
            the OIDC configuration wasn't set or the keys could not be parsed.
        """
        if jwks:
            self.keys = {}
            for jwk in jwks['keys']:
                kid : str = jwk.get_kid()
                self.keys[kid] = jwk
        else:
            if not self.oidc_config:
                raise ValueError("Load OIDC config before Jwks")
            try:
                async with aiohttp.ClientSession() as session:

                    resp = await session.get(self.oidc_config['jwks_uri'])
                    if not resp:
                        raise ValueError("Couldn't get OIDC configuration")
                    self.keys = {}
                    body = await resp.json()
                    if 'keys' not in body or not isinstance(body['keys'], list):
                        raise ValueError("Couldn't fetch keys")
                    for k in body['keys']:
                        kid = k.get('kid', "_default")
                        self.keys[kid] = jwk_from_dict(k)

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
            CrossauthLogger.logger().error(j({"msg": token_type + " expected but got " + decoded.get('type', "")}))
            return None
        if decoded.get('iss') != self._auth_server_base_url:
            CrossauthLogger.logger().error(j({"msg": f"Invalid issuer: {decoded.get('iss')} in access token", "hashedAccessToken": self.hash(decoded["jti"])}))
            return None
        if 'aud' in decoded:
            if (isinstance(decoded['aud'], list) and self._audience not in decoded['aud']) or \
               (not isinstance(decoded['aud'], list) and decoded['aud'] != self._audience):
                CrossauthLogger.logger().warn(j({"msg": f"Invalid audience: {decoded['aud']} in access token"}))
                return None
        return decoded
    
    async def token_authorized(self, token: str, tokenType: Literal["access", "refresh", "id"]) -> Optional[Dict[str, Any]]:
        """
        If the given token is valid, the payload is returned.  Otherwise
        undefined is returned.  
        
        The signature must be valid, the expiry must not have passed and,
        if `tokenType` is defined,. the `type` claim in the payload must
        match it.
        
        Doesn't throw exceptions.
        
        :param str token: The token to validate
        :param Literal["access", "refresh", "id"] token_type: If defined, the `type` claim in the payload must
               match this value
        """
        payload = await self._token_authorized(token, tokenType)
        if payload:
            if tokenType == "access" and self._persist_access_token and self.__key_storage:
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
            CrossauthLogger.logger().warn(j({"msg": "No keys loaded so cannot validate tokens"}))
        kid : str|None = None
        instance = JWT()
        try:
            header = OAuthTokenConsumer.decode_header(access_token)
            kid = header.get('kid', "_default")
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": e}))
            CrossauthLogger.logger().warn(j({"msg": "Invalid access token format", "cerr": ce}))
            return None
        key = self.keys.get("_default")
        for loaded_kid in self.keys:
            if kid == loaded_kid:
                key = self.keys[loaded_kid]
                break
        if not key:
            CrossauthLogger.logger().warn(j({"msg": "No matching keys found for access token"}));
            return None
        try:
            decoded_payload = instance.decode(access_token, key)
            # if decoded_payload['exp'] * 1000 < (datetime.now().timestamp() + self._clock_tolerance):
            #     CrossauthLogger.logger.warn(j({("msg": "Access token has expired"}))
            #     return None
            return decoded_payload
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err":e}))
            return None

    @staticmethod
    def decode_header(token : str):
        parts = token.split(".")
        if (len(parts) != 3):
            raise CrossauthError(ErrorCode.DataFormat, "Invalid JWT")
        #header_str = base64.urlsafe_b64decode(parts[0])
        header_str = Crypto.base64_decode(parts[0])
        return json.loads(header_str)
    
    def hash(self, plaintext : str) -> str: 
        return Crypto.hash(plaintext); 
    
