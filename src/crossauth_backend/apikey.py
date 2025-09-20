
from typing import TypedDict, NamedTuple, Dict, Any, cast
import re
import datetime
from nulltype import Null, NullType

from crossauth_backend.common.interfaces import ApiKey, Key
from crossauth_backend.crypto import Crypto
from crossauth_backend.storage import KeyStorage
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.error import CrossauthError, ErrorCode

TOKEN_LENGTH = 16; # in bytes, before base64url

class KeyReturn(NamedTuple):
    key: ApiKey
    token: str

class NamedKey(Key):
    name: str

class ApiKeyManagerOptions(TypedDict, total=False):
    """ Configuration options for TokenEmailer """

    key_length: int
    """  Length in bytes of the randomly-created key (before Base64 encoding and signature) """

    secret: str
    """ Server secret.  Needed for emailing tokens and for csrf tokens """

    prefix: str
    """ The prefix to add to the hashed key in storage.  Defaults to :class: Prefix.api_key """

    auth_scheme: str
    """ The token type in the Authorization header.  Defaults to "ApiKey" """

class ApiKeyManager:
    """
    Manager API keys.

    The caller must pass a {@link KeyStorage} object.  This must provide a 
    string field called `name` in the returned {@link @crossauth/common!Key}
    objects (in other words, the databsae table behind it must have a `name` field).

    Api keys have three forms in their value.  The {@link @crossauth/common!Key} 
    object's `value` field is a base64-url-encoded random number.
    When the key is in a header, it is expected to be folled by a dot and a 
    signature to protect against injection attacks.
    When stored in the key storage, only the unsigned part is used (before the 
    dot), it is hashed and preceded by
    `prefix`.  The signature part is dropped for storage economy.  This does 
    not compromise security so long as the
    signature is always validated before comparing with the database.
    """

    def __init__(self, key_storage: KeyStorage, options : ApiKeyManagerOptions = {}):
    
        self.__secret = ""
        self.__key_length = 16
        self.__api_key_storage : KeyStorage = key_storage
        self.prefix = ""
        self.auth_scheme = "ApiKey"
        set_parameter("secret", ParamType.String, self, options, "SECRET", required=True)
        set_parameter("key_length", ParamType.Integer, self, options, "APIKEY_LENGTH")
        set_parameter("prefix", ParamType.String, self, options, "APIKEY_PREFIX", public=True)
        set_parameter("auth_scheme", ParamType.String, self, options, "APIKEY_AUTHSCHEME", public=True)


    async def create_key(self, 
                        name: str,
                        userid: str|int|None = None,
                        data: Dict[str,Any]|None = None,
                        expiry: int|None = None,
                        extra_fields: Dict[str, Any] = {}) -> KeyReturn:
        """
        Creates a new random key and returns it, unsigned. It is also persisted in the key storage as a 
        hash of the unsigned part prefixed with prefix().
        

        :param name: a name for the key. This is for the user to refer to it 
                 (eg, for showing the keys the user has created or deleting 
                 a key)
            userid: id for the user who owns this key, which may be None 
                   for keys not associated with a user
        :param data: any application-specific extra data.
                  If it contains an array called `scope` and this array 
                  contains `editUser`, the api key can be used for user
                  manipulation functions (eg change password)
        :param expiry: expiry as a number of seconds from now
        :param extra_fields: any extra fields to save in key storage, and pass 
                         back in the Key object.
        
        Returns:
            Dictionary containing:
            - key: the new key as an ApiKey object
            - token: the token for the Authorization header (with the signature appended.)
        """
        value = Crypto.random_value(self.__key_length)
        created = datetime.datetime.now()
        expires = datetime.datetime.fromtimestamp(created.timestamp() + expiry) if expiry else Null
        hashed_key = ApiKeyManager.__hash_api_key_value(value)
        _userid : str|int|NullType = userid if userid is not None else Null
        if (userid is None): userid = Null
        
        # Create the key object with all fields
        key : NamedKey = {
            'name': name,
            'value': value,
            'userid': _userid,
            'data': KeyStorage.encode_data(data),
            'expires': expires,
            'created': created
        }
        
        key = cast(NamedKey, {**key, **extra_fields})
                
        # Prepare storage data
        storage_extra : Dict[str,Any] = {'name': name, **extra_fields}
        
        await self.__api_key_storage.save_key(
            userid,
            self.prefix + hashed_key,
            created,
            expires,
            key["data"] if "data" in key else "",
            storage_extra
        )
        
        token = self.__sign_api_key_value(value)
        
        return KeyReturn(key, token) 
    

    @staticmethod
    def __hash_api_key_value(unsigned_value: str) -> str:
        return Crypto.hash(unsigned_value)

    @staticmethod
    def hashSignedApiKeyValue(unsigned_value : str) -> str:
        """
        Returns the hash of the bearer value from the Authorization header.
        
        This has little practical value other than for reporting.  Unhashed
        tokens are never reported.
        @param unsignedValue the part of the Authorization header after "Berear ".
        @returns a hash of the value (without the prefix).
        """
        return Crypto.hash(unsigned_value.split(".")[0])
    
    def __unsign_api_key_value(self, signed_value: str) -> str:
        return Crypto.unsign(signed_value, self.__secret)["v"]
    
    def __sign_api_key_value(self, unsigned_value: str) -> str:
        return Crypto.sign({"v": unsigned_value}, self.__secret)
    
    async def get_key(self, signed_value: str) -> NamedKey:
        """
        Get API key from signed value.
        
        :param signedValue: The signed API key value
            
        :return Dict containing the API key data
            
        :raise CrossauthError: If the key is invalid
        """
        if self.auth_scheme != "" and signed_value.startswith(self.auth_scheme + " "):
            regex = re.compile(f"^{re.escape(self.auth_scheme)} ")
            signed_value = regex.sub("", signed_value)
        
        unsigned_value = self.__unsign_api_key_value(signed_value)
        hashed_value = ApiKeyManager.__hash_api_key_value(unsigned_value)
        key = await self.__api_key_storage.get_key(self.prefix + hashed_value)
        
        if "name" not in key:
            raise CrossauthError(ErrorCode.InvalidKey, "Not a valid API key")
        
        return cast(NamedKey, {**key, "name": key["name"]})

    async def validateToken(self, header_value: str) -> ApiKey:
        """
        Returns the ApiKey if the token is valid, throws an exception otherwise.
        
        :param headerValue: the token from the Authorization header (after the "Bearer ").
            
        :return The ApiKey object
            
        :raise CrossauthError: with code `InvalidKey`
        """
        parts = header_value.split(" ")
        if len(parts) != 2 or parts[0] != self.auth_scheme:
            raise CrossauthError(ErrorCode.InvalidKey, f"Not a {self.auth_scheme} token")
        
        return await self.get_key(parts[1])
