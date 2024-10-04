# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import TypedDict, Required, List, NamedTuple
from nulltype import NullType
import urllib.parse
from crossauth_backend.storage import OAuthClientStorage
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.common.interfaces import OAuthClient
from crossauth_backend.oauth.client import OAuthFlows
from crossauth_backend.crypto import Crypto

CLIENT_ID_LENGTH = 16
CLIENT_SECRET_LENGTH = 32

class UpdateClientReturn(NamedTuple):
    client: OAuthClient
    new_secret: bool

class OAuthClientManagerOptions(TypedDict, total=False):
    """ Options for :class:`OAuthClientManager` """

    oauth_pbkdf2digest : str
    """ PBKDF2 HMAC for hashing client secret """

    oauth_pbkdf2iterations : int
    """ PBKDF2 iterations for hashing client secret """

    oauth_pbkdf2key_length : int
    """ PBKDF2 key length for hashing client secret """

    client_storage : Required[OAuthClientStorage]
    """ Database for storage clients """

class OAuthClientManager:

    def __init__(self, options: OAuthClientManagerOptions):
        if not options["client_storage"]:
            raise CrossauthError(ErrorCode.Configuration,
                "Must specify client_storage when adding a client manager")
        self.__client_storage = options["client_storage"]

        self.__oauth_pbkdf2_digest = "sha256"
        self.__oauth_pbkdf2_iterations = 40000
        self.__oauth_pbkdf2_key_length = 32

        set_parameter("oauth_pbkdf2_digest", ParamType.String, self, options, "OAUTH_PBKDF2_DIGEST")
        set_parameter("oauth_pbkdf2_key_length", ParamType.String, self, options, "OAUTH_PBKDF2_KEYLENGTH")
        set_parameter("require_redirect_uri_registration", ParamType.Boolean, self, options, "OAUTH_REQUIRE_REDIRECT_URI_REGISTRATION")

    async def create_client(self, client_name: str,
                            redirect_uri: List[str],
                            valid_flow: List[str]|None = None,
                            confidential: bool = True,
                            userid: str|int|None = None) -> OAuthClient:
        client_id = OAuthClientManager.random_client_id()
        client_secret = None
        plaintext = None
        if confidential:
            plaintext = OAuthClientManager.random_client_secret()
            client_secret = await Crypto.password_hash(plaintext, {
                "encode": True,
                "iterations": self.__oauth_pbkdf2_iterations,
                "key_len": self.__oauth_pbkdf2_key_length,
                "digest": self.__oauth_pbkdf2_digest,
            })
        
        for uri in redirect_uri:
            OAuthClientManager.validate_uri(uri)
        
        if not valid_flow:
            valid_flow = OAuthFlows.all_flows()
        
        client : OAuthClient = {
            "client_id": client_id,
            "client_name": client_name,
            "redirect_uri": redirect_uri,
            "confidential": confidential,
            "valid_flow": valid_flow,
        }
        if (userid is not None): client["userid"] = userid
        if (client_secret is not None): client["client_secret"] = client_secret
        
        new_client = None
        for try_num in range(5):
            try:
                new_client = await self.__client_storage.create_client(client)
                break
            except Exception as e:
                if try_num == 4:
                    ce = CrossauthError.as_crossauth_error(e)
                    if ce.code != ErrorCode.ClientExists:
                        raise e
                else:
                    client["client_id"] = OAuthClientManager.random_client_id()
        
        if not new_client:
            raise CrossauthError(ErrorCode.ClientExists)
        if "client_secret" in new_client and type(new_client["client_secret"]) is not NullType and plaintext:
            new_client["client_secret"] = plaintext
        return new_client

    async def update_client(self, client_id: str,
                            client: OAuthClient,
                            reset_secret: bool = False) -> UpdateClientReturn:
        old_client = await self.__client_storage.get_client_by_id(client_id)
        new_secret = False
        plaintext = None
        if (client.get("confidential") is True and not old_client["confidential"]) or \
           (client.get("confidential") is True and reset_secret):
            plaintext = OAuthClientManager.random_client_secret()
            client["client_secret"] = await Crypto.password_hash(plaintext, {
                "encode": True,
                "iterations": self.__oauth_pbkdf2_iterations,
                "key_len": self.__oauth_pbkdf2_key_length,
                "digest": self.__oauth_pbkdf2_digest,
            })
            new_secret = True
        elif client.get("confidential") is False and "client_secret" in client:
            del client["client_secret"]
        
        if "redirect_uri" in client:
            for uri in client["redirect_uri"]:
                OAuthClientManager.validate_uri(uri)
        
        client["client_id"] = client_id
        await self.__client_storage.update_client(client)
        new_client = await self.__client_storage.get_client_by_id(client_id)
        if plaintext:
            new_client["client_secret"] = plaintext
        return UpdateClientReturn(client, new_secret)

    @staticmethod
    def random_client_id() -> str:
        return Crypto.random_value(CLIENT_ID_LENGTH)

    @staticmethod
    def random_client_secret() -> str:
        return Crypto.random_value(CLIENT_SECRET_LENGTH)

    @staticmethod
    def validate_uri(uri: str):
        valid = False
        try:
            valid_uri = urllib.parse.urlparse(uri)
            valid = not valid_uri.fragment
        except:
            # test if it's a valid relative url
            try:
                valid_uri = urllib.parse.urlparse(uri, scheme="http")
                valid = not valid_uri.fragment
            except Exception as e2:
                CrossauthLogger.logger().debug(j({"err": e2}))
        
        if not valid:
            raise CrossauthError.from_oauth_error("invalid_request", 
                f"Invalid redirect Uri {uri}")
