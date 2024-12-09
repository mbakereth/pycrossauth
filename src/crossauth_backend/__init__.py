# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from .common.error import ErrorCode, CrossauthError
from .common.logger import CrossauthLogger, j
from .common.jwt import JWT

from .common.interfaces import Key, PartialKey, \
    UserInputFields, User, \
    UserSecretsInputFields, UserSecrets, UserState, KeyPrefix, ApiKey, \
    PartialUserInputFields, PartialUser, PartialUserSecrets

from .oauth.wellknown import TokenEndpointAuthMethod, ResponseMode, \
    GrantType, SubjectType, ClaimType, \
    OpenIdConfiguration, Jwks, DEFAULT_OIDCCONFIG, \
    AuthorizeQueryType, TokenBodyType

from .oauth.tokenconsumer import EncryptionKey, \
    OAuthTokenConsumerOptions, OAuthTokenConsumer

from .utils import set_parameter, ParamType, MapGetter

from .crypto import Crypto

from .storage import UserStorageGetOptions, UserStorageOptions, UserStorage, \
    KeyStorage, KeyDataEntry, \
    OAuthClientStorageOptions, OAuthClientStorage, \
    OAuthAuthorizationStorageOptions, OAuthAuthorizationStorage, UserAndSecrets

from .storageimpl.inmemorystorage import InMemoryKeyStorage
from .storageimpl.sqlalchemystorage import SqlAlchemyKeyStorage, SqlAlchemyKeyStorageOptions

from .cookieauth import DoubleSubmitCsrfToken, DoubleSubmitCsrfTokenOptions, SessionCookie, SessionCookieOptions
from .session import SessionManager, SessionManagerOptions

# Version of realpython-reader package
__version__ = "0.0.3"

__all__ = (
    "ErrorCode", "CrossauthError",
    "CrossauthLogger", "j",
    "JWT",
    "Key", "PartialKey", "KeyDataEntry", \
    "UserInputFields", "User", "UserSecretsInputFields", "UserSecrets", "UserState", "KeyPrefix", "ApiKey",
    "PartialUserInputFields", "PartialUser", "PartialUserSecrets",
    "TokenEndpointAuthMethod", "ResponseMode", "GrantType", "SubjectType", "ClaimType",
    "OpenIdConfiguration", "Jwks", "DEFAULT_OIDCCONFIG", "AuthorizeQueryType", "TokenBodyType",
    "EncryptionKey", "OAuthTokenConsumerOptions", "OAuthTokenConsumer",
    "set_parameter", "ParamType", "MapGetter",
    "Crypto",
    "UserStorageGetOptions", "UserStorageOptions", "UserStorage", 
    "KeyStorage", 
    "OAuthClientStorageOptions", "OAuthClientStorage", 
    "OAuthAuthorizationStorageOptions", "OAuthAuthorizationStorage",
    "InMemoryKeyStorage",
    "SqlAlchemyKeyStorage", "SqlAlchemyKeyStorageOptions",
    "DoubleSubmitCsrfToken", "DoubleSubmitCsrfTokenOptions", 
    "SessionCookie", "SessionCookieOptions",
    "SessionManager", "SessionManagerOptions",
    "UserAndSecrets"
)
