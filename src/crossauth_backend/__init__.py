# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from .common.error import ErrorCode, CrossauthError
from .common.logger import CrossauthLogger, j
from .common.jwt import JWT

from .common.interfaces import Key, PartialKey, \
    UserInputFields, User, \
    UserSecretsInputFields, UserSecrets, UserState, KeyPrefix, ApiKey, \
    PartialUserInputFields, PartialUser, PartialUserSecrets, \
    OAuthClient, PartialOAuthClient, LdapUser

from .oauth.wellknown import TokenEndpointAuthMethod, ResponseMode, \
    GrantType, SubjectType, ClaimType, \
    OpenIdConfiguration, Jwks, DEFAULT_OIDCCONFIG, \
    AuthorizeQueryType, TokenBodyType

from .oauth.tokenconsumer import EncryptionKey, \
    OAuthTokenConsumerOptions, OAuthTokenConsumer

from .utils import set_parameter, ParamType, MapGetter

from .crypto import Crypto, HashOptions

from .storage import UserStorageGetOptions, UserStorageOptions, UserStorage, \
    KeyStorage, KeyDataEntry, \
    OAuthClientStorageOptions, OAuthClientStorage, \
    OAuthAuthorizationStorageOptions, OAuthAuthorizationStorage, UserAndSecrets

from .storageimpl.inmemorystorage import InMemoryKeyStorage, InMemoryUserStorage, \
    InMemoryOAuthClientStorage, InMemoryOAuthAuthorizationStorage
from .storageimpl.sqlalchemystorage import SqlAlchemyKeyStorage, SqlAlchemyKeyStorageOptions, \
    SqlAlchemyUserStorage, SqlAlchemyUserStorageOptions, \
    SqlAlchemyOAuthClientStorage, SqlAlchemyOAuthClientStorageOptions, \
    register_sqlite_datetime
from .storageimpl.ldapstorage import default_create_user_dn, LdapUserStorage, LdapUserStorageOptions

from .cookieauth import DoubleSubmitCsrfToken, DoubleSubmitCsrfTokenOptions, SessionCookie, SessionCookieOptions
from .session import SessionManager, SessionManagerOptions

from .auth import Authenticator, AuthenticationParameters, AuthenticationOptions, AuthenticatorCapabilities, PasswordAuthenticator

from .authenticators.passwordauth import default_password_validator, LocalPasswordAuthenticator, LocalPasswordAuthenticatorOptions
from .authenticators.ldapauth import LdapAuthenticator, LdapAuthenticatorOptions

# Version of realpython-reader package
__version__ = "0.0.9"

__all__ = (
    "ErrorCode", "CrossauthError",
    "CrossauthLogger", "j",
    "JWT",
    "Key", "PartialKey", "KeyDataEntry", "LdapUser",
    "OAuthClient", "PartialOAuthClient",
    "UserInputFields", "User", "UserSecretsInputFields", "UserSecrets", "UserState", "KeyPrefix", "ApiKey",
    "PartialUserInputFields", "PartialUser", "PartialUserSecrets",
    "TokenEndpointAuthMethod", "ResponseMode", "GrantType", "SubjectType", "ClaimType",
    "OpenIdConfiguration", "Jwks", "DEFAULT_OIDCCONFIG", "AuthorizeQueryType", "TokenBodyType",
    "EncryptionKey", "OAuthTokenConsumerOptions", "OAuthTokenConsumer",
    "set_parameter", "ParamType", "MapGetter",
    "Crypto", "HashOptions",
    "UserStorageGetOptions", "UserStorageOptions", "UserStorage", 
    "KeyStorage", 
    "OAuthClientStorageOptions", "OAuthClientStorage", 
    "OAuthAuthorizationStorageOptions", "OAuthAuthorizationStorage",
    "InMemoryKeyStorage", "InMemoryUserStorage", "InMemoryOAuthClientStorage", "InMemoryOAuthAuthorizationStorage",
    "SqlAlchemyKeyStorage", "SqlAlchemyKeyStorageOptions",
    "SqlAlchemyUserStorage", "SqlAlchemyUserStorageOptions",
    "SqlAlchemyOAuthClientStorage", "SqlAlchemyOAuthClientStorageOptions",
    "default_create_user_dn", "LdapUserStorage", "LdapUserStorageOptions",
    "register_sqlite_datetime",
    "DoubleSubmitCsrfToken", "DoubleSubmitCsrfTokenOptions", 
    "SessionCookie", "SessionCookieOptions",
    "SessionManager", "SessionManagerOptions",
    "UserAndSecrets",
    "Authenticator", "AuthenticationParameters", "AuthenticationOptions", "AuthenticatorCapabilities", "PasswordAuthenticator",

    "default_password_validator", "LocalPasswordAuthenticator", "LocalPasswordAuthenticatorOptions",
    "LdapAuthenticator", "LdapAuthenticatorOptions",
)
