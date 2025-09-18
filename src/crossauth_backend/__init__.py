# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file

##### 
# Base
from .common.error import ErrorCode, CrossauthError
from .common.logger import CrossauthLogger, j
from .common.jwt import JWT

#####
# Interfaces
from .common.interfaces import Key, PartialKey, \
    UserInputFields, User, \
    UserSecretsInputFields, UserSecrets, UserState, KeyPrefix, ApiKey, \
    PartialUserInputFields, PartialUser, PartialUserSecrets, \
    OAuthClient, PartialOAuthClient, LdapUser

#####
# OAuth
from .oauth.wellknown import TokenEndpointAuthMethod, ResponseMode, \
    GrantType, SubjectType, ClaimType, \
    OpenIdConfiguration, Jwks, DEFAULT_OIDCCONFIG, \
    AuthorizeQueryType, TokenBodyType

from .oauth.tokenconsumer import EncryptionKey, \
    OAuthTokenConsumerOptions, OAuthTokenConsumer

#####
# Utils
from .utils import set_parameter, ParamType, MapGetter
from .crypto import Crypto, HashOptions

#####
# Storage
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

#####
# Session
from .cookieauth import DoubleSubmitCsrfToken, DoubleSubmitCsrfTokenOptions, SessionCookie, SessionCookieOptions
from .session import SessionManager, SessionManagerOptions

#####
# Auth
from .auth import Authenticator, AuthenticationParameters, AuthenticationOptions, AuthenticatorCapabilities, PasswordAuthenticator

from .authenticators.passwordauth import default_password_validator, LocalPasswordAuthenticator, LocalPasswordAuthenticatorOptions
from .authenticators.ldapauth import LdapAuthenticator, LdapAuthenticatorOptions
from .authenticators.dummyfactor2 import DummyFactor2Authenticator, DummyFactor2AuthenticatorOptions
from .authenticators.emailauth import EmailAuthenticator, EmailAuthenticatorOptions
from .authenticators.smsauth import SmsAuthenticator, SmsAuthenticatorOptions, SMSUser
from .authenticators.dummysmsauth import DummySmsAuthenticator
from .authenticators.oidcauth import OidcAuthenticator, OidcAuthenticatorOptions

# Version of realpython-reader package
__version__ = "0.0.9"

__all__ = (
    #####
    # Base
    "ErrorCode", "CrossauthError",
    "CrossauthLogger", "j",
    "set_parameter", "ParamType", "MapGetter",

    #####
    # Interfaces
    "JWT",
    "Key", "PartialKey", "KeyDataEntry", "LdapUser",
    "OAuthClient", "PartialOAuthClient",
    "UserInputFields", "User", "UserSecretsInputFields", "UserSecrets", "UserState", "KeyPrefix", "ApiKey",
    "PartialUserInputFields", "PartialUser", "PartialUserSecrets",

    #####
    # OAuth
    "TokenEndpointAuthMethod", "ResponseMode", "GrantType", "SubjectType", "ClaimType",
    "OpenIdConfiguration", "Jwks", "DEFAULT_OIDCCONFIG", "AuthorizeQueryType", "TokenBodyType",
    "EncryptionKey", "OAuthTokenConsumerOptions", "OAuthTokenConsumer",

    #####
    # Utils
    "Crypto", "HashOptions",

    #####
    # Storage
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

    #####
    # Session
    "DoubleSubmitCsrfToken", "DoubleSubmitCsrfTokenOptions", 
    "SessionCookie", "SessionCookieOptions",
    "SessionManager", "SessionManagerOptions",
    "UserAndSecrets",

    #####
    # Auth
    "Authenticator", "AuthenticationParameters", "AuthenticationOptions", "AuthenticatorCapabilities", "PasswordAuthenticator",
    "default_password_validator", "LocalPasswordAuthenticator", "LocalPasswordAuthenticatorOptions",
    "LdapAuthenticator", "LdapAuthenticatorOptions",
    "DummyFactor2Authenticator", "DummyFactor2AuthenticatorOptions",
    "EmailAuthenticator", "EmailAuthenticatorOptions",
    "SmsAuthenticator", "SmsAuthenticatorOptions", "SMSUser",
    "DummySmsAuthenticator",
    "OidcAuthenticator", "OidcAuthenticatorOptions",
)
