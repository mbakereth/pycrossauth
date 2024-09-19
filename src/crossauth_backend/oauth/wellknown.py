# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from jwcrypto.jwk import JWK
from typing import Literal, TypedDict, NotRequired, Required

from crossauth_backend.common.interfaces import User

type TokenEndpointAuthMethod = Literal["client_secret_post", "client_secret_basic", "client_secret_jwt", "private_key_jwt"]
type ResponseMode = Literal["query", "fragment"]
type GrantType = Literal["authorization_code", "implicit", "client_credentials", "password", "refresh_token", "http://auth0.com/oauth/grant-type/mfa-otp", "http://auth0.com/oauth/grant-type/mfa-oob", "urn:ietf:params:oauth:grant-type:device_code"]
type SubjectType = Literal["pairwise", "public"]
type ClaimType = Literal["normal", "aggregated", "distributed"]


class OpenIdConfiguration(TypedDict):
    """This class encapsulate the data returned by the `oidc-configuration`
    well-known endpoint.  For further details, see the OpenID Connect
    specification.
    """

    issuer : str
    authorization_endpoint: str
    token_endpoint: str
    userinfo_endpoint : NotRequired[str]
    jwks_uri : str
    registration_endpoint : NotRequired[str]
    scopes_supported : NotRequired[list[str]]
    response_types_supported: list[str]
    response_modes_supported: list[ResponseMode]
    grant_types_supported : list[GrantType]
    check_session_iframe : NotRequired[str]
    end_session_endpoint : NotRequired[str]
    acr_values_supported: NotRequired[list[str]]
    subject_types_supported: list[SubjectType]
    id_token_signing_alg_values_supported: list[str]
    id_token_encryption_alg_values_supported : NotRequired[list[str]]
    id_token_encryption_enc_values_supported : NotRequired[list[str]]
    userinfo_signing_alg_values_supported : NotRequired[list[str]]
    userinfo_encryption_alg_values_supported : NotRequired[list[str]]
    userinfo_encryption_enc_values_supported : NotRequired[list[str]]
    request_object_signing_alg_values_supported : NotRequired[list[str]]
    request_object_encryption_alg_values_supported : NotRequired[list[str]]
    request_object_encryption_enc_values_supported : NotRequired[list[str]]
    token_endpoint_auth_methods_supported: NotRequired[list[TokenEndpointAuthMethod]]
    token_endpoint_auth_signing_alg_values_supported : NotRequired[list[str]]
    display_values_supported : NotRequired[list[str]]
    claim_types_supported : NotRequired[list[ClaimType]]
    claims_supported : NotRequired[list[str]]
    service_documentation : NotRequired[str]
    claims_locales_supported : NotRequired[list[str]]
    ui_locales_supported : NotRequired[list[str]]
    claims_parameter_supported : NotRequired[bool]
    request_parameter_supported : NotRequired[bool]
    request_uri_parameter_supported : NotRequired[bool]
    require_request_uri_registration : NotRequired[bool]
    op_policy_uri : NotRequired[str]
    op_tos_uri : NotRequired[str]


class Jwks(TypedDict):
    keys: list[JWK]


DEFAULT_OIDCCONFIG : OpenIdConfiguration = {
    'issuer': "",
    'authorization_endpoint': "",
    'token_endpoint': "",
    'jwks_uri' : "",
    'response_types_supported': [],
    'subject_types_supported' : [],
    'response_modes_supported': ["query", "fragment"],
    'grant_types_supported' : ["authorization_code", "implicit"],
    'id_token_signing_alg_values_supported': [],
    'claim_types_supported' : ["normal"],
    'claims_parameter_supported' : False,
    'request_parameter_supported' : False,
    'request_uri_parameter_supported' : True,
    'require_request_uri_registration' : False,
}
"""
   This is the detault configuration for 
   :class: OAuthAuthorizationServer.
"""

class TokenBodyType(TypedDict, total=False):
    grant_type : Required[str]
    client_id : Required[str]
    scope : str
    code : str
    client_secret : str
    code_verifier : str
    refresh_token : str
    username : str
    password : str
    mfa_token : str
    oobCode : str
    binding_code: str
    otp : str
    device_code : str

class AuthorizeQueryType(TypedDict, total=False):
    response_type : Required[str]
    client_id : str
    redirect_uri : str
    scope : str
    state : str
    code_challenge : str
    code_challenge_method : str
    user : User
