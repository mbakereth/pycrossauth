# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.utils import set_parameter, ParamType, MapGetter
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.oauth.wellknown import OpenIdConfiguration, TokenBodyType
from crossauth_backend.oauth.tokenconsumer import OAuthTokenConsumer, OAuthTokenConsumerOptions
from crossauth_backend.crypto import Crypto

from typing import Dict, List, Optional, TypedDict, Any, Literal, Mapping, cast
import json
import urllib.parse
from abc import abstractmethod
import requests
from urllib.parse import urlparse
from jwt import (
    JWT
)
import aiohttp

class OAuthFlows:
    """
    Crossauth allows you to define which flows are valid for a given client.
    """

    All = "all"
    """ All flows are allowed """

    AuthorizationCode = "authorizationCode"
    """ OAuth authorization code flow (without PKCE) """

    AuthorizationCodeWithPKCE = "authorizationCodeWithPKCE"
    """ OAuth authorization code flow with PKCE """

    ClientCredentials = "clientCredentials"
    """ Auth client credentials flow """

    RefreshToken = "refresh_token"
    """ OAuth refresh token flow """

    DeviceCode = "device_code"
    """ OAuth device code flow """

    Password = "password"
    """ OAuth password flow """

    PasswordMfa = "passwordMfa"
    """ The Auth0 password MFA extension to the password flow """

    OidcAuthorizationCode = "oidcAuthorizationCode"
    """ The OpenID Connect authorization code flow, with or without PKCE """

    flow_name = {
        AuthorizationCode: "Authorization Code",
        AuthorizationCodeWithPKCE: "Authorization Code with PKCE",
        ClientCredentials: "Client Credentials",
        RefreshToken: "Refresh Token",
        DeviceCode: "Device Code",
        Password: "Password",
        PasswordMfa: "Password MFA",
        OidcAuthorizationCode: "OIDC Authorization Code",
    }
    """ A user friendly name for the given flow ID """

    @staticmethod
    def flow_names(flows: List[str]) -> Dict[str, str]:
        """
        Returns a user-friendly name for the given flow strs.

        The value returned is the one in `flow_name`.
        :param List[str] flows: the flows to return the names of

        :return: a dictionary of strs
        """

        return {flow: OAuthFlows.flow_name[flow] for flow in flows if flow in OAuthFlows.flow_name}

    @staticmethod
    def is_valid_flow(flow: str) -> bool:
        """
        Returns true if the given str is a valid flow name.
        :param str flow: the flow to check

        :return: true or false.
        """

        return flow in OAuthFlows.all_flows()

    @staticmethod
    def are_valid_flows(flows: List[str]) -> bool:
        """
        Returns true only if all given strs are valid flows
        :param List[str] flows: the flows to check

        :return: true or false.
        """

        return all(OAuthFlows.is_valid_flow(flow) for flow in flows)

    @staticmethod
    def all_flows() -> List[str]:
        """ Returns a lsit of all possible OAuth flows """

        return [
            OAuthFlows.AuthorizationCode,
            OAuthFlows.AuthorizationCodeWithPKCE,
            OAuthFlows.ClientCredentials,
            OAuthFlows.RefreshToken,
            OAuthFlows.DeviceCode,
            OAuthFlows.Password,
            OAuthFlows.PasswordMfa,
            OAuthFlows.OidcAuthorizationCode,
        ]

    @staticmethod
    def grant_type(oauthFlow: str) -> Optional[List[str]]:
        """
        Returns the OAuth grant types that are valid for a given flow, or
        `None` if it is not a valid flow.
        :param str oauthFlow: the flow to get the grant type for.

        :return: a list of grant type strs or None
        """

        match oauthFlow:
            case  OAuthFlows.AuthorizationCode: 
                return ["authorization_code"]
            case OAuthFlows.AuthorizationCodeWithPKCE: 
                return ["authorization_code"]
            case OAuthFlows.OidcAuthorizationCode: 
                return ["authorization_code"]
            case OAuthFlows.ClientCredentials: 
                return ["client_credentials"]
            case OAuthFlows.RefreshToken: 
                return ["refresh_token"]
            case OAuthFlows.Password: 
                return ["password"]
            case OAuthFlows.PasswordMfa: 
                return ["http://auth0.com/oauth/grant-type/mfa-otp", "http://auth0.com/oauth/grant-type/mfa-oob"]
            case OAuthFlows.DeviceCode: 
                return ["urn:ietf:params:oauth:grant-type:device_code"]
            case _:
                raise CrossauthError(ErrorCode.BadRequest, "Invalid OAuth flow " + oauthFlow)

class IdTokenReturn(TypedDict, total=False):
    id_payload: Mapping[str, Any]
    error: str
    error_description: str

class OAuthTokenResponse(TypedDict, total=False):
    """
    These are the fields that can be returned in the JSON from an OAuth call.
    """

    access_token : str
    refresh_token : str
    id_token : str
    id_payload : Mapping[str, Any]
    token_type : str
    expires_in : int
    error : str
    error_description : str
    scope : str
    mfa_token : str
    oob_channel : str
    oob_code : str
    challenge_type : str
    binding_method : str
    name : str

class OAuthMfaAuthenticator(TypedDict, total=False):
    authenticator_type: str
    id : str
    active: bool
    oob_channel : str
    name: str
    error: str
    error_description: str

class OAuthMfaAuthenticatorsResponse(TypedDict, total=False):
    authenticators: List[OAuthMfaAuthenticator]
    error : str
    error_description: str

class OAuthMfaAuthenticatorsOrTokenResponse(OAuthMfaAuthenticatorsResponse, OAuthTokenResponse, total=False):
    pass

class OAuthMfaChallengeResponse(TypedDict, total=False):
    challenge_type: str
    oob_code: str
    binding_method: str
    error : str
    error_description: str

class OAuthDeviceAuthorizationResponse(TypedDict, total=False):
    """
    These are the fields that can be returned in the device_authorization
    device code flow endpoint.
    """

    device_code : str
    user_code : str
    verification_uri : str
    verification_uri_complete : str
    expires_in : str
    interval : str
    error : str
    error_description : str

class OAuthDeviceResponse(TypedDict, total=False):
    """
    These are the fields that can be returned in the device
    device code flow endpoint.
    """

    client_id : str
    scope_authorization_needed : bool
    scope : str
    error : str
    error_description : str

class OAuthClientOptions(OAuthTokenConsumerOptions, total=False):
    """ Options for :class: OAuthClientBase """

    state_length : int
    """ Length of random state variable for passing to `authorize` endpoint
        (before bsae64-url-encoding)
    """

    verifier_length : int
    """ Length of random code verifier to generate 
        (before bsae64-url-encoding) 
    """

    client_id : str
    """
        Client ID for this client
    """

    client_secret : str
    """
        Client secret for this client (can be undefined for no secret)
    """

    redirect_uri : str
    """
        Redirect URI to send in `authorize` requests
    """

    code_challenge_method : Literal["plain",  "S256"]
    """
        Type of code challenge for PKCE
    """

    device_authorization_url : str
    """
        URL to call for the device_authorization endpoint, relative to
        the `auth_server_base_url`.
        
        Default `device_authorization`
    """

    oauth_post_type : Literal["json", "form"]
    """
        If set to JSON, make calls to the token endpoint as JSON, otherwise
        as x-www-form-urlencoded.
    """

    oauth_use_user_info_endpoint : bool
    """
    If your authorization server only returns certain claims in the userinfo
    endpoint, rather than in the id token, set this to true
    """

    oauth_authorize_redirect : str|None
    """
    In the special case where you are running this in Docker on a private
    machine, the client cannot redirect to the authorization endpoint given
    in the OIDC configuration.  You will typically set the auth_server_base_url
    to the name of the docker host in this case, and set 
    oauth_authorize_redirect to localhost.
    Default None
    """

class OAuthClient:
    """
    Base class for OAuth clients.

    Flows supported are Authorization Code Flow with and without PKCE,
    Client Credentials, Refresh Token, Password and Password MFA.  The
    latter is defined at
    [auth0.com](https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors).

    It also supports the OpenID Connect Authorization Code Flow, with and 
    without PKCE.
    """

    def __init__(self, auth_server_base_url : str, options : OAuthClientOptions):
        """
        Constructor.
        
        Args:
        :param str auth_server_base_url: bsae URL for the authorization server
              expected to issue access tokens.  If the `iss` field in a JWT
              does not match this, it is rejected.
        :param crossauth_backend.OAuthClientOptions options: see :class: OAuthClientOptions

        """

        self._verifier_length = 32
        self._state_length = 32
        self._client_id : str = ""
        self._client_secret : str|None = None
        self._redirect_uri : str|None = None
        self._code_challenge_method : Literal["plain", "S256"] = "S256"
        self._auth_server_credentials : Literal["include", "omit", "same-origin" ] | None = None
        self._auth_server_mode : Literal["no-cors", "cors", "same-origin" ] | None = None
        self._auth_server_headers : Dict[str, str] = {}
        self._authz_code = ""
        self._oidc_config : OpenIdConfiguration | None = None
        self._device_authorization_url : str = "device_authorization"
        self._oauth_post_type = "json"
        self._oauth_use_user_info_endpoint = False
        self._oauth_authorize_redirect : str|None = None

        self.auth_server_base_url = auth_server_base_url
        set_parameter("client_id", ParamType.String, self, options, "OAUTH_CLIENT_ID", required=True, protected=True)
        set_parameter("client_secret", ParamType.String, self, options, "OAUTH_CLIENT_SECRET", protected=True)
        set_parameter("redirect_uri", ParamType.String, self, options, "OAUTH_REDIRECT_URI", protected=True)

        self._token_consumer = OAuthTokenConsumer(self._client_id, {"auth_server_base_url": auth_server_base_url, **options})
        set_parameter("state_length", ParamType.String, self, options, "OAUTH_STATE_LENGTH", protected=True)
        set_parameter("verifier_length", ParamType.String, self, options, "OAUTH_VERIFIER_LENGTH", protected=True)
        set_parameter("client_secret", ParamType.String, self, options, "OAUTH_CLIENT_SECRET", protected=True)
        set_parameter("code_challenge_method", ParamType.String, self, options, "OAUTH_CODE_CHALLENGE_METHOD", protected=True)
        set_parameter("device_authorization_url", ParamType.String, self, options, "OAUTH_DEVICE_AUTHORIZATION_URL", protected=True)
        set_parameter("auth_server_credentials", ParamType.String, self, options, "OAUTH_AUTH_SERVER_CREDENTIALS", protected=True)
        set_parameter("auth_server_mode", ParamType.String, self, options, "OAUTH_AUTH_SERVER_MODE", protected=True)
        set_parameter("auth_server_headers", ParamType.Json, self, options, "OAUTH_AUTH_SERVER_HEADERS", protected=True)
        if (self._device_authorization_url[0:1] == "/"): self._device_authorization_url = self._device_authorization_url[1:]
        set_parameter("oauth_post_type", ParamType.Json, self, options, "OAUTH_POST_TYPE", protected=True)
        if (self._oauth_post_type != "json" and self._oauth_post_type != "form"):
            raise CrossauthError(ErrorCode.Configuration, "oauth_post_type must be json or form")
        set_parameter("oauth_use_user_info_endpoint", ParamType.Json, self, options, "OAUTH_USE_USER_INFO_ENDPOINT", protected=True)
        set_parameter("oauth_authorize_redirect", ParamType.String, self, options, "OAUTH_AUTHORIZE_REDIRECT", protected=True)

    async def load_config(self, oidc_config : OpenIdConfiguration|None=None):
        """
        Loads OpenID Connect configuration so that the client can determine
        the URLs it can call and the features the authorization server provides.
        
        :param oidc_config if defined, loadsa the config from this object.
            Otherwise, performs a fetch by appending
            `/.well-known/openid-configuration` to the 
            `auth_server_base_url`.
        :throws :class: crossauth_backend.CrossauthError} with the following 
           :attr: crossauth_backend.ErrorCode.Connection if data from the URL 
                  could not be fetched or parsed.
        """

        if oidc_config:
            CrossauthLogger.logger().debug(j({"msg": "Reading OIDC config locally"}))
            self._oidc_config = oidc_config
            return

        url = f"{self.auth_server_base_url}/.well-known/openid-configuration"
        urlparse(url)
        CrossauthLogger.logger().debug(j({"msg": f"Fetching OIDC config from {url}"}))
        headers = self._auth_server_headers
        options : Dict[str, Any] = {"headers": headers}
        if self._auth_server_mode is not None:
            options["mode"] = self._auth_server_mode
        if self._auth_server_credentials:
            options["credentials"] = self._auth_server_credentials

        try:
            async with aiohttp.ClientSession() as session:
                response = await session.get(url, **options)
                response.raise_for_status()
        except requests.RequestException as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            raise Exception("Couldn't get OIDC configuration from URL")

        self._oidc_config : OpenIdConfiguration | None= None
        try:
            body : Mapping[str,str] = await response.json()
            self._oidc_config = {**(cast(OpenIdConfiguration, body))}
        except json.JSONDecodeError:
            raise Exception("Unrecognized response from OIDC configuration endpoint")

    def get_oidc_config(self):
        return self._oidc_config

    @abstractmethod
    def random_value(self, length : int) -> str:
        """
        Produce a random Base64-url-encoded str, whose length before 
        base64-url-encoding is the given length,
        @param length the length of the random array before base64-url-encoding.
        @returns the random value as a Base64-url-encoded srting
        """

        return Crypto.random_value(length);

    @abstractmethod
    async def sha256(self, plaintext : str) -> str:
        """
        SHA256 and Base64-url-encodes the given test
        @param plaintext the text to encode
        @returns the SHA256 hash, Base64-url-encode
        """

        return Crypto.sha256(plaintext)

    async def code_challenge_and_verifier(self):
        code_verifier = self.random_value(self._verifier_length)
        code_challenge = await self.sha256(code_verifier) if self._code_challenge_method == "S256" else code_verifier
        return {"code_verifier": code_verifier, "code_challenge": code_challenge}
    

    async def start_authorization_code_flow(self, state: str, scope : str | None = None, code_challenge: str|None = None, pkce : bool = False):
        """
        Initiates the authorization code flow

        :param str|None scope:, which can be None
        :param bool pkce: if True, start the flow with PKCE (for public clients). Default False

        """

        CrossauthLogger.logger().debug(j({"msg": "Starting authorization code flow"}))
        if self._oidc_config is None:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't load OIDC Configuration")
        if "code" not in self._oidc_config["response_types_supported"] or not "query" in self._oidc_config["response_modes_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support authorization code flow"
            }
        if not self._oidc_config.get("authorization_endpoint"):
            return {
                "error": "server_error",
                "error_description": "Cannot get authorize endpoint"
            }
        if not self._client_id:
            return {
                "error": "invalid_request",
                "error_description": "Cannot make authorization code flow without client id"
            }
        if not self._redirect_uri:
            return {
                "error": "invalid_request",
                "error_description": "Cannot make authorization code flow without Redirect Uri"
            }

        base = self._oidc_config["authorization_endpoint"]
        if (self._oauth_authorize_redirect):
            base = self._oauth_authorize_redirect
        url = f"{base}?response_type=code&client_id={urllib.parse.quote(self._client_id)}&state={urllib.parse.quote(state)}&redirect_uri={urllib.parse.quote(self._redirect_uri)}"

        if scope:
            url += f"&scope={urllib.parse.quote(scope)}"

        if pkce:
            url += f"&code_challenge={code_challenge}"

        return {"url": url}

    async def redirect_endpoint(self, code : str|None = None, state : str|None = None, code_verifier: str|None = None, error : str|None =None, error_description : str|None=None) -> OAuthTokenResponse:
        """
        For calling in a Redirect Uri endpoint

        :param str|None code: the authorization code 
        :param str|None the state, if one is used by the authorization server
        :param str|None any error: error message returned by the authorization server.  It is passed through in the returned value
        :param str|None any error_description: error description returned by the authorization server.  It is passed through in the returned value

        :return: an OAuth token endpoint response
        """

        if not self._oidc_config: 
            await self.load_config()
        if (not self._oidc_config):
            return {"error": "server_error", "error_description": "Couldn't load OIDC configuration"}
        if error is not None or not code:
            if error is None:
                error = "server_error"
            if error_description is None:
                error_description = "Unknown error"
            return {"error": error, "error_description": error_description}
        self.authzCode = code

        if "authorization_code" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support authorization code grant"
            }
        if not self._oidc_config.get("token_endpoint"):
            return {
                "error": "server_error",
                "error_description": "Cannot get token endpoint"
            }
        url = self._oidc_config["token_endpoint"]

        grant_type = "authorization_code"
        client_secret = self._client_secret
        params : Dict[str, Any]= {
            "grant_type": grant_type,
            "client_id": self._client_id,
            "code": self.authzCode,
        }
        if client_secret:
            params["client_secret"] = client_secret
        params["code_verifier"] = code_verifier
        try:
            ret = cast(OAuthTokenResponse, await self._post(url, params, self._auth_server_headers)) 
            if ("id_token" in ret):
                access_token : str|None = None
                if "access_token" in ret:
                    access_token = ret["access_token"]
                user_info = await self._get_id_payload(ret["id_token"], access_token)
                error1 : str|None = user_info["error"] if "error" in user_info else None
                error_description1 : str|None = user_info["error_description"] if "error_description" in user_info else ""
                if (error1 is not None):
                    return {
                        "error": error1,
                        "error_description": error_description1
                    }
                if ("id_payload" in user_info):
                    ret["id_payload"] = user_info["id_payload"]
            
            return ret
        except Exception as e:
            CrossauthLogger.logger().error(j({"cerr": e}))
            CrossauthLogger.logger().debug(j({"err": e}))
            return {
                "error": "server_error",
                "error_description": "Unable to get access token from server"
            }

    async def client_credentials_flow(self, scope : str|None = None) -> OAuthTokenResponse:
        """
        Start the client credentials flow

        :param str|None scope:, which can be None

        :return: an OAuth token endpoint response
        """

        CrossauthLogger.logger().debug(j({"msg": "Starting client credentials flow"}))
        if not self._oidc_config: 
            await self.load_config()
        if self._oidc_config is None or self._oidc_config["token_endpoint"] == "":
            return {"error": "server_error", "error_description": "Cannot get token endpoint"}
        if "client_credentials" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support client credentials grant"
            }
        if self._client_id == "":
            return {
                "error": "invalid_request",
                "error_description": "Cannot make client credentials flow without client id"
            }

        url = self._oidc_config["token_endpoint"]

        params : TokenBodyType = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
        }
        if self._client_secret is not None: 
            params["client_secret"] = self._client_secret

        if scope:
            params["scope"] = scope
        try:
            ret = cast(OAuthTokenResponse, await self._post(url, params, self._auth_server_headers)) 
            if ("id_token" in ret):
                access_token : str|None = None
                if "access_token" in ret:
                    access_token = ret["access_token"]
                user_info = await self._get_id_payload(ret["id_token"], access_token)
                error1 : str|None = user_info["error"] if "error" in user_info else None
                error_description1 : str|None = user_info["error_description"] if "error_description" in user_info else ""
                if (error1 is not None):
                    return {
                        "error": error1,
                        "error_description": error_description1
                    }
                if ("id_payload" in user_info):
                    ret["id_payload"] = user_info["id_payload"]
            return ret
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Error connecting to authorization server"
            }

    async def password_flow(self, username : str, password : str, scope : str|None = None)  -> OAuthTokenResponse:
        """
        Start the password flow

        :param str username:, user's username
        :param str password:, user's plaintext password
        :param str|None scope:, which can be None

        :return: an OAuth token endpoint response
        """

        CrossauthLogger.logger().debug(j({"msg": "Starting password flow"}))
        if not self._oidc_config:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")
        if "password" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support password grant"
            }
        if not self._oidc_config.get("token_endpoint"):
            return {
                "error": "server_error",
                "error_description": "Cannot get token endpoint"
            }

        url = self._oidc_config["token_endpoint"]

        params : TokenBodyType = {
            "grant_type": "password",
            "client_id": self._client_id,
            "username": username,
            "password": password,
        }
        if (self._client_secret is not None):
            params["client_secret"] = self._client_secret

        if scope:
            params["scope"] = scope
        try:
            ret = cast(OAuthTokenResponse, await self._post(url, params, self._auth_server_headers))
            if ("id_token" in ret):
                access_token : str|None = None
                if "access_token" in ret:
                    access_token = ret["access_token"]
                user_info = await self._get_id_payload(ret["id_token"], access_token)
                error1 : str|None = user_info["error"] if "error" in user_info else None
                error_description1 : str|None = user_info["error_description"] if "error_description" in user_info else ""
                if (error1 is not None):
                    return {
                        "error": error1,
                        "error_description": error_description1
                    }
                if ("id_payload" in user_info):
                    ret["id_payload"] = user_info["id_payload"]
            return ret
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Error connecting to authorization server"
            }

    async def mfa_authenticators(self, mfa_token: str) -> OAuthMfaAuthenticatorsResponse :
        """
        Fields that canb be returned by the `mfaAuthenticators` function call
        See Auth0's documentation for the password MFA flow.

        :param str mfa_token:, The MFA token returned when the flow was initiated

        :return: See :class:`OAuthMfaAuthenticatorsResponse`
        """

        CrossauthLogger.logger().debug(j({"msg": "Getting valid MFA authenticators"}))
        if self._oidc_config is None:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")

        if "http://auth0.com/oauth/grant-type/mfa-otp" not in self._oidc_config["grant_types_supported"] and \
           "http://auth0.com/oauth/grant-type/mfa-oob" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support password_mfa grant"
            }
        if not self._oidc_config.get("issuer"):
            return {"error": "server_error", "error_description": "Cannot get issuer"}

        url = f"{self._oidc_config['issuer']}/mfa/authenticators" if self._oidc_config['issuer'].endswith("/") else f"{self._oidc_config['issuer']}/mfa/authenticators"
        resp = await self._get(url, {'authorization': f'Bearer {mfa_token}', **self._auth_server_headers})
        if not isinstance(resp, list):
            return {
                "error": "server_error",
                "error_description": "Expected array of authenticators in mfa/authenticators response"
            }
        authenticators : List[OAuthMfaAuthenticator] = []
        for authenticator in resp:
            if not authenticator.get("id") or not authenticator.get("authenticator_type") or not authenticator.get("active"):
                return {
                    "error": "server_error",
                    "error_description": "Invalid mfa/authenticators response"
                }
            authenticators.append({
                "id": authenticator["id"],
                "authenticator_type": authenticator["authenticator_type"],
                "active": authenticator["active"],
                "name": authenticator.get("name"),
                "oob_channel": authenticator.get("oob_channel"),
            })
        return {"authenticators": authenticators}

    async def mfa_otp_request(self, mfa_token: str, authenticator_id: str) -> OAuthMfaChallengeResponse:
        """
        This is part of the Auth0 Password MFA flow.  Once the client has
        received a list of valid authenticators, if it wishes to initiate
        OTP, call this function
        
        Does not throw exceptions.
        
        :param str mfa_token: the MFA token that was returned by the authorization
            server in the response from the Password Flow.
        :param str authenticator_id: the authenticator ID, as returned in the response
        from the :func:`mfaAuthenticators` request.
        """

        CrossauthLogger.logger().debug(j({"msg": "Making MFA OTB request"}))
        if not self._oidc_config:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")
        if "http://auth0.com/oauth/grant-type/mfa-otp" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support password_mfa grant"
            }
        if not self._oidc_config.get("issuer"):
            return {"error": "server_error", "error_description": "Cannot get issuer"}

        url = f"{self._oidc_config['issuer']}/mfa/challenge" if self._oidc_config['issuer'].endswith("/") else f"{self._oidc_config['issuer']}/mfa/challenge"
        resp = await self._post(url, {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "challenge_type": "otp",
            "mfa_token": mfa_token,
            "authenticator_id": authenticator_id,
        }, self._auth_server_headers)
        if resp.get("challenge_type") != "otp":
            return {
                "error": resp.get("error", "server_error"),
                "error_description": resp.get("error_description", "Invalid OTP challenge response")
            }

        return cast(OAuthMfaChallengeResponse, resp) 

    async def mfa_otp_complete(self, mfa_token: str, otp: str, scope: Optional[str] = None) -> OAuthTokenResponse:
        """
        Completes the Password MFA OTP flow.

        :param str mfa_token: the MFA token that was returned by the authorization
               server in the response from the Password Flow.
        :param str otp: the OTP entered by the user

        :return: an object with some of the following fields, depending on
                 authorization server configuration and whether there were
                 errors:
          - `access_token` an OAuth access token
          - `refresh_token` an OAuth access token
          - `id_token` an OpenID Connect ID token
          - `expires_in` number of seconds when the access token expires
          - `scope` the scopes the user authorized
          - `token_type` the OAuth token type
          - `error` as per Auth0 Password MFA documentation
          - `error_description` friendly error message
        """

        CrossauthLogger.logger().debug(j({"msg": "Completing MFA OTP request"}))
        if self._oidc_config is None:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")
        if "http://auth0.com/oauth/grant-type/mfa-otp" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support password_mfa grant"
            }
        if not self._oidc_config.get("issuer"):
            return {"error": "server_error", "error_description": "Cannot get issuer"}

        otpUrl = self._oidc_config["token_endpoint"]
        otpResp = await self._post(otpUrl, {
            "grant_type": "http://auth0.com/oauth/grant-type/mfa-otp",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "challenge_type": "otp",
            "mfa_token": mfa_token,
            "otp": otp,
            "scope": scope,
        }, self._auth_server_headers)
        id_token : Mapping[str,Any]|None = None
        if ("id_token" in otpResp):
            access_token : str|None = None
            if "access_token" in otpResp:
                access_token = otpResp["access_token"]
            user_info = await self._get_id_payload(otpResp["id_token"], access_token)
            error1 : str|None = user_info["error"] if "error" in user_info else None
            error_description1 : str|None = user_info["error_description"] if "error_description" in user_info else ""
            if (error1 is not None):
                return {
                    "error": error1,
                    "error_description": error_description1
                }
            if ("id_payload" in user_info):
                id_token = user_info["id_payload"]
        ret = cast(OAuthTokenResponse, {
            "id_token": otpResp.get("id_token"),
            "access_token": otpResp.get("access_token"),
            "refresh_token": otpResp.get("refresh_token"),
            "expires_in": int(otpResp.get("expires_in", 0)),
            "scope": otpResp.get("scope"),
            "token_type": otpResp.get("token_type"),
            "error": otpResp.get("error"),
            "error_description": otpResp.get("error_description"),
        })
        if (id_token is not None):
            ret["id_payload"] = id_token
        return ret

    async def mfa_oob_request(self, mfa_token: str, authenticator_id: str) -> OAuthMfaAuthenticatorsResponse:
        """
        This is part of the Auth0 Password MFA flow.  Once the client has
        received a list of valid authenticators, if it wishes to initiate
        OOB (out of band) login, call this function
        
        Does not throw exceptions.
        
        :param str mfa_token: the MFA token that was returned by the authorization
               server in the response from the Password Flow.
        :param str authenticator_id: the authenticator ID, as returned in the response
        from the :func:`mfa_authenticators` request.

        :return: an object with one or more of the following defined:
          - `challenge_type` as per the Auth0 MFA documentation
          - `oob_code` as per the Auth0 MFA documentation
          - `binding_method` as per the Auth0 MFA documentation
          - `error` as per Auth0 Password MFA documentation
          - `error_description` friendly error message
        """

        CrossauthLogger.logger().debug(j({"msg": "Making MFA OOB request"}))
        if self._oidc_config is None:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")
        if "http://auth0.com/oauth/grant-type/mfa-otp" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support password_mfa grant"
            }
        if not self._oidc_config.get("issuer"):
            return {"error": "server_error", "error_description": "Cannot get issuer"}

        url = f"{self._oidc_config['issuer']}/mfa/challenge" if self._oidc_config['issuer'].endswith("/") else f"{self._oidc_config['issuer']}/mfa/challenge"
        resp = await self._post(url, {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "challenge_type": "oob",
            "mfa_token": mfa_token,
            "authenticator_id": authenticator_id,
        }, self._auth_server_headers)
        if resp.get("challenge_type") != "oob" or not resp.get("oob_code") or not resp.get("binding_method"):
            return {
                "error": resp.get("error", "server_error"),
                "error_description": resp.get("error_description", "Invalid OOB challenge response")
            }

        return cast(OAuthMfaAuthenticatorsResponse, {
            "challenge_type": resp.get("challenge_type"),
            "oob_code": resp.get("oob_code"),
            "binding_method": resp.get("binding_method"),
            "error": resp.get("error"),
            "error_description": resp.get("error_description"),
        }) 

    async def mfa_oob_complete(self, mfa_token: str, oobCode: str, bindingCode: str, scope: Optional[str] = None) -> OAuthTokenResponse:
        """
        Completes the Password MFA OTP flow.
        
        Does not throw exceptions.
        
        :param str mfa_token: the MFA token that was returned by the authorization
               server in the response from the Password Flow.
        :param oob_code: the code entered by the user

        :return: an :class:`OAuthTokenResponse` object, which may contain
                 an error instead of the response fields.
        """

        CrossauthLogger.logger().debug(j({"msg": "Completing MFA OOB request"}))
        if self._oidc_config is None:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")
        if "http://auth0.com/oauth/grant-type/mfa-oob" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support password_mfa grant"
            }
        if not self._oidc_config.get("issuer"):
            return {"error": "server_error", "error_description": "Cannot get issuer"}

        url = self._oidc_config["token_endpoint"]
        resp = await self._post(url, {
            "grant_type": "http://auth0.com/oauth/grant-type/mfa-oob",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "challenge_type": "otp",
            "mfa_token": mfa_token,
            "oob_code": oobCode,
            "binding_code": bindingCode,
            "scope": scope,
        }, self._auth_server_headers)
        if "error" in resp and "error_description" in resp:
            return {
                "error": MapGetter[str].get(resp, "error", ""),
                "error_description": MapGetter[str].get(resp, "error_description", ""),
            }
        id_token : Mapping[str,Any]|None = None
        if ("id_token" in resp):
            access_token : str|None = None
            if "access_token" in resp:
                access_token = resp["access_token"]
            user_info = await self._get_id_payload(resp["id_token"], access_token)
            error1 : str|None = user_info["error"] if "error" in user_info else None
            error_description1 : str|None = user_info["error_description"] if "error_description" in user_info else ""
            if (error1 is not None):
                return {
                    "error": error1,
                    "error_description": error_description1
                }
            if ("id_payload" in user_info):
                id_token = user_info["id_payload"]
        ret = cast(OAuthTokenResponse, {
            "id_token": resp.get("id_token"),
            "access_token": resp.get("access_token"),
            "refresh_token": resp.get("refresh_token"),
            "expires_in": int(resp.get("expires_in", 0)),
            "scope": resp.get("scope"),
            "token_type": resp.get("token_type"),
        })
        if (id_token is not None):
            ret["id_payload"] = id_token
        return ret

    async def refresh_token_flow(self, refresh_token: str) -> OAuthTokenResponse:
        """
        Starts the refresh token flow

        :param str refresh_token: the refresh token to exchange

        :return: a :class:`OAuthTokenResponse?  response
        """

        CrossauthLogger.logger().debug(j({"msg": "Starting refresh token flow"}))
        if self._oidc_config is None:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")
        if "refresh_token" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support refresh_token grant"
            }
        if not self._oidc_config.get("token_endpoint"):
            return {
                "error": "server_error",
                "error_description": "Cannot get token endpoint"
            }

        url = self._oidc_config["token_endpoint"]

        client_secret = self._client_secret

        params = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self._client_id,
        }
        if client_secret:
            params["client_secret"] = client_secret
        try:
            ret = cast(OAuthTokenResponse, await self._post(url, params, self._auth_server_headers))
            if ("id_token" in ret):
                access_token : str|None = None
                if "access_token" in ret:
                    access_token = ret["access_token"]
                user_info = await self._get_id_payload(ret["id_token"], access_token)
                error1 : str|None = user_info["error"] if "error" in user_info else None
                error_description1 : str|None = user_info["error_description"] if "error_description" in user_info else ""
                if (error1 is not None):
                    return {
                        "error": error1,
                        "error_description": error_description1
                    }
                if ("id_payload" in user_info):
                    ret["id_payload"] = user_info["id_payload"]
            return ret
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Error connecting to authorization server"
            }

    async def start_device_code_flow(self, url: str, scope: Optional[str] = None) -> OAuthDeviceAuthorizationResponse:

        """
        Starts the Device Code Flow on the primary device (the one wanting an access token)
        :param str url: The URl for the device_authorization endpoint, as it is not defined in the OIDC configuration
        :param str|None scope: optional scope to request authorization for

        :return: See :class:`OAuthDeviceAuthorizationResponse`
        """

        CrossauthLogger.logger().debug(j({"msg": "Starting device code flow"}))
        if self._oidc_config is None:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")
        if "urn:ietf:params:oauth:grant-type:device_code" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support device code grant"
            }

        params : TokenBodyType = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": self._client_id,
        }
        if self._client_secret is not None:
            params["client_secret"] = self._client_secret

        if scope:
            params["scope"] = scope
        try:
            ret = cast(OAuthDeviceAuthorizationResponse, await self._post(url, params, self._auth_server_headers))
            if ("id_token" in ret):
                access_token : str|None = None
                if "access_token" in ret:
                    access_token = ret["access_token"]
                user_info = await self._get_id_payload(ret["id_token"], access_token)
                error1 : str|None = user_info["error"] if "error" in user_info else None
                error_description1 : str|None = user_info["error_description"] if "error_description" in user_info else ""
                if (error1 is not None):
                    return {
                        "error": error1,
                        "error_description": error_description1
                    }
                if ("id_payload" in user_info):
                    ret["id_payload"] = user_info["id_payload"]
            return ret
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Error connecting to authorization server"
            }

    async def poll_device_code_flow(self, device_code: str) -> OAuthDeviceResponse:
        """
        Polls the device endpoint to check if the device code flow has been
        authorized by the user.
        
        :param str device_code: the device code to poll

        :return: See :class:`OAuthDeviceResponse`
        """

        CrossauthLogger.logger().debug(j({"msg": "Starting device code flow"}))
        if self._oidc_config is None:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")
        if "urn:ietf:params:oauth:grant-type:device_code" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support device code grant"
            }
        if not self._oidc_config.get("token_endpoint"):
            return {
                "error": "server_error",
                "error_description": "Cannot get token endpoint"
            }

        params : TokenBodyType = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": self._client_id,
            "device_code": device_code,
        }
        if self._client_secret is not None:
            params["client_secret"] = self._client_secret

        try:
            resp = await self._post(self._oidc_config["token_endpoint"], params, self._auth_server_headers)
            ret = cast(OAuthDeviceResponse, resp)
            if ("id_token" in ret):
                access_token : str|None = None
                if "access_token" in ret:
                    access_token = ret["access_token"]
                user_info = await self._get_id_payload(ret["id_token"], access_token)
                error1 : str|None = user_info["error"] if "error" in user_info else None
                error_description1 : str|None = user_info["error_description"] if "error_description" in user_info else ""
                if (error1 is not None):
                    return {
                        "error": error1,
                        "error_description": error_description1
                    }
                if ("id_payload" in user_info):
                    ret["id_payload"] = user_info["id_payload"]
            return ret
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Error connecting to authorization server"
            }

    #################################################################3
    ## UserInfo

    async def user_info_endpoint(self, access_token : str) -> Mapping[str, Any]:
        if (not self._oidc_config or "token_endpoint" not in self._oidc_config):
            CrossauthLogger.logger().warn(j({"msg": "Not fetching user info as the endpoint is not defined in the OIDC Config"}))
            return {
                "error": "server_error",
                "error_description": "Cannot get token endpoint"
            }
        url = self._oidc_config["token_endpoint"]

        resp = await self._post(url, {}, {"authorization": "Bearer " + access_token})
        return resp
    
    async def _get_id_payload(self, id_token: str, access_token : str|None) -> IdTokenReturn:
        ret : IdTokenReturn = {}
        try:

            payload = await self.validate_id_token(id_token)
            if (not payload):
                ret["error"] = "access_denied"
                ret["error_description"] = "Invalid ID token received"
                return ret
            ret["id_payload"] = payload
            if (access_token):
                if (self._oauth_use_user_info_endpoint):
                    user_info = await self.user_info_endpoint(access_token)
                    if ("error" in user_info):
                        ret["error"] = user_info["error"]
                        ret["error_description"] = "Failed getting user info: "
                        if ("error_description" in user_info):
                            ret["error_description"] += user_info["error_description"]
                        else:
                            ret["error_description"] += "Unknown error"
                    payload = {**payload, **user_info}
            ret["id_payload"] = payload
            return ret
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": ce}))
            CrossauthLogger.logger().error(j({"msg": "Couldn't get user info", "cerr": ce}));
            ret["error"] = ce.oauthErrorCode
            ret["error_description"] = "Couldn't get user info: " + ce.message
            return ret
        
    async def _post(self, url: str, params: Mapping[str, Any], headers: Dict[str, Any] = {}) -> Mapping[str, Any]:
        CrossauthLogger.logger().debug(j({
            "msg": "Fetch POST",
            "url": url,
            "params": list(params.keys())
        }))
        options = {}
        if self._auth_server_credentials:
            options["credentials"] = self._auth_server_credentials
        if self._auth_server_mode:
            options["mode"] = self._auth_server_mode
        async with aiohttp.ClientSession() as session:
            if (self._oauth_post_type == "json"):
                resp = await session.post(url, json=params, headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/json',
                    **headers,
                })
                return await resp.json()
            else:
                resp = await session.post(url, data=params, headers={
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencodedc',
                    **headers,
                })
                return await resp.json()
                    

    async def _get(self, url: str, headers: Mapping[str, Any] = {}) -> Mapping[str, Any] | List[Any]:
        CrossauthLogger.logger().debug(j({"msg": "Fetch GET", "url": url}))
        options = {}
        if self._auth_server_credentials:
            options["credentials"] = self._auth_server_credentials
        if self._auth_server_mode:
            options["mode"] = self._auth_server_mode
        async with aiohttp.ClientSession() as session:
            resp = await session.get(url, headers={
                'Accept': 'application/json',
                'Content-Type': 'application/json',
                **headers,
            })
            return await resp.json()
    
    async def validate_id_token(self, token: str) -> Optional[Dict[str, Any]]:
        """
        Validates an OpenID ID token, returning None if it is invalid.
        
        Does not raise exceptions.
        
        :param token: the token to validate. To be valid, the signature must
            be valid and the `type` claim in the payload must be set to `id`.
        
        :returns
            the parsed payload or None if the token is invalid.
        """

        try:
            return await self._token_consumer.token_authorized(token, "id")
        except Exception:
            return None

    async def id_token_authorized(self, id_token: str) -> Optional[Dict[str, Any]]:
        """
        Validates a token using the token consumer.
        
        :param id_token (str): the token to validate
        
        :returns the parsed JSON of the payload, or None if it is not valid.
        """

        try:
            return await self._token_consumer.token_authorized(id_token, "id")
        except Exception as e:
            CrossauthLogger.logger().warn(j({"err": e}))
            return None

    def get_token_payload(self, token: str) -> Dict[str, Any]:
        """
        Validates a token and, if valid, returns the payload
        """
        instance = JWT()
        return instance.decode(token, None, do_verify=False, do_time_check=False)
    
