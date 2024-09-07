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
import jwt
import aiohttp

class OAuthFlows:
    """
    Crossauth allows you to define which flows are valid for a given client.
    """

    """ All flows are allowed """
    All = "all"

    """ OAuth authorization code flow (without PKCE) """
    AuthorizationCode = "authorizationCode"

    """ OAuth authorization code flow with PKCE """
    AuthorizationCodeWithPKCE = "authorizationCodeWithPKCE"

    """ Auth client credentials flow """
    ClientCredentials = "clientCredentials"

    """ OAuth refresh token flow """
    RefreshToken = "refreshToken"

    """ OAuth device code flow """
    DeviceCode = "deviceCode"

    """ OAuth password flow """
    Password = "password"

    """ The Auth0 password MFA extension to the password flow """
    PasswordMfa = "passwordMfa"

    """ The OpenID Connect authorization code flow, with or without PKCE """
    OidcAuthorizationCode = "oidcAuthorizationCode"

    """ A user friendly name for the given flow ID """
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

class OAuthTokenResponse(TypedDict, total=False):
    """
    These are the fields that can be returned in the JSON from an OAuth call.
    """

    access_token : str
    refresh_token : str
    id_token : str
    token_type : str
    expires_in : str
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
    active: str
    oob_channel : str
    name: str
    error: str
    error_description: str

class OAuthMfaAuthenticatorsResponse(TypedDict, total=False):
    authenticators: List[OAuthMfaAuthenticator]
    error : str
    error_description: str

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

    """ Length of random state variable for passing to `authorize` endpoint
        (before bsae64-url-encoding)
    """
    state_length : int

    """ Length of random code verifier to generate 
        (before bsae64-url-encoding) 
    """
    verifier_length : int

    """
        Client ID for this client
    """
    client_id : str

    """
        Client secret for this client (can be undefined for no secret)
    """
    client_secret : str

    """
        Redirect URI to send in `authorize` requests
    """
    redirect_uri : str

    """
        Type of code challenge for PKCE
    """
    code_challenge_method : Literal["plain",  "S256"]

    """
        URL to call for the device_authorization endpoint, relative to
        the `auth_server_base_url`.
        
        Default `device_authorization`
    """
    device_authorization_url : str

class OAuthClient:
    """
    Base class for OAuth clients.

    Flows supported are Authorization Code Flow with and without PKCE,
    Client Credentials, Refresh Token, Password and Password MFA.  The
    latter is defined at
    {@link https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors}.

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
        :param OAuthClientOptions options: see :class: OAuthClientOptions
        """
        self._session = aiohttp.ClientSession() 
        self._verifier_length = 32
        self._state_length = 32
        self._client_id : str = ""
        self._client_secret : str|None = None
        self._redirect_uri : str|None = None
        self._code_challenge_method : Literal["plain", "S256"] = "S256"
        self._auth_server_credentials : Literal["include", "omit", "same-origin" ] | None = None
        self._auth_server_mode : Literal["no-cors", "cors", "same-origin" ] | None = None
        self._auth_server_headers : Dict[str, str] = {}
        self._code_challenge : str|None = None
        self._code_verifier : str|None = None
        self._state = ""
        self._authz_code = ""
        self._oidc_config : OpenIdConfiguration | None = None
        self._device_authorization_url : str|None = None

        self.auth_server_base_url = auth_server_base_url
        set_parameter("client_id", ParamType.String, self, options, "OAUTH_CLIENT_ID", required=True, protected=True)
        set_parameter("client_secret", ParamType.String, self, options, "OAUTH_CLIENT_SECRET", required=True, protected=True)

        self._token_consumer = OAuthTokenConsumer(self._client_id, self._session, options)
        set_parameter("state_length", ParamType.String, self, options, "OAUTH_STATE_LENGTH", protected=True)
        set_parameter("verifier_length", ParamType.String, self, options, "OAUTH_VERIFIER_LENGTH", protected=True)
        set_parameter("client_secret", ParamType.String, self, options, "OAUTH_CLIENT_SECRET", protected=True)
        set_parameter("code_challenge_method", ParamType.String, self, options, "OAUTH_CODE_CHALLENGE_METHOD", protected=True)
        set_parameter("device_authorization_url", ParamType.String, self, options, "OAUTH_DEVICE_AUTHORIZATION_URL", protected=True)
        if (self._device_authorization_url is not None and self._device_authorization_url[0:1] == "/"): self._device_authorization_url = self._device_authorization_url[1:]



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
            response = await self._session.get(url, **options)
            response.raise_for_status()
        except requests.RequestException as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            raise Exception("Couldn't get OIDC configuration from URL")

        self._oidc_config : OpenIdConfiguration | None= None
        try:
            body : Mapping[str,str] = await response.json()
            self.oidc_config = {**body}
        except json.JSONDecodeError:
            raise Exception("Unrecognized response from OIDC configuration endpoint")

    def get_oidc_config(self):
        return self.oidc_config

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

    async def start_authorization_code_flow(self, scope : str | None = None, pkce : bool = False):
        CrossauthLogger.logger().debug(j({"msg": "Starting authorization code flow"}))
        if self._oidc_config is None:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't load OIDC Configuration")
        if "code" not in self._oidc_config["response_types_supported"] or not "query" in self.oidc_config["response_modes_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support authorization code flow"
            }
        if not self.oidc_config.get("authorization_endpoint"):
            return {
                "error": "server_error",
                "error_description": "Cannot get authorize endpoint"
            }
        self.state = self.random_value(self._state_length)
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

        base = self.oidc_config["authorization_endpoint"]
        url = f"{base}?response_type=code&client_id={urllib.parse.quote(self._client_id)}&state={urllib.parse.quote(self.state)}&redirect_uri={urllib.parse.quote(self._redirect_uri)}"

        if scope:
            url += f"&scope={urllib.parse.quote(scope)}"

        if pkce:
            self._code_verifier = self.random_value(self._verifier_length)
            self._code_challenge = await self.sha256(self._code_verifier) if self._code_challenge_method == "S256" else self._code_verifier
            url += f"&code_challenge={self._code_challenge}"

        return {"url": url}

    async def redirect_endpoint(self, code : str|None = None, state : str|None = None, error : str|None =None, error_description : str|None=None) -> OAuthTokenResponse:
        if not self.oidc_config: 
            await self.load_config()
        if error is not None or not code:
            if error is None:
                error = "server_error"
            if error_description is None:
                error_description = "Unknown error"
            return {"error": error, "error_description": error_description}
        if self.state and state != self.state:
            return {"error": "access_denied", "error_description": "State is not valid"}
        self.authzCode = code

        if "authorization_code" not in self.oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support authorization code grant"
            }
        if not self.oidc_config.get("token_endpoint"):
            return {
                "error": "server_error",
                "error_description": "Cannot get token endpoint"
            }
        url = self.oidc_config["token_endpoint"]

        grant_type = "authorization_code"
        client_secret = self._client_secret
        params : Dict[str, Any]= {
            "grant_type": grant_type,
            "client_id": self._client_id,
            "code": self.authzCode,
        }
        if client_secret:
            params["client_secret"] = client_secret
        params["code_verifier"] = self._code_verifier
        try:
            return cast(OAuthTokenResponse, await self.post(url, params, self._auth_server_headers)) 
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Unable to get access token from server"
            }

    async def client_credentials_flow(self, scope : str|None = None) -> OAuthTokenResponse:
        CrossauthLogger.logger().debug(j({"msg": "Starting client credentials flow"}))
        if not self.oidc_config:
            await self.load_config()
        if "client_credentials" not in self.oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support client credentials grant"
            }
        if self._oidc_config is None or self._oidc_config["token_endpoint"] == "":
            return {"error": "server_error", "error_description": "Cannot get token endpoint"}
        if self._client_id == "":
            return {
                "error": "invalid_request",
                "error_description": "Cannot make client credentials flow without client id"
            }

        url = self.oidc_config["token_endpoint"]

        params : TokenBodyType = {
            "grant_type": "client_credentials",
            "client_id": self._client_id,
        }
        if self._client_secret is not None: 
            params["client_secret"] = self._client_secret

        if scope:
            params["scope"] = scope
        try:
            return cast(OAuthTokenResponse, await self.post(url, params, self._auth_server_headers)) 
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Error connecting to authorization server"
            }

    async def password_flow(self, username : str, password : str, scope : str|None = None)  -> OAuthTokenResponse:
        CrossauthLogger.logger().debug(j({"msg": "Starting password flow"}))
        if not self.oidc_config:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")
        if "password" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support password grant"
            }
        if not self.oidc_config.get("token_endpoint"):
            return {
                "error": "server_error",
                "error_description": "Cannot get token endpoint"
            }

        url = self.oidc_config["token_endpoint"]

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
            return cast(OAuthTokenResponse, await self.post(url, params, self._auth_server_headers))
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Error connecting to authorization server"
            }

    async def mfa_authenticators(self, mfa_token: str) -> OAuthMfaAuthenticatorsResponse :
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
        if not self.oidc_config.get("issuer"):
            return {"error": "server_error", "error_description": "Cannot get issuer"}

        url = f"{self.oidc_config['issuer']}/mfa/authenticators" if self.oidc_config['issuer'].endswith("/") else f"{self.oidc_config['issuer']}/mfa/authenticators"
        resp = await self.get(url, {'authorization': f'Bearer {mfa_token}', **self._auth_server_headers})
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
        CrossauthLogger.logger().debug(j({"msg": "Making MFA OTB request"}))
        if not self.oidc_config:
            await self.load_config()
        if (self._oidc_config is None):
            raise CrossauthError(ErrorCode.Connection, "Couldn't fet OIDC configuration")
        if "http://auth0.com/oauth/grant-type/mfa-otp" not in self._oidc_config["grant_types_supported"]:
            return {
                "error": "invalid_request",
                "error_description": "Server does not support password_mfa grant"
            }
        if not self.oidc_config.get("issuer"):
            return {"error": "server_error", "error_description": "Cannot get issuer"}

        url = f"{self.oidc_config['issuer']}/mfa/challenge" if self.oidc_config['issuer'].endswith("/") else f"{self.oidc_config['issuer']}/mfa/challenge"
        resp = await self.post(url, {
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
        if not self.oidc_config.get("issuer"):
            return {"error": "server_error", "error_description": "Cannot get issuer"}

        otpUrl = self.oidc_config["token_endpoint"]
        otpResp = await self.post(otpUrl, {
            "grant_type": "http://auth0.com/oauth/grant-type/mfa-otp",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "challenge_type": "otp",
            "mfa_token": mfa_token,
            "otp": otp,
            "scope": scope,
        }, self._auth_server_headers)
        return cast(OAuthTokenResponse, {
            "id_token": otpResp.get("id_token"),
            "access_token": otpResp.get("access_token"),
            "refresh_token": otpResp.get("refresh_token"),
            "expires_in": int(otpResp.get("expires_in", 0)),
            "scope": otpResp.get("scope"),
            "token_type": otpResp.get("token_type"),
            "error": otpResp.get("error"),
            "error_description": otpResp.get("error_description"),
        })

    async def mfa_oob_request(self, mfa_token: str, authenticator_id: str) -> OAuthMfaAuthenticatorsResponse:
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
        if not self.oidc_config.get("issuer"):
            return {"error": "server_error", "error_description": "Cannot get issuer"}

        url = f"{self.oidc_config['issuer']}/mfa/challenge" if self.oidc_config['issuer'].endswith("/") else f"{self.oidc_config['issuer']}/mfa/challenge"
        resp = await self.post(url, {
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
        if not self.oidc_config.get("issuer"):
            return {"error": "server_error", "error_description": "Cannot get issuer"}

        url = self.oidc_config["token_endpoint"]
        resp = await self.post(url, {
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
        return cast(OAuthTokenResponse, {
            "id_token": resp.get("id_token"),
            "access_token": resp.get("access_token"),
            "refresh_token": resp.get("refresh_token"),
            "expires_in": int(resp.get("expires_in", 0)),
            "scope": resp.get("scope"),
            "token_type": resp.get("token_type"),
        })

    async def refresh_token_flow(self, refreshToken: str) -> OAuthTokenResponse:
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
        if not self.oidc_config.get("token_endpoint"):
            return {
                "error": "server_error",
                "error_description": "Cannot get token endpoint"
            }

        url = self.oidc_config["token_endpoint"]

        client_secret = self._client_secret

        params = {
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": self._client_id,
        }
        if client_secret:
            params["client_secret"] = client_secret
        try:
            return cast(OAuthTokenResponse, await self.post(url, params, self._auth_server_headers))
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Error connecting to authorization server"
            }

    async def start_device_code_flow(self, url: str, scope: Optional[str] = None) -> OAuthDeviceAuthorizationResponse:
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

        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
        }
        if scope:
            params["scope"] = scope
        try:
            return cast(OAuthDeviceAuthorizationResponse, await self.post(url, params, self._auth_server_headers))
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Error connecting to authorization server"
            }

    async def poll_device_code_flow(self, deviceCode: str) -> OAuthDeviceResponse:
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
        if not self.oidc_config.get("token_endpoint"):
            return {
                "error": "server_error",
                "error_description": "Cannot get token endpoint"
            }

        params = {
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "device_code": deviceCode,
        }
        try:
            resp = await self.post(self.oidc_config["token_endpoint"], params, self._auth_server_headers)
            return cast(OAuthDeviceResponse, resp)
        except Exception as e:
            CrossauthLogger.logger().error(j({"err": str(e)}))
            return {
                "error": "server_error",
                "error_description": "Error connecting to authorization server"
            }

    async def post(self, url: str, params: Mapping[str, Any], headers: Dict[str, Any] = {}) -> Mapping[str, Any]:
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
        resp = await self._session.post(url, json=params, headers={
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            **headers,
        })
        return await resp.json()

    async def get(self, url: str, headers: Mapping[str, Any] = {}) -> Mapping[str, Any] | List[Any]:
        CrossauthLogger.logger().debug(j({"msg": "Fetch GET", "url": url}))
        options = {}
        if self._auth_server_credentials:
            options["credentials"] = self._auth_server_credentials
        if self._auth_server_mode:
            options["mode"] = self._auth_server_mode
        resp = await self._session.get(url, headers={
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
        return jwt.decode(token, options={"verify_signature": False}) 
    
