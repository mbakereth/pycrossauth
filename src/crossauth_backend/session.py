from crossauth_backend.storage import UserStorage, KeyStorage, KeyDataEntry
from crossauth_backend.cookieauth import DoubleSubmitCsrfTokenOptions, DoubleSubmitCsrfToken
from crossauth_backend.cookieauth import SessionCookieOptions, SessionCookie, Cookie
from crossauth_backend.crypto import Crypto
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.common.interfaces import User, UserSecrets, PartialUser, KeyPrefix
from crossauth_backend.auth import Authenticator, AuthenticationParameters
from typing import TypedDict, List, Mapping, NamedTuple, Any, cast
from datetime import datetime
import json

class SessionManagerOptions(TypedDict, total=False):
    """
    Options for SessionManager
    """

    user_storage: UserStorage
    """
    If user login is enabled, you must provide the object where users
    are stored.
    """

    double_submit_cookie_options : DoubleSubmitCsrfTokenOptions
    """Options for csrf cookie manager"""

    session_cookie_options : SessionCookieOptions
    """options for session cookie manager """

    enable_email_verification : bool
    """
    If true, users will have to verify their email address before account is created or when changing their email address.
    See class description for details. Default True
    """

    enable_password_reset : bool
    """
    If true, allow password reset by email token.
    See class description for details. Default True
    """

    secret : str
    """Server secret. Needed for emailing tokens and for csrf tokens"""

    email_token_storage : KeyStorage
    """
    Store for password reset and email verification tokens. If not passed, the same store as
    for sessions is used.
    """

    site_url : str
    """
    Base URL for the site.
    
    This is used when constructing URLs, eg for sending password reset
    tokens.
    """

    allowed_factor2 : List[str]
    """
    Set of 2FA factor names a user is allowed to set.
    
    The name corresponds to the key you give when adding authenticators.
    See `authenticators` in SessionManager.constructor.
    """
class AnonymousSession(NamedTuple):
    session_cookie: Cookie
    csrf_cookie: Cookie
    csrf_form_or_header_value: str

class SessionManager:
    def __init__(self, key_storage : KeyStorage, authenticators : Mapping[str, Authenticator] , options : SessionManagerOptions = {}):
        if options is None:
            options = {}
        self.user_storage = options.get('userStorage', None)
        self.key_storage = key_storage
        self.email_token_storage : KeyStorage | None = None
        self.authenticators = authenticators
        for authentication_name in self.authenticators:
            self.authenticators[authentication_name].factor_name = authentication_name

        self.session = SessionCookie(self.key_storage, options["session_cookie_options"] if "session_cookie_options" in options else {})
        self.csrf_tokens = DoubleSubmitCsrfToken(options["double_submit_cookie_options"] if "double_submit_cookie_options" in options else {})
        self.allowed_factor2 = []
        self._enable_email_verification : bool = False
        self._enable_password_reset : bool = False
        self._token_emailer = None

        set_parameter("allowed_factor2", ParamType.JsonArray, self, options, "ALLOWED_FACTOR2")
        set_parameter("enable_email_verification", ParamType.Boolean, self, options, "ENABLE_EMAIL_VERIFICATION", protected=True)
        set_parameter("enable_password_reset", ParamType.Boolean, self, options, "ENABLE_PASSWORD_RESET", protected=True)
        self.email_token_storage = self.key_storage
        if self.user_storage and (self._enable_email_verification or self._enable_password_reset):
            raise CrossauthError(ErrorCode.NotImplemented, "email verification is not supported in this version")

    async def login(self, username, params, extra_fields=None, persist=None, user=None, bypass_2fa=False):
        raise CrossauthError(ErrorCode.NotImplemented, "login not implemented in this version")
    
    async def create_anonymous_session(self, extra_fields=None) -> AnonymousSession:
        if extra_fields is None:
            extra_fields = {}
        key = await self.session.create_session_key(None, extra_fields)
        session_cookie = self.session.make_cookie(key, False)
        csrf_data = await self.create_csrf_token()
        return AnonymousSession(session_cookie, csrf_data['csrfCookie'], csrf_data['csrf_form_or_header_value'])
        

    async def logout(self, session_id):
        key = await self.session.get_session_key(session_id)
        return await self.key_storage.delete_key(SessionCookie.hash_session_id(key["value"]))

    async def logout_from_all(self, userid, except_id=None):
        return await self.session.delete_all_for_user(userid, except_id)

    async def user_for_session_id(self, session_id):
        return await self.session.get_user_for_session_id(session_id)

    async def data_string_for_session_id(self, session_id):
        try:
            key_data = await self.session.get_user_for_session_id(session_id)
            return key_data['key'].data
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            if ce.code == ErrorCode.Expired:
                return None
            raise ce

    async def data_for_session_id(self, session_id):
        str_data = await self.data_string_for_session_id(session_id)
        if not str_data:
            return {}
        return json.loads(str_data)

    async def create_csrf_token(self):
        csrf_token = self.csrf_tokens.create_csrf_token()
        csrf_form_or_header_value = self.csrf_tokens.make_csrf_form_or_header_token(csrf_token)
        csrf_cookie = self.csrf_tokens.make_csrf_cookie(csrf_token)
        return {
            'csrfCookie': csrf_cookie,
            'csrf_form_or_header_value': csrf_form_or_header_value,
        }

    async def create_csrf_form_or_header_value(self, csrf_cookie_value: str):
        csrf_token = self.csrf_tokens.unsign_cookie(csrf_cookie_value)
        return self.csrf_tokens.make_csrf_form_or_header_token(csrf_token)

    def get_session_id(self, session_cookie_value: str):
        return self.session.unsign_cookie(session_cookie_value)

    def validate_double_submit_csrf_token(self, csrf_cookie_value : str, csrf_form_or_header_value: str):
        if not csrf_cookie_value or not csrf_form_or_header_value:
            raise CrossauthError(ErrorCode.InvalidCsrf, "CSRF missing from either cookie or form/header value")
        self.csrf_tokens.validate_double_submit_csrf_token(csrf_cookie_value, csrf_form_or_header_value)

    def validate_csrf_cookie(self, csrf_cookie_value):
        self.csrf_tokens.validate_csrf_cookie(csrf_cookie_value)

    async def update_session_activity(self, session_id):
        key_data = await self.session.get_session_key(session_id)
        if self.session.idle_timeout > 0:
            await self.session.update_session_key({
                'value': key_data['value'],
                'lastactive': datetime.now(),
            })

    async def update_session_data(self, session_id: str, name: str, value: Mapping[str, Any]) -> None:
        hashed_session_key = self.session.hash_session_id(session_id)
        CrossauthLogger.logger().debug(j({"msg": f"Updating session data value{name}", "hashedSessionCookie": Crypto.hash(session_id)}))
        await self.key_storage.update_data(hashed_session_key, name, value)

    async def update_many_session_data(self, session_id: str, data_array: List[KeyDataEntry]) -> None:
        hashed_session_key = self.session.hash_session_id(session_id)
        CrossauthLogger.logger().debug(j({"msg": f"Updating session data", "hashedSessionCookie": Crypto.hash(session_id)}))
        await self.key_storage.update_many_data(hashed_session_key, data_array)

    async def delete_session_data(self, session_id: str, name: str) -> None:
        hashed_session_key = self.session.hash_session_id(session_id)
        CrossauthLogger.logger().debug(j({"msg": f"Updating session data value{name}", "hashedSessionCookie": Crypto.hash(session_id)}))
        await self.key_storage.delete_data(hashed_session_key, name)

    async def delete_session(self, session_id: str) -> None:
        return await self.key_storage.delete_key(self.session.hash_session_id(session_id))

    async def create_user(self, user: User, params: UserSecrets, repeat_params: UserSecrets|None = None, skip_email_verification: bool = False, empty_password: bool = False) -> User:
        if not self.user_storage:
            raise Exception("Cannot call createUser if no user storage provided")

        if user['factor1'] not in self.authenticators:
            raise Exception("Authenticator cannot create users")

        if self.authenticators[user['factor1']].skip_email_verification_on_signup():
            skip_email_verification = True

        secrets = await self.authenticators[user['factor1']].create_persistent_secrets(user['username'], params, repeat_params) if not empty_password else None
        new_user = await self.user_storage.create_user(user, secrets) if not empty_password else await self.user_storage.create_user(user)

        if not skip_email_verification and self._enable_email_verification and self._token_emailer:
            raise CrossauthError(ErrorCode.NotImplemented, "Email verification is not supported in this version")
            #await self.token_emailer.send_email_verification_token(new_user['id'], None)

        return new_user

    async def delete_user_by_username(self, username: str) -> None:
        if not self.user_storage:
            raise Exception("Cannot call deleteUser if no user storage provided")
        self.user_storage.delete_user_by_username(username)

    async def initiate_two_factor_signup(self, user: User, params: UserSecrets, session_id: str, repeat_params: UserSecrets|None):
        if not self.user_storage:
            raise Exception("Cannot call initiateTwoFactorSignup if no user storage provided")
        if user['factor1'] not in self.authenticators:
            raise Exception("Authenticator cannot create users")
        if 'factor2' not in user or user['factor2'] not in self.authenticators:
            raise Exception("Two factor authentication not enabled for user")

        authenticator = self.authenticators[user['factor2']]
        factor2_data = await authenticator.prepare_configuration(user)
        user_data = factor2_data.get('userData', {}) if factor2_data else {}
        session_data = factor2_data.get('sessionData', {}) if factor2_data else {}

        factor1_secrets = await self.authenticators[user['factor1']].create_persistent_secrets(user['username'], params, repeat_params)
        user['state'] = "awaitingtwofactorsetup"
        await self.key_storage.update_data(self.session.hash_session_id(session_id), "2fa", session_data)

        new_user = await self.user_storage.create_user(user, factor1_secrets)
        return {"userid": new_user['id'], "userData": user_data}

    async def initiate_two_factor_setup(self, user: User, new_factor2: str|None, session_id: str) -> Mapping[str, Any]:
        if not self.user_storage:
            raise Exception("Cannot call initiateTwoFactorSetup if no user storage provided")

        if new_factor2 and new_factor2 is not None:
            if new_factor2 not in self.authenticators:
                raise Exception("Two factor authentication not enabled for user")
            authenticator = self.authenticators[new_factor2]
            factor2_data = await authenticator.prepare_configuration(user)
            user_data = factor2_data.get('userData', {}) if factor2_data else {}
            session_data = factor2_data.get('sessionData', {}) if factor2_data else {}

            await self.key_storage.update_data(self.session.hash_session_id(session_id), "2fa", session_data)
            return user_data

        await self.user_storage.update_user({"id": user['id'], "factor2": new_factor2 or ""})
        await self.key_storage.update_data(self.session.hash_session_id(session_id), "2fa", None)
        return {}

    async def repeat_two_factor_signup(self, session_id: str) -> Mapping[str, Any]:
        if not self.user_storage:
            raise Exception("Cannot call repeatTwoFactorSignup if no user storage provided")

        session_data = (await self.data_for_session_id(session_id))["2fa"]
        username = session_data['username']
        factor2 = session_data['factor2']
        hashed_session_key = self.session.hash_session_id(session_id)
        session_key = await self.key_storage.get_key(hashed_session_key)
        authenticator = self.authenticators[factor2]

        resp = await authenticator.reprepare_configuration(username, session_key)
        user_data = resp.get('userData', {}) if resp else {}
        secrets = resp.get('secrets', {}) if resp else {}
        new_session_data = resp.get('newSessionData', {}) if resp else {}

        if new_session_data:
            await self.key_storage.update_data(hashed_session_key, "2fa", new_session_data)

        user = (await self.user_storage.get_user_by_username(username, {"skipActiveCheck": True, "skipEmailVerifiedCheck": True}))['user']
        return {"userid": user['id'], "userData": user_data, "secrets": secrets}

    async def complete_two_factor_setup(self, params: AuthenticationParameters, session_id: str) -> User:
        if not self.user_storage:
            raise Exception("Cannot call completeTwoFactorSetup if no user storage provided")

        new_signup = False
        ret = await self.session.get_user_for_session_id(session_id, {"skipActiveCheck": True})
        user = cast(User, ret["user"])
        key = ret["key"]
        if user and (user['state'] != "active" and user['state'] != "factor2ResetNeeded"):
            raise Exception("UserNotActive")
        if not key:
            raise Exception("Session key not found")

        data = json.loads(key['data'])["2fa"]
        if not data.get('factor2') or not data.get('username'):
            raise Exception("Two factor authentication not initiated")

        username = data['username']
        authenticator = self.authenticators[data['factor2']]
        if not authenticator:
            raise Exception("Unrecognised second factor authentication")

        new_secrets = {secret: data[secret] for secret in authenticator.secret_names() if secret in data}
        await authenticator.authenticate_user(None, data, params)

        if not user:
            new_signup = True
            user = (await self.user_storage.get_user_by_username(username, {"skipActiveCheck": True, "skipEmailVerifiedCheck": True}))['user']

        skip_email_verification = authenticator.skip_email_verification_on_signup()
        if not user:
            raise Exception("Couldn't fetch user")

        new_user : PartialUser = {
            "id": user['id'],
            "state": "awaitingemailverification" if not skip_email_verification and self._enable_email_verification else "active",
            "factor2": data['factor2'],
        }

        if authenticator.secret_names():
            await self.user_storage.update_user(new_user, new_secrets)
        else:
            await self.user_storage.update_user(new_user)

        if not skip_email_verification and new_signup and self._enable_email_verification and self._token_emailer:
            raise CrossauthError(ErrorCode.NotImplemented, "Email verification is not implemented in this version")
        await self.key_storage.update_data(self.session.hash_session_id(key['value']), "2fa", None)
        user.update(new_user)
        return user

    async def initiate_two_factor_login(self, user: User) -> Mapping[str, Any]:
        if ('factor2' not in user or user['factor2'] not in self.authenticators):
            raise CrossauthError(ErrorCode.Configuration, "Factor2 " + user['factor2'] if "factor2" in user else "none" + " not supported in configuration")
        authenticator = self.authenticators[user['factor2']]
        secrets = await authenticator.create_one_time_secrets(user)
        session_cookie = await self.create_anonymous_session({"data": json.dumps({"2fa": {"username": user['username'], "twoFactorInitiated": True, "factor2": user['factor2'], **secrets}})})
        csrf_token = self.csrf_tokens.create_csrf_token()
        csrf_cookie = self.csrf_tokens.make_csrf_cookie(csrf_token)
        csrf_form_or_header_value = self.csrf_tokens.make_csrf_form_or_header_token(csrf_token)

        return {
            "sessionCookie": session_cookie,
            "csrfCookie": csrf_cookie,
            "csrfFormOrHeaderValue": csrf_form_or_header_value,
        }

    async def initiate_two_factor_page_visit(self, user: User, session_id: str, request_body: Mapping[str, Any], url: str|None=None, content_type: str|None = None):
        if ('factor2' not in user or user['factor2'] not in self.authenticators):
            raise CrossauthError(ErrorCode.Configuration, "Factor2 " + user['factor2'] if "factor2" in user else "none" + " not supported in configuration")
        authenticator = self.authenticators[user['factor2']]
        secrets = await authenticator.create_one_time_secrets(user)

        hashed_session_id = self.session.hash_session_id(session_id)
        CrossauthLogger.logger().debug(f"initiateTwoFactorPageVisit {user['username']} {session_id} {hashed_session_id}")
        new_data = {"username": user['username'], "factor2": user['factor2'], "secrets": secrets, "body": request_body, "url": url}
        if content_type:
            new_data["content-type"] = content_type
        await self.key_storage.update_data(hashed_session_id, "pre2fa", new_data)

        return {
            "sessionCookie": None,
            "csrfCookie": None,
            "csrfFormOrHeaderValue": None,
        }

    async def complete_two_factor_page_visit(self, params, session_id):
        if not self.user_storage:
            raise CrossauthError(ErrorCode.Configuration, "Cannot call completeTwoFactorPageVisit if no user storage provided")
        key = await self.session.get_user_for_session_id(session_id)
        if not key:
            raise CrossauthError(ErrorCode.InvalidKey, "Session key not found")
        data = KeyStorage.decode_data(key["data"])
        if "pre2fa" not in data:
            raise CrossauthError(ErrorCode.Unauthorized, "Two factor authentication not initiated")
        secrets = await self.user_storage.get_user_by_username(data["pre2fa"].username)

        authenticator = self.authenticators[data["pre2fa"].factor2]
        if not authenticator:
            raise CrossauthError(ErrorCode.Configuration, "Unrecognised second factor authentication")
        new_secrets = {}
        secret_names = authenticator.secret_names()
        for secret in secrets:
            if secret in secret_names and secret in secrets:
                new_secrets[secret] = secrets[secret]
        secrets1 = secrets
        secrets1.update(**data["pre2fa"]["secrets"])
        await authenticator.authenticate_user(None,secrets1, params)
        await self.key_storage.update_data(SessionCookie.hash_session_id(key["value"]), "pre2fa", None)

    async def cancel_two_factor_page_visit(self, session_id):
        key = await self.session.get_user_for_session_id(session_id)
        if not key:
            raise CrossauthError(ErrorCode.InvalidKey, "Session key not found")
        data = KeyStorage.decode_data(key["data"])
        if "pre2fa" not in data:
            raise CrossauthError(ErrorCode.Unauthorized, "Two factor authentication not initiated")
        await self.key_storage.update_data(SessionCookie.hash_session_id(key["value"]), "pre2fa", None)
        return data["pre2fa"]

    async def complete_two_factor_login(self, params, session_id, extra_fields=None, persist=None):
        raise CrossauthError(ErrorCode.NotImplemented, "Login is not implemented in this version")

    async def request_password_reset(self, email):
        raise CrossauthError(ErrorCode.NotImplemented, "Password reset is not implemented in this version")

    async def apply_email_verification_token(self, token):
        raise CrossauthError(ErrorCode.NotImplemented, "Email verification is not implemented in this version")


    async def user_for_password_reset_token(self, token):
        raise CrossauthError(ErrorCode.NotImplemented, "Password reset  is not implemented in this version")

    async def update_user(self, current_user, new_user, skip_email_verification=False, as_admin=False):
        raise CrossauthError(ErrorCode.NotImplemented, "User update is not implemented in this version")

    async def reset_secret(self, token, factor_number, params, repeat_params=None):
        raise CrossauthError(ErrorCode.NotImplemented, "Password reset is not implemented in this version")

