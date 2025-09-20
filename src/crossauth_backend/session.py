from crossauth_backend.storage import UserStorage, KeyStorage, KeyDataEntry
from crossauth_backend.cookieauth import DoubleSubmitCsrfTokenOptions, DoubleSubmitCsrfToken
from crossauth_backend.cookieauth import SessionCookieOptions, SessionCookie, Cookie
from crossauth_backend.crypto import Crypto
from crossauth_backend.emailtoken import TokenEmailer, TokenEmailerOptions
from crossauth_backend.utils import set_parameter, ParamType
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.interfaces import User, UserSecrets, UserInputFields, \
    UserState, KeyPrefix, UserSecretsInputFields, PartialUser, PartialUserSecrets
from crossauth_backend.auth import Authenticator, AuthenticationParameters
from typing import List, Mapping, NamedTuple, Any, Dict, cast
from datetime import datetime
import json

class UserIdAndData(NamedTuple):
    userid: str|int
    user_data: Dict[str,Any]
    secrets: UserSecrets|None

class SessionTokens(NamedTuple):
    session_cookie: Cookie|None
    csrf_cookie: Cookie|None
    csrf_form_or_header_value: str|None
    user: User|None
    secrets: UserSecrets|None

class Csrf(NamedTuple):
    csrf_cookie: Cookie
    csrf_form_or_header_value: str

class TokensSent(NamedTuple):
    email_verification_token_sent: bool
    password_reset_token_sent: bool

class SessionManagerOptions(TokenEmailerOptions, total=False):
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

class SessionManager:
    """
    Class for managing sessions.
    """

    @property
    def user_storage(self):
        return self._user_storage

    @property
    def key_storage(self):
        return self._key_storage

    @property
    def email_token_storage(self):
        return self._email_token_storage
    
    @property
    def csrf_tokens(self):
        return self._csrf_tokens

    @property
    def session(self):
        return self._session

    @property
    def authenticators(self):
        return self._authenticators

    @property
    def allowed_factor2(self):
        return self._allowed_factor2

    def __init__(self, key_storage : KeyStorage, authenticators : Mapping[str, Authenticator] , options : SessionManagerOptions = {}):
        """
        Constructor
        :param crossauth_backend._key_storage key_storage:  the :class:`_key_storage` instance to use, eg :class:`Prisma_key_storage`.
        :param Mapping[str, Authenticator] authenticators: authenticators used to validate users, eg :class:`LocalPasswordAuthenticatorOptions`.
        :param SessionManagerOptions options: optional parameters for authentication. See :class:`SessionManagerOptions`.

        """
        self._user_storage = options.get('user_storage', None)
        self._key_storage = key_storage
        self._email_token_storage : KeyStorage
        self._authenticators = authenticators
        for authentication_name in self._authenticators:
            self._authenticators[authentication_name].factor_name = authentication_name

        soptions : SessionCookieOptions = {**options}
        if ("session_cookie_options" in options):
            soptions = {**soptions, **options["session_cookie_options"]}
        self._session = SessionCookie(self._key_storage, soptions)
        coptions : DoubleSubmitCsrfTokenOptions = {}
        if "secret" in options:
            coptions["secret"] = options["secret"]
        if ("double_submit_cookie_options" in options):
            coptions = {**coptions, **options["double_submit_cookie_options"]}
        self._csrf_tokens = DoubleSubmitCsrfToken(coptions)

        self._allowed_factor2 : List[str] = []
        self.__enable_email_verification : bool = False
        self.__enable_password_reset : bool = False
        self.__token_emailer : TokenEmailer|None = None

        set_parameter("allowed_factor2", ParamType.JsonArray, self, options, "ALLOWED_FACTOR2", protected=True)
        set_parameter("enable_email_verification", ParamType.Boolean, self, options, "ENABLE_EMAIL_VERIFICATION")
        set_parameter("enable_password_reset", ParamType.Boolean, self, options, "ENABLE_PASSWORD_RESET")
        self._email_token_storage = self._key_storage
        if self._user_storage and (self.__enable_email_verification or self.__enable_password_reset):
            if ("email_token_storage" in options):
                self.__email_token_storage = options["email_token_storage"]
            self.__token_emailer = TokenEmailer(self._user_storage, self._key_storage, options)

    
    async def login(self, username : str, 
                    params : AuthenticationParameters, 
                    extra_fields : Mapping[str,Any] = {}, 
                    persist : bool=False, 
                    user : User|None=None, bypass_2fa : bool=False) -> SessionTokens:
        """
        Performs a user login
        
        * Authenticates the username and password
        * Creates a session key - if 2FA is enabled, this is an anonymous session,
          otherwise it is bound to the user
        * Returns the user (without the password hash) and the session cookie.
        If the user object is defined, authentication (and 2FA) is bypassed
        
        :param username: the username to validate
        :param params: user-provided credentials (eg password) to authenticate with
        :param extra_fields: add these extra fields to the session key if authentication is successful
        :param persist: if passed, overrides the persistSessionId setting.
        :param user: if this is defined, the username and password are ignored and the given user is logged in.
                  The 2FA step is also skipped
            bypass2FA: if true, the 2FA step will be skipped
            
        :return
            Dict containing the user, user secrets, and session cookie and CSRF cookie and token.
            if a 2fa step is needed, it will be an anonymouos session, otherwise bound to the user
            
        :raise:
            CrossauthError: with ErrorCode of Connection, UserNotValid, 
                          PasswordNotMatch or UserNotExist.
        """
                
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, "Cannot call login if no user storage provided")
        
        secrets: UserSecrets = UserSecrets(userid="")
        defaultAuth = ""
        
        if not user:
            user_input_fields: UserInputFields = {
                "username": "", 
                "state": UserState.active,
                "factor1": ""
            }
            try:
                user_and_secrets = await self._user_storage.get_user_by_username(
                    username, 
                    {"skip_active_check": True, 
                    "skip_email_verified_check": True
                    })
                secrets = user_and_secrets["secrets"]
                user = user_and_secrets["user"]
                user_input_fields = user_and_secrets["user"]
            except Exception as e:
                ce = CrossauthError.as_crossauth_error(e)
                if ce.code == ErrorCode.Connection:
                    raise e
                
                for auth in self.authenticators:
                    if not self.authenticators[auth].require_user_entry():
                        user_input_fields: UserInputFields = {
                            "username": "", 
                            "state": UserState.active,
                            "factor1": ""
                        }
                        defaultAuth = auth
            
            if user_input_fields["username"] == "":
                raise CrossauthError(ErrorCode.UserNotExist)
            
            auth_key = user["factor1"] if user and "factor1" in user and user["factor1"] != "" else defaultAuth
            await self.authenticators[auth_key].authenticate_user(user_input_fields, secrets, params)
            
            user_and_secrets = await self._user_storage.get_user_by_username(
                username, 
                {"skip_active_check": True, 
                "skip_email_verified_check": True})
            secrets = user_and_secrets["secrets"]
            user = user_and_secrets["user"]
        else:
            user_and_secrets = await self._user_storage.get_user_by_username(
                user["username"], 
                {"skip_active_check": True, 
                "skip_email_verified_check": True})
            secrets = user_and_secrets["secrets"]

        # create a session ID - bound to user if no 2FA and no password change required, anonymous otherwise
        session_cookie: Cookie
        
        if user["state"] == UserState.password_change_needed:
            # create an anonymous session and store the username and 2FA data in it
            resp = await self.create_anonymous_session({
                "data": json.dumps({"passwordchange": {"username": user["username"] if user else ""}})
            })
            if (resp.session_cookie is None):
                raise CrossauthError(ErrorCode.InvalidSession, "Sessing cookie is missing")
            session_cookie = resp.session_cookie
        elif user["state"] == UserState.factor2_reset_needed:
            resp = await self.create_anonymous_session({
                "data": json.dumps({"factor2change": {"username": user["username"]}})
            })
            if (resp.session_cookie is None):
                raise CrossauthError(ErrorCode.InvalidSession, "Sessing cookie is missing")
            session_cookie = resp.session_cookie
        elif not bypass_2fa and "factor2" in user and user["factor2"] != "":
            # create an anonymous session and store the username and 2FA data in it
            result = await self.initiate_two_factor_login(user)
            if (result.session_cookie is None):
                raise CrossauthError(ErrorCode.InvalidSession, "Sessing cookie is missing")
            session_cookie = result.session_cookie
        else:
            session_key = await self.session.create_session_key(user["id"], extra_fields)
            #await self.sessionStorage.saveSession(user.id, session_key.value, session_key.dateCreated, session_key.expires)
            session_cookie = self.session.make_cookie(session_key, persist)

        # create a new CSRF token, since we have a new session
        csrf_token = self.csrf_tokens.create_csrf_token()
        csrf_cookie = self.csrf_tokens.make_csrf_cookie(csrf_token)
        csrfFormOrHeaderValue = self.csrf_tokens.make_csrf_form_or_header_token(csrf_token)
        
        # delete any password reset tokens that still exist for this user.
        try:
            await self.email_token_storage.delete_all_for_user(
                user["id"],
                KeyPrefix.password_reset_token
            )
        except Exception as e:
            CrossauthLogger.logger().warn(j({
                "msg": "Couldn't delete password reset tokens while logging in", 
                "user": username
            }))
            CrossauthLogger.logger().debug(j({"err": e}))

        # send back the cookies and user details
        return SessionTokens(
            session_cookie=session_cookie,
            csrf_cookie=csrf_cookie,
            csrf_form_or_header_value=csrfFormOrHeaderValue,
            user=user,
            secrets=secrets,
        )

    async def create_anonymous_session(self, extra_fields: Mapping[str,Any]|None=None) -> SessionTokens:
        if extra_fields is None:
            extra_fields = {}
        key = await self._session.create_session_key(None, extra_fields)
        session_cookie = self._session.make_cookie(key, False)
        csrf_data = await self.create_csrf_token()
        return SessionTokens(session_cookie, csrf_data.csrf_cookie, csrf_data.csrf_form_or_header_value, None, None)
        

    async def logout(self, session_id : str):
        key = await self._session.get_session_key(session_id)
        return await self._key_storage.delete_key(SessionCookie.hash_session_id(key["value"]))

    async def logout_from_all(self, userid : str|int, except_id : str|None=None):
        return await self._session.delete_all_for_user(userid, except_id)

    async def user_for_session_id(self, session_id : str):
        return await self._session.get_user_for_session_id(session_id)

    async def data_string_for_session_id(self, session_id : str) -> str|None:
        """
        Returns the data object for a session key, or undefined, as a JSON string 
        (which is how it is stored in the session table)
        
        If the user is undefined, or the key has expired, returns undefined.
        
        :param str session_id: the session id to look up in session storage

        :return: a string from the data field

        :raise :class:`crossauth_backend.CrossauthError`: with 
            :class:`ErrorCode` of `Connection`,  `InvalidSessionId`
            `UserNotExist` or `Expired`.
        """
        try:
            key_data = await self._session.get_user_for_session_id(session_id)
            return key_data.key["data"] if "data" in key_data.key else None
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            if ce.code == ErrorCode.Expired:
                return None
            raise ce

    async def data_for_session_id(self, session_id : str) -> Dict[str,Any]|None:
        """
        Returns the data object for a session id, or undefined, as an object.
        
        If the user is undefined, or the key has expired, returns undefined.
        
        :param str session_id: the session key to look up in session storage

        :return: a string from the data field

        :raise :class:`crossauth_backend.CrossauthError`: with 
            :class:`ErrorCode` of `Connection`,  `InvalidSessionId`
            `UserNotExist` or `Expired`.
        """
        str_data = await self.data_string_for_session_id(session_id)
        if not str_data:
            return None
        return json.loads(str_data)

    async def create_csrf_token(self) -> Csrf:
        """
        Creates and returns a signed CSRF token based on the session ID

        :return: a CSRF cookie and value to put in the form or CSRF header
        """
        csrf_token = self._csrf_tokens.create_csrf_token()
        csrf_form_or_header_value = self._csrf_tokens.make_csrf_form_or_header_token(csrf_token)
        csrf_cookie = self._csrf_tokens.make_csrf_cookie(csrf_token)
        return Csrf(csrf_cookie,csrf_form_or_header_value)

    async def create_csrf_form_or_header_value(self, csrf_cookie_value: str):
        """
        Validates the signature on the CSRF cookie value and returns a
        value that can be put in the form or CSRF header value.
        
        :param str csrf_cookie_value: the value from the CSRF cookie

        :return: the value to put in the form or CSRF header
        """
        csrf_token = self._csrf_tokens.unsign_cookie(csrf_cookie_value)
        return self._csrf_tokens.make_csrf_form_or_header_token(csrf_token)

    def get_session_id(self, session_cookie_value: str):
        """
        Returns the session ID from the signed session cookie value
        
        :param str session_cookie_value: value from the session ID cookie

        :return: the usigned cookie value.

        :raises :class:`crossauth_backend.CrossauthError` with `InvalidKey`
            if the signature is invalid.
        """
        return self._session.unsign_cookie(session_cookie_value)

    def validate_double_submit_csrf_token(self, csrf_cookie_value : str, csrf_form_or_header_value: str):
        """
        Throws :class:`crossauth_backend.CrossauthError` with 
        `InvalidKey` if the passed CSRF token is not valid for the given
        session ID.  Otherwise returns without error
        
        :param strcsrf_cookie_value: the CSRF cookie value
        :param str csrf_form_or_header_value: the value from the form field or
               CSRF header
        """
        if not csrf_cookie_value or not csrf_form_or_header_value:
            raise CrossauthError(ErrorCode.InvalidCsrf, "CSRF missing from either cookie or form/header value")
        self._csrf_tokens.validate_double_submit_csrf_token(csrf_cookie_value, csrf_form_or_header_value)

    def validate_csrf_cookie(self, csrf_cookie_value : str):
        """
        Throws :class:`crossauth_backend.CrossauthError` with `InvalidKey` if 
        the passed CSRF cookie value is not valid (ie invalid signature)
        :param str csrf_cookie_value: the CSRF cookie value 

        """
        self._csrf_tokens.validate_csrf_cookie(csrf_cookie_value)

    async def update_session_activity(self, session_id : str):
        """
        If session_idle_timeout is set, update the last activcity time in key 
        storage to current time.
        
        :param str session_id: the session Id to update.

        """
        key_data = await self._session.get_session_key(session_id)
        if self._session.idle_timeout > 0:
            await self._session.update_session_key({
                'value': key_data['value'],
                'lastactive': datetime.now(),
            })

    async def update_session_data(self, session_id: str, name: str, value: Mapping[str, Any]) -> None:
        """
        Update a field in the session data.
        
        The `data` field in the session entry is assumed to be a JSON string.
        The field with the given name is updated or set if not already set.
        :param str session_id: the session Id to update.
        :param str name: of the field.
        :param Mapping[str, Any] value: new value to store

        """
        hashed_session_key = self._session.hash_session_id(session_id)
        CrossauthLogger.logger().debug(j({"msg": f"Updating session data value{name}", "hashedSessionCookie": Crypto.hash(session_id)}))
        await self._key_storage.update_data(hashed_session_key, name, value)

    async def update_many_session_data(self, session_id: str, data_array: List[KeyDataEntry]) -> None:
        """
        Update field sin the session data.
        
        The `data` field in the session entry is assumed to be a JSON string.
        The field with the given name is updated or set if not already set.
        :param str session_id: the session Id to update.
        :param  List[crossauth_backend.KeyDataEntry] data_array: names and values.

        """
        hashed_session_key = self._session.hash_session_id(session_id)
        CrossauthLogger.logger().debug(j({"msg": f"Updating session data", "hashedSessionCookie": Crypto.hash(session_id)}))
        await self._key_storage.update_many_data(hashed_session_key, data_array)

    async def delete_session_data(self, session_id: str, name: str) -> None:
        """
        Deletes a field from the session data.
        
        The `data` field in the session entry is assumed to be a JSON string.
        The field with the given name is updated or set if not already set.
        :param str session_id; the session Id to update.

        """
        hashed_session_key = self._session.hash_session_id(session_id)
        CrossauthLogger.logger().debug(j({"msg": f"Updating session data value{name}", "hashedSessionCookie": Crypto.hash(session_id)}))
        await self._key_storage.delete_data(hashed_session_key, name)

    async def delete_session(self, session_id: str) -> None:
        """
        Deletes the given session ID from the key storage (not the cookie)
        
        :param str session_id: the session Id to delete

        """
        return await self._key_storage.delete_key(self._session.hash_session_id(session_id))

    async def create_user(self, user: User, params: UserSecrets, repeat_params: UserSecrets|None = None, skip_email_verification: bool = False, empty_password: bool = False) -> User:
        if not self._user_storage:
            raise Exception("Cannot call createUser if no user storage provided")

        if user['factor1'] not in self._authenticators:
            raise Exception("Authenticator cannot create users")

        if self._authenticators[user['factor1']].skip_email_verification_on_signup():
            skip_email_verification = True

        secrets = await self._authenticators[user['factor1']].create_persistent_secrets(user['username'], params, repeat_params) if not empty_password else None
        secrets = secrets
        new_user = await self._user_storage.create_user(user, secrets) if not empty_password else await self._user_storage.create_user(user)

        if not skip_email_verification and self.__enable_email_verification and self.__token_emailer:
            raise CrossauthError(ErrorCode.NotImplemented, "Email verification is not supported in this version")
            #await self.token_emailer.send_email_verification_token(new_user['id'], None)

        return new_user

    async def delete_user_by_username(self, username: str) -> None:
        if not self._user_storage:
            raise Exception("Cannot call deleteUser if no user storage provided")
        await self._user_storage.delete_user_by_username(username)

    async def initiate_two_factor_signup(self, 
            user: User, 
            params: UserSecrets, 
            session_id: str, 
            repeat_params: UserSecrets|None) -> UserIdAndData:
        """Creates a user with 2FA enabled.
        
        The user storage entry will be createed, with the state set to
        `awaitingtwofactorsetup`.   The passed session key will be updated to 
        include the username and details needed by 2FA during the configure step.  
        
        :param user: details to save in the user table
        :param params: params the parameters needed to authenticate with factor1
                    (eg password)
        :param session_id: the anonymous session cookie 
        :param repeat_params: if passed, these will be compared with `params` and
                    if they don't match, `PasswordMatch` is thrown.
        
        :return:
            Dict containing:
                userid: the id of the created user.  
                userData: data that can be displayed to the user in the page to 
                         complete 2FA set up (eg the secret key and QR codee for TOTP),
        """
        if ("factor1" not in user or "factor2" not in user):
            raise CrossauthError(ErrorCode.Configuration, "factor1 and factor2 must be in user to use 2FA")
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, "Cannot call initiateTwoFactorSignup if no user storage provided")
        if user["factor1"] not in self.authenticators:
            raise CrossauthError(ErrorCode.Configuration, "Authenticator cannot create users")
        if user["factor2"] not in self.authenticators:
            raise CrossauthError(ErrorCode.Configuration, "Two factor authentication not enabled for user")
        
        authenticator = self.authenticators[user["factor2"]]
        # const session_id = this.session.unsignCookie(sessionCookieValue);
        factor2_data = await authenticator.prepare_configuration(user)
        user_data = {} if factor2_data is None else factor2_data.get("userData", {})
        session_data = {} if factor2_data is None else factor2_data.get("sessionData", {})

        factor1_secrets = await self.authenticators[user["factor1"]].create_persistent_secrets(user["username"], params, repeat_params)
        factor1_secrets = factor1_secrets
        user["state"] = UserState.awaiting_two_factor_setup
        await self.key_storage.update_data(
            SessionCookie.hash_session_id(session_id), 
            "2fa",
            session_data)

        new_user = await self._user_storage.create_user(user, factor1_secrets)
        return UserIdAndData(new_user["id"], user_data, None)

    async def initiate_two_factor_setup(self, user: User, new_factor2: str|None, session_id: str) -> Mapping[str, Any]:
        """
        Begins the process of setting up 2FA for a user which has already been 
        created and activated.  Called when changing 2FA or changing its parameters.
        
        :param user: the logged in user
        :param new_factor2: new second factor to change user to
        :param session_id: the session cookie for the user
            
        :return
            the 2FA data that can be displayed to the user in the configure 2FA
            step (such as the secret and QR code for TOTP).
        """
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, "Cannot call initiateTwoFactorSetup if no user storage provided")
        
        # const session_id = this.session.unsignCookie(sessionCookieValue);
        if new_factor2 and new_factor2 != "none":
            if new_factor2 not in self.authenticators:
                raise CrossauthError(ErrorCode.Configuration, "Two factor authentication not enabled for user")
            
            authenticator = self.authenticators[new_factor2]
            factor2_data = await authenticator.prepare_configuration(user)
            userData = {} if factor2_data is None else factor2_data["userData"] or {}
            sessionData = {} if factor2_data is None else factor2_data["sessionData"] or {}
            
            sessionData["userData"] = userData

            await self._key_storage.update_data(
                SessionCookie.hash_session_id(session_id),
                "2fa",
                sessionData)
            return userData

        # this part is for turning off 2FA
        await self._user_storage.update_user({"id": user["id"], "factor2": new_factor2 or ""})
        await self._key_storage.update_data(
            SessionCookie.hash_session_id(session_id), 
            "2fa",
            None)
        return {}
    
    async def repeat_two_factor_signup(self, session_id: str) -> UserIdAndData:
        """
        This can be called if the user has finished signing up with factor1 but
        closed the browser before completing factor2 setup.  Call it if the user
        signs up again with the same factor1 credentials.
        
        :param session_id: the anonymous session ID for the user
            
        :return:
            Dict containing:
                userid: the id of the created user
                userData: data that can be displayed to the user in the page to 
                        complete 2FA set up (eg the secret key and QR code for TOTP),
                secrets: data that is saved in the session for factor2.  In the
                        case of TOTP, both `userData` and `secrets` contain the shared
                        secret but only `userData` has the QR code, since it can be
                        generated from the shared secret.
        """
        if not self._user_storage:
            raise CrossauthError(
                ErrorCode.Configuration, 
                "Cannot call repeatTwoFactorSignup if no user storage provided"
            )
        
        session_data = await self.data_for_session_id(session_id)
        if (session_data is None):
            raise CrossauthError(ErrorCode.InvalidSession, "No 2FA data found in session")
        session_data = (session_data)["2fa"]
        username = session_data["username"]
        factor2 = session_data["factor2"]
        
        # const sessionId = this.session.unsignCookie(sessionId);
        hashed_session_key = SessionCookie.hash_session_id(session_id)
        session_key = await self.key_storage.get_key(hashed_session_key)
        authenticator = self.authenticators[factor2]

        resp = await authenticator.reprepare_configuration(username, session_key)
        user_data = {} if resp is None else resp.get("userData", {})
        secrets = {} if resp is None else resp.get("secrets", {})
        new_session_data = {} if resp is None else resp.get("newSessionData", {})
        
        if new_session_data:
            await self.key_storage.update_data(hashed_session_key, "2fa", new_session_data)

        user_result = await self._user_storage.get_user_by_username(
            username, 
            {"skip_active_check": True, 
            "skip_email_verified_check": True})
        user = user_result["user"]
        if (not user_data): user_data = {}
        return UserIdAndData(user["id"], user_data, cast(UserSecrets, secrets))
    
    async def complete_two_factor_setup(self, params: AuthenticationParameters, session_id: str) -> User:
        """
        Authenticates with the second factor.  
        
        If successful, the new user object is returned.  Otherwise an exception
        is thrown,
        :param params the parameters from user input needed to authenticate (eg TOTP code)
        :param session_id the session cookie value (ie still signed)
        :return the user object
        :raise CrossauthError if authentication fails.
        """
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, "Cannot call completeTwoFactorSetup if no user storage provided")
        
        new_signup = False
        
        result = await self.session.get_user_for_session_id(session_id, {
            "skip_active_check": True
        })
        user = result.user
        key = result.key
        
        if user and (user["state"] != UserState.active and user["state"] != UserState.factor2_reset_needed):
            raise CrossauthError(ErrorCode.UserNotActive)
        
        if not key:
            raise CrossauthError(ErrorCode.InvalidKey, "Session key not found")
        
        if ("data" not in key):
            raise CrossauthError(ErrorCode.InvalidSession, "No 2FA data in session")
        data = KeyStorage.decode_data(key["data"])["2fa"]
        # let data = getJsonData(key)["2fa"];
        
        if not data or not data.get("factor2") or not data.get("username"):
            raise CrossauthError(ErrorCode.Unauthorized, "Two factor authentication not initiated")
        
        username = data["username"]
        authenticator = self.authenticators[data["factor2"]]
        
        if not authenticator:
            raise CrossauthError(ErrorCode.Configuration, "Unrecognised second factor authentication")
        
        new_secrets: PartialUserSecrets = {}
        secret_names = authenticator.secret_names()
        
        for secret in data:
            if secret in secret_names:
                new_secrets[secret] = data[secret]
        
        await authenticator.authenticate_user(None, data, params)

        if not user:
            new_signup = True
            resp = await self._user_storage.get_user_by_username(username, {
                "skip_active_check": True, 
                "skip_email_verified_check": True
            })
            user = resp["user"]
        
        skip_email_verification = authenticator.skip_email_verification_on_signup() == True
        
        if not user:
            raise CrossauthError(ErrorCode.UserNotExist, "Couldn't fetch user")
        
        state = UserState.awaiting_email_verification if not skip_email_verification and self.__enable_email_verification else UserState.active
        new_user : PartialUser = {
            "id": user["id"],
            "state": state,
            "factor2": data["factor2"],
        }
        
        if len(authenticator.secret_names()) > 0:
            await self._user_storage.update_user(new_user, new_secrets)
        else:
            await self._user_storage.update_user(new_user)

        if not skip_email_verification and new_signup and \
            self.__enable_email_verification and self.__token_emailer:
            await self.__token_emailer.send_email_verification_token(user["id"], "")
        
        await self.key_storage.update_data(SessionCookie.hash_session_id(key["value"]), "2fa", None)
        
        return {**user, **new_user}

    async def initiate_two_factor_login(self, user: User) -> SessionTokens:
        """
        Initiates the two factor login process.
        
        Creates an anonymous session and corresponding CSRF token
        
        Args:
            user: the user, which should already have been authenticated with factor1
            
        Returns:
            a new anonymous session cookie and corresponding CSRF cookie and token.
        """
        if "factor2" not in user:
            raise CrossauthError(ErrorCode.Configuration, "Cannot initiate 2FA as factor2 not in user")
        authenticator = self._authenticators[user["factor2"]]
        secrets = await authenticator.create_one_time_secrets(user)
        
        session_data : Dict[str, Any]= {
            "2fa": {
                "username": user["username"],
                "twoFactorInitiated": True,
                "factor2": user["factor2"],
                **secrets
            }
        }
        
        session_result = await self.create_anonymous_session({"data": json.dumps(session_data)})
        session_cookie = session_result.session_cookie
        csrf_token = self.csrf_tokens.create_csrf_token()
        csrf_cookie = self.csrf_tokens.make_csrf_cookie(csrf_token)
        csrf_form_or_header_value = self.csrf_tokens.make_csrf_form_or_header_token(csrf_token)
        
        return SessionTokens(session_cookie, csrf_cookie, csrf_form_or_header_value, None, None)
    
    async def initiate_two_factor_page_visit(self, 
                user: User, 
                session_id: str, 
                request_body: Mapping[str, Any], 
                url: str|None=None, 
                content_type: str|None = None) -> SessionTokens:
        """
        Initiates the two factor process when visiting a protected page.
        
        Creates an anonymous session and corresponding CSRF token
        
        :param user: the user, which should already have been authenticated with factor1
        :param session_id: the logged in session associated with the user
        :param request_body: the parameters from the request made before 
            being redirected to factor2 authentication
        :param url: the requested url, including path and query parameters
            content_type: optional content type from the request
            
        :return
            If a token was passed a new anonymous session cookie and 
            corresponding CSRF cookie and token.
        """
        if ("factor2" not in user):
            raise CrossauthError(ErrorCode.Configuration, 
                    "Cannot initiate factor2 page visti as factor2 not in user")
        authenticator = self._authenticators[user["factor2"]]
        secrets = await authenticator.create_one_time_secrets(user)

        session_cookie: Cookie|None = None
        csrf_cookie: Cookie|None = None
        csrf_form_or_header_value: str|None = None
        
        # const sessionId = this.session.unsignCookie(sessionCookieValue);
        hashed_session_id = SessionCookie.hash_session_id(session_id)
        CrossauthLogger.logger().debug(
            f"initiate_two_factor_page_visit {user["username"]} {session_id} {hashed_session_id}"
        )
        
        new_data: Dict[str, Any] = {
            "username": user["username"],
            "factor2": user["factor2"],
            "secrets": secrets,
            "body": request_body,
            "url": url
        }
        
        if content_type:
            new_data["content-type"] = content_type
            
        await self.key_storage.update_data(hashed_session_id, "pre2fa", new_data)

        return SessionTokens(session_cookie, csrf_cookie, csrf_form_or_header_value, None, None)
    
    async def complete_two_factor_page_visit(self, params : AuthenticationParameters, session_id : str):
        """
        Completes 2FA when visiting a protected page.  
        
        If successful, returns.  Otherwise an exception is thrown.
        
        :param params: the parameters from user input needed to authenticate 
                   (eg TOTP code).  Passed to the authenticator
        :param session_id: the session cookie value (ie still signed)
            
        :raise
            CrossauthError: if authentication fails.
        """
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, 
                    "Cannot call completeTwoFactorPageVisit if no user storage provided")
        
        result = await self.session.get_user_for_session_id(session_id)
        key = result.key
        
        if not key:
            raise CrossauthError(ErrorCode.InvalidKey, "Session key not found")
        
        if ("data" not in key):
            raise CrossauthError(ErrorCode.InvalidSession, 
                    "Cannot complete 2FA page visit: 2FA data not in session")
        data = KeyStorage.decode_data(key["data"])
        # let data = getJsonData(key);
        
        if "pre2fa" not in data:
            raise CrossauthError(ErrorCode.Unauthorized, "Two factor authentication not initiated")
        
        user_result = await self._user_storage.get_user_by_username(data["pre2fa"]["username"])
        secrets = user_result.get('secrets')

        authenticator = self._authenticators.get(data["pre2fa"]["factor2"])
        if not authenticator:
            raise CrossauthError(ErrorCode.Configuration, "Unrecognised second factor authentication")
        
        new_secrets: UserSecretsInputFields = {}
        secret_names = authenticator.secret_names()
        
        for secret in secrets:
            #if (secretNames.includes(secret)) newSecrets[secret] = data[secret];
            if secret in secret_names and secret in secrets:
                new_secrets[secret] = secrets[secret]
        
        # Merge new_secrets with data.pre2fa.secrets, with data.pre2fa.secrets taking precedence
        pre2fasecrets = cast(UserSecretsInputFields, data["pre2fa"]["secrets"])
        combined_secrets : UserSecretsInputFields = {**new_secrets, **pre2fasecrets}
        
        await authenticator.authenticate_user(None, combined_secrets, params)
        await self.key_storage.update_data(SessionCookie.hash_session_id(key["value"]), "pre2fa", None)


    async def cancel_two_factor_page_visit(self, session_id : str) -> Dict[str,Any]:
        """
        Cancels the 2FA that was previously initiated but not completed..
        
        If successful, returns.  Otherwise an exception is thrown.
        
        :param session_id: the session id (unsigned)
            
        :return
            Dict[str, Any]: the 2FA data that was created on initiation
            
        :raise
            CrossauthError: of `Unauthorized` if 2FA was not initiated.
        """
        user_data = await self.session.get_user_for_session_id(session_id)
        key = user_data.key
        
        if not key:
            raise CrossauthError(ErrorCode.InvalidSession, "Session key not found")
            
        if ("data" not in key):
            CrossauthLogger.logger().debug(j({"mag": "Cancelling 2FA page visit - no data in session.  Doing nothing"}))
            return {}
        
        data = KeyStorage.decode_data(key["data"])
        # data = get_json_data(key)
        
        if "pre2fa" not in data:
            raise CrossauthError(ErrorCode.Unauthorized, "Two factor authentication not initiated")
            
        await self.key_storage.update_data(
            SessionCookie.hash_session_id(key["value"]), 
            "pre2fa", 
            None
        )
        
        return data["pre2fa"]
    
    async def complete_two_factor_login(self, 
            params : AuthenticationParameters, 
            session_id : str, 
            extra_fields:Mapping[str, Any] = {}, 
            persist:bool=False) -> SessionTokens:
        """
        Performs the second factor authentication as the second step of the login
        process
        
        If authentication is successful, the user's state will be set to active
        and a new session will be created, bound to the user.  The anonymous session
        will be deleted.
        
        :param params: the user-provided parameters to authenticate with (eg TOTP code).
        :param session_id: the user's anonymous session
        :param extra_fields: extra fields to add to the user-bound new session table entry
        :param persist: if true, the cookie will be perstisted (with an expiry value);
                    otberwise it will be a session-only cookie.

        :return AuthResult containing:
                session_cookie: the new session cookie
                csrf_cookie: the new CSRF cookie
                csrf_form_or_header_value: the new CSRF token corresponding to the cookie
                user: the newly-logged in user.
        """
            
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, 
                               "Cannot call completeTwoFactorLogin if no user storage provided")
        
        key_result = await self.session.get_user_for_session_id(session_id)
        key = key_result.key
        
        if not key or "data" not in key or key["data"] == "":
            raise CrossauthError(ErrorCode.Unauthorized)
        
        data = KeyStorage.decode_data(key["data"])["2fa"]
        # let data = getJsonData(key)["2fa"];
        username = data["username"]
        factor2 = data["factor2"]
        
        user_result = await self._user_storage.get_user_by_username(username)
        user = user_result["user"]
        secrets = user_result["secrets"]
        
        authenticator = self._authenticators.get(factor2)
        if not authenticator:
            raise CrossauthError(ErrorCode.Configuration, 
                               f"Second factor {factor2} not enabled")
        
        # Merge secrets and data dictionaries for authentication
        auth_data = cast(UserSecretsInputFields, {**secrets, **data})
        await authenticator.authenticate_user(user, auth_data, params)

        new_session_key = await self.session.create_session_key(user["id"], extra_fields)
        await self.key_storage.delete_key(SessionCookie.hash_session_id(key["value"]))
        session_cookie = self.session.make_cookie(new_session_key, persist)

        csrf_token = self.csrf_tokens.create_csrf_token()
        csrf_cookie = self.csrf_tokens.make_csrf_cookie(csrf_token)
        csrf_form_or_header_value = self.csrf_tokens.make_csrf_form_or_header_token(csrf_token)
        
        try:
            await self.email_token_storage.delete_all_for_user(user["id"], 
                            KeyPrefix.password_reset_token)
        except Exception as e:
            CrossauthLogger.logger().warn(j({"msg": "Couldn't delete password reset tokens while logging in", 
                                          "user": username}))
            CrossauthLogger.logger().debug(j({"err": str(e)}))
        
        return SessionTokens(
            session_cookie=session_cookie,
            csrf_cookie=csrf_cookie,
            csrf_form_or_header_value=csrf_form_or_header_value,
            user=user,
            secrets=None
        )
    async def request_password_reset(self, email: str) -> None:
        """
        Sends a password reset token
        :param email: the user's email (where the token will be sent)
        """
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, 
                    "Cannot call requestPasswordReset if no user storage provided")
        
        result = await self._user_storage.get_user_by_email(email, {"skip_active_check": True})
        user = result["user"]
        
        if (user["state"] != UserState.active and 
            user["state"] != UserState.password_reset_needed and 
            user["state"] != UserState.password_and_factor2_reset_needed):
            raise CrossauthError(ErrorCode.UserNotActive)
        
        if self.__token_emailer:
            await self.__token_emailer.send_password_reset_token(user["id"])


    async def apply_email_verification_token(self, token: str) -> User:
        """
        Takes an email verification token as input and applies it to the user storage.
        
        The state is reset to active.  If the token was for changing the password, the new
        password is saved to the user in user storage.
        
        Args:
            token: the token to apply
            
        Returns:
            the new user record
        """
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, "Cannot call applyEmailVerificationToken if no user storage provided")
        
        CrossauthLogger.logger().debug(j({"msg": "applyEmailVerificationToken"}))
        
        if not self.__token_emailer:
            raise CrossauthError(ErrorCode.Configuration, "Email verification not enabled")
        
        try:
            # Verify the email verification token
            token_result = await self.__token_emailer.verify_email_verification_token(token)
            userid = token_result["userid"]
            new_email = str(token_result["newEmail"])
            
            # Get user by ID
            user_result = await self._user_storage.get_user_by_id(userid, {"skip_email_verified_check":True})
            user = user_result["user"]
            
            # Handle old email logic
            old_email: str|None = None
            if "email" in user and user["email"] != "":
                old_email = user["email"]
            else:
                old_email = user["username"]
            
            # Create new user partial object
            new_user: PartialUser = {
                "id": user["id"],
            }
            
            # Update state if it was awaiting email verification
            if user["state"] == UserState.awaiting_email_verification:
                new_user["state"] = "active"
            
            # Update email if newEmail is not empty
            if new_email != "":
                new_user["email"] = new_email
            else:
                old_email = None
            
            # Update user in storage
            await self._user_storage.update_user(new_user)
            
            # Delete the email verification token
            await self.__token_emailer.delete_email_verification_token(token)
            
            # Return merged user object
            merged_user = cast(User, {**user, **new_user, "oldEmail": old_email})
            return merged_user  
        
        finally:
            pass

    async def user_for_password_reset_token(self, token: str) -> User:
        """
        Returns the user associated with a password reset token
        
        :param token: the token that was emailed
            
        :return: the user
            
        :raise CrossauthError: if the token is not valid.
        """
        if not self.__token_emailer:
            raise CrossauthError(ErrorCode.Configuration, "Password reset not enabled")
        return await self.__token_emailer.verify_password_reset_token(token)
    
    async def change_secrets(self,
                           username: str,
                           factor_number: int,  # 1 or 2
                           new_params: AuthenticationParameters,
                           repeat_params: AuthenticationParameters|None = None,
                           old_params: AuthenticationParameters|None = None) -> User:
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, "Cannot call changeSecrets if no user storage provided")
        
        user_data = await self._user_storage.get_user_by_username(username)
        user = user_data["user"]
        secrets = user_data["secrets"]
        
        factor : str|None = None
        if (factor_number == 1):
            factor = user["factor1"]
        elif ("factor2" in user and factor_number == 2):
            factor = user["factor2"]
        if (factor is None):
            raise CrossauthError(ErrorCode.BadRequest, "Factor number requesting change for is not in user")
        
        if old_params is not None:
            await self.authenticators[factor].authenticate_user(user, secrets, old_params)
        
        new_secrets = await self._authenticators[user["factor1"]].create_persistent_secrets(
            user["username"], new_params, repeat_params
        )

        
        await self._user_storage.update_user(
            {"id": user["id"]},
            cast(PartialUserSecrets,new_secrets)
        )

        # delete any password reset tokens
        try:
            await self.__email_token_storage.delete_all_for_user(
                user["id"],
                KeyPrefix.password_reset_token
            )
        except Exception as e:
            CrossauthLogger.logger().warn(j({
                "msg": "Couldn't delete password reset tokens while logging in",
                "user": username
            }))
            CrossauthLogger.logger().debug(j({"err": str(e)}))

        return user
    
    async def update_user(
        self, 
        current_user: User, 
        new_user: User, 
        skip_email_verification: bool = False, 
        as_admin: bool = False
    ) -> TokensSent:
        """
        Updates a user entry in storage
        :param current_user the current user details
        :param new_user the new user details
        :return dict with emailVerificationTokenSent and passwordResetTokenSent booleans
        """
        new_email: str|None = None
        
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, "Cannot call updateUser if no user storage provided")
        
        if "id" not in current_user:
            raise CrossauthError(ErrorCode.UserNotExist, "Please specify a user id")
        
        if "username" not in current_user or current_user["username"] == "":
            raise CrossauthError(ErrorCode.UserNotExist, "Please specify a userername")
        
        # Extract email, username, password and collect remaining fields
        email = new_user["email"] if "email" in new_user else None
        username = new_user["username"]
        
        # Create rest dictionary with all other fields except email, username, password
        rest : PartialUser = {}
        for key, value in vars(new_user).items():
            if key not in ['email', 'username', 'password']:
                rest[key] = value
        
        rest['userid'] = current_user["userid"] if "userid" in current_user else None # type: ignore
        rest['id'] = current_user["id"] if "id" in current_user else ""
        has_email = False
        
        if email:
            new_email = email
            TokenEmailer.validate_email(new_email)
            has_email = True
        elif username:
            new_email = username
            try:
                TokenEmailer.validate_email(current_user["username"])
                has_email = True
            except:  # not in email format - can ignore
                pass
            if has_email:
                TokenEmailer.validate_email(new_email)
        
        if (new_email is None):
            raise CrossauthError(ErrorCode.UnknownError) # pathological
        
        if not skip_email_verification and self.__enable_email_verification and has_email:
            if self.__token_emailer:
                await self.__token_emailer.send_email_verification_token(current_user["id"], new_email)
        else:
            if email:
                rest['email'] = email
            if username:
                rest['username'] = username
        
        if (new_user["state"] == UserState.password_reset_needed or 
            new_user["state"] == UserState.password_and_factor2_reset_needed):
            if self.__token_emailer:
                await self.__token_emailer.send_password_reset_token(current_user["id"], {}, as_admin)
        
        await self._user_storage.update_user(rest)
        
        return TokensSent((not skip_email_verification and 
                                self.__enable_email_verification and 
                                has_email),
                          (new_user["state"] == UserState.password_reset_needed or 
                                new_user["state"] == UserState.password_and_factor2_reset_needed) )

    async def reset_secret(self, 
            token: str,
            factror_number: int,  # 1 or 2
            params: AuthenticationParameters,
            repeat_params: AuthenticationParameters|None = None) -> User:
        """
        Resets the secret for factor1 or 2 (eg reset password)
        
        :param token: the reset password token that was emailed
        :param factror_number: which factor to reset (1 or 2)
        :param params: the new secrets entered by the user (eg new password)
        :param repeat_params: optionally, repeat of the secrets. If passed, 
                an exception will be thrown if they do not match
                         
        :return the user object
            
        :raise CrossauthError: if the repeat_params don't match params,
                the token is invalid or the user storage cannot be updated.
        """
        if not self._user_storage:
            raise CrossauthError(ErrorCode.Configuration, "Cannot call resetSecret if no user storage provided")
                
        if not self.__token_emailer:
            raise CrossauthError(ErrorCode.Configuration, "Password reset not enabled")
        
        user = await self.user_for_password_reset_token(token)
        factor : str|None = None
        if (factror_number == 1):
            factor = user["factor1"]
        elif (factror_number == 2 and "factor2" in user):
            factor = user["factor2"]
        if (factor is None):
            raise CrossauthError(ErrorCode.BadRequest, "No factor2 for user but factor 2 reset requested")
        
        if not self.__token_emailer:
            raise CrossauthError(ErrorCode.Configuration)
        
        new_state = (UserState.factor2_reset_needed 
                   if user["state"] == UserState.password_and_factor2_reset_needed 
                   else UserState.active)
        
        secrets = await self._authenticators[factor].create_persistent_secrets(user["username"], params, repeat_params)
        await self._user_storage.update_user(
            {"id": user["id"], "state": new_state},
            cast(PartialUserSecrets,secrets))
        
        
        # this.keyStorage.deleteKey(TokenEmailer.hashPasswordResetToken(token));
        
        # delete all password reset tokens
        try:
            await self.__email_token_storage.delete_all_for_user(user["id"], 
                                                KeyPrefix.password_reset_token)
        except Exception as e:
            CrossauthLogger.logger().warn(j({"msg": "Couldn't delete password reset tokens while logging in", 
                                           "user": user["username"]}))
            CrossauthLogger.logger().debug(j({"err": str(e)}))
        
        return {**user, "state": new_state}

    @property
    def session_cookie_name(self):
        """ Returns the name used for session ID cookies. """
        return self._session.cookie_name
    
    @property
    def session_cookie_path(self):
        """ Returns the name used for session ID cookies """
        return self._session.path
    
    @property
    def csrf_cookie_name(self):
        """ Returns the name used for CSRF token cookies. """
        return self._csrf_tokens.cookie_name
    
    @property
    def csrf_cookie_path(self):
        """ Returns the name used for CSRF token cookies. """
        return self._csrf_tokens.path
    
    @property
    def csrf_header_name(self):
        """ Returns the name used for CSRF token cookies """
        return self._csrf_tokens.header_name
    