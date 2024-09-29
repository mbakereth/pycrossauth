# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from typing import Any, Dict, Optional, TypedDict, NotRequired
import json
from datetime import datetime
from nulltype import NullType
from crossauth_backend.common.logger import CrossauthLogger, j

class Key(TypedDict):
    """
    A key (eg session ID, email reset token) as stored in a database table.
 
    The fields defined here are the ones used by Crossauth.  You may add
    others.
    """

    value : str
    """ The value of the keykey.
     In a cookie, the value part of cookiename=value; options... 
     """

    created : datetime
    """ The datetime/time the key was created, in local time on the server """

    expires : datetime | NullType
    """ The datetime/time the key expires """

    userid : NotRequired[str | int | NullType]
    """ the user this key is for (or undefined for an anonymous session ID)
     
     It accepts the value null as usually this is the value stored in the
     database, rather than undefined.  Some functions need to differentiate
     between a null value as opposed to the value not being defined (eg for
     a partial updatetime).
     """

    lastactive : NotRequired[datetime]
    """ The datetime/time key was last used (eg last time a request was made
     with this value as a session ID)
     """

    data : NotRequired[str]
    """ Additional key-specific data (eg new email address for email change).
     
     While application specific, any data Crossauth puts in this field
     is a strified JSON, with its own key so it can co-exist with
     other data.
     """

class PartialKey(TypedDict, total = False):
    """
    Same as :class:`crossauth_backend.Key` but all fields are NotRequired
    """

    value : str
    created : datetime
    expires : datetime | NullType
    userid : Optional[str | int | NullType]
    lastactive : Optional[datetime]
    data : Optional[str]


class ApiKey(Key):
    """
    An API key is a str that can be used in place of a username and 
    password.  These are not automatically created, like OAuth access tokens.
    """

    name : str
    """ A name for the key, unique to the user """

def get_json_data(key: Key) -> Dict[str, Any]:
    """
    Parses the data field in the key as a JSON object

    :param crossauth_backend.Key key: the key to extract the data field from

    :return: the data as dict
    """
    if ("data" not in key):
        return {}
    try:
        return json.loads(key["data"])
    except json.JSONDecodeError:
        CrossauthLogger.logger().warn(j({"msg": "data in key is not JSON"}))
        return {}

class UserInputFields(TypedDict):
    """
    Describes a user as fetched from the user storage (eg, database table),
    excluding auto-generated fields such as an auto-generated ID

    This is extendible with additional fields - provide them to the 
    :class:`UserStorage` class as `extraFields`.

    You may want to do this if you want to pass additional user data back to the 
    caller, eg real name.

    The fields defined here are the ones used by Crossauth.  You may add
    others.
    """

    username : str
    """The username.  This may be an email address or anything else,
    application-specific.
    """

    state : str
    """
    You are free to define your own states.  The ones Crossauth recognises
    are defined in :class:`UserState`.
    """

    email : NotRequired[str]
    """
    You can optionally include an email address field in your user table.
    If your username is an email address, you do not need a separate field.
    """

    admin : NotRequired[bool]
    """
    Whether or not the user has administrator priviledges (and can acess
    admin-only functions).
    """

    factor1 : str
    """
    Factor for primary authentication.

    Should match the name of an authenticator
    """

    factor2 : NotRequired[str]
    """
    Factor for second factor authentication.

    Should match the name of an authenticator
    """


class PartialUserInputFields(TypedDict, total=False):
    """
    Same as UserInputFields but all fields are not required
    """

    username : str
    state : str
    email : NotRequired[str]
    admin : NotRequired[bool]
    factor1 : NotRequired[str]
    factor2 : NotRequired[str]

class PartialUser(PartialUserInputFields, total=False):
    """
    Same as User but all fields are not required
    """
    id : str | int


class User(UserInputFields):
    """
    This adds ID to :class:`UserInputFields`.  

    If your `username` field is
    unique and immutable, you can omit ID (passing username anywhere an ID)
    is expected.  However, if you want users to be able to change their username,
    you should include ID field and make that immutable instead.
    """

    """ ID fied, which may be auto-generated """
    id : str | int

class UserSecretsInputFields(TypedDict, total=False):
    """
    Secrets, such as a password, are not in the User object to prevent them
    accidentally being leaked to the frontend.  All functions that return
    secrets return them in this separate object.

    The fields in this class are the ones that are not autogenerated by the
    database.
    """

    password : str
    totpsecret : str
    otp: str
    expiry: int

class PartialUserSecrets(UserSecretsInputFields, total=False):
    """
    Same as UserSecrets except all fields are NotRequired
    """

    userid : str|int


class UserSecrets(UserSecretsInputFields):
    """
    This adds the user ID toi :class:`UserSecretsInputFields`.
    """

    userid : str|int

class OAuthClient(TypedDict):
    """
    OAuth client data as stored in a database table
    """

    client_id : str
    """The client_id, which is auto-generated and immutable """

    confidential : bool
    """Whether or not the client is confidential (and can therefore
    keep the client secret secret) """

    client_name : str
    """
    A user-friendly name for the client (not used as part of the OAuth
    API).
    """

    client_secret : NotRequired[str|NullType]
    """
    Client secret, which is autogenerated.  
    
    If there is no client secret, it should be set to `undefined`.
    
    This field allows `null` as well as `undefined` this is used, for 
    example, when partially updating a client and you specifically 
    want to set the secret to undefined, as opposed to just not wishing
    to change the value.  Other than that, this value is always either
    a str or `undefined`.
    """

    redirect_uri : list[str]
    """
    An array of value redirect URIs for the client.
    """

    valid_flow : list[str]
    """
    An array of OAuth flows allowed for this client.  
    
    See :class:`OAuthFlows`.
    """


    userid : NotRequired[str|int|NullType]
    """
    ID of the user who owns this client, which may be `undefined`
    for not being owned by a specific user.  
    
    This field allows `null` as well as `undefined` this is used, for 
    example, when partially updating a client and you specifically 
    want to set the user ID to undefined, as opposed to just not wishing
    to change the value.  Other than that, this value is always either
    a str or number (depending on the ID type in your user storage)
    or `undefined`.
    """

class UserState:
    """
    These are used valiues for `state` in a :class:`crossauth_backend.User` object
    """

    active = "active"
    disabled = "disabled"
    awaiting_two_factor_setup = "awaitingtwofactorsetup"
    awaiting_email_verification = "awaitingemailverification"
    password_change_needed = "passwordchangeneeded"
    password_reset_needed = "passwordresetneeded"
    factor2_reset_needed = "factor2resetneeded"
    password_and_factor2_reset_needed = "passwordandfactor2resetneeded"

class KeyPrefix:
    """
    These are used prefixes for keye in a key storage entry
    """

    session = "s:"
    password_reset_token = "p:"
    email_verification_token = "e:"
    api_key = "api:"
    authorization_code = "authz:"
    access_token = "access:"
    refresh_token = "refresh:"
    mfa_token = "omfa:"
    device_code = "dc:"
    user_code = "uc:"
