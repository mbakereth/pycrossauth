# Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file

from crossauth_backend.authenticators.smsauth import SmsAuthenticator, SmsAuthenticatorOptions
from crossauth_backend.common.error import CrossauthError, ErrorCode

import os
from twilio.rest import Client
from typing import cast

class TwilioAuthenticator(SmsAuthenticator):
    """
    This authenticator sends a one-time code by SMS using the Twilio service.

    You will need to have the TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN
    environment variables set, otherwise the constructor will raise
    an exception
    """

    def __init__(self, options: SmsAuthenticatorOptions = {}):
        """
        Constructor

        :param options see :class:`crossauth_backend.SmsAuthenticatorOptions`  
        """

        super().__init__(options)

        if ("TWILIO_ACCOUNT_SID" not in os.environ or "TWILIO_AUTH_TOKEN" not in os.environ):
            raise CrossauthError(ErrorCode.Configuration, "Must set TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN environment variables to use Twilio")

        self.__account_sid : str = os.environ["TWILIO_ACCOUNT_SID"]
        self.__auth_token : str = os.environ["TWILIO_AUTH_TOKEN"]

    async def _send_sms(self, to: str, body: str) -> str:
        """
        Uses Twilio to send an SMS
        :param to number to send SMS to (starting with `+`)
        :param body text to send
        :return the send message ID
        """
        TwilioAuthenticator.validate_phone(to)
        client = Client(self.__account_sid, self.__auth_token)
        message = client.messages.create(
            to=to,
            from_=self._sms_authenticator_from,
            body=body)

        if (message.sid is None): # type: ignore
            raise CrossauthError(ErrorCode.Connection, "Failed to send SMS")
        return cast(str,message.sid) # type: ignore
