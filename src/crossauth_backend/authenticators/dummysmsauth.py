from crossauth_backend.authenticators.smsauth import SmsAuthenticator, SmsAuthenticatorOptions

from typing import Dict, Any

otp = ""

def render(body : str, data: Dict[str,Any]) -> str:
    global otp
    otp = data["otp"]
    return otp

class DummySmsAuthenticator(SmsAuthenticator):
    """
    This authenticator mocks sending an SMS OTP

    """

    def __init__(self, options: SmsAuthenticatorOptions = {}):
        """
        Constructor

        :param options see :class:`crossauth_backend.SmsAuthenticatorOptions`  
        """

        super().__init__({"render": render, **options})

    async def _send_sms(self, to: str, body: str) -> str:
        """
        Uses Twilio to send an SMS
        :param to number to send SMS to (starting with `+`)
        :param body text to send
        :return the send message ID
        """
        global otp
        DummySmsAuthenticator.validate_phone(to)
        otp = body
        return otp
