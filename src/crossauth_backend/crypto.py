import os
import base64
import json
import hashlib
import hmac
import secrets
from datetime import datetime
from typing import Optional, Dict, Any, Union
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from typing import TypedDict

from crossauth_backend.common.error import ErrorCode, CrossauthError
from crossauth_backend.utils import MapGetter

PBKDF2_DIGEST = os.getenv("PBKDF2_DIGEST", "sha256")
PBKDF2_ITERATIONS = int(os.getenv("PBKDF2_ITERATIONS", 600_000))
PBKDF2_KEYLENGTH = int(os.getenv("PBKDF2_KEYLENGTH", 32))  # in bytes, before base64
PBKDF2_SALTLENGTH = int(os.getenv("PBKDF2_SALTLENGTH", 16))  # in bytes, before base64

SIGN_DIGEST = "sha256"

class PasswordHash(TypedDict):
        """
        An object that contains all components of a hashed password.  Hashing is done with PBKDF2
        """

        """ The actual hashed password in Base64 format """
        hashed_password : str

        """ The random salt used to create the hashed password """
        salt : str

        """ Number of iterations for PBKDF2 """
        iterations : int

        """ If true, secret (application secret) is also used to hash the password"""
        use_secret : bool

        """ The key length parameter passed to PBKDF2 - hash will be this number of characters long """
        key_len : int

        """ The digest algorithm to use, eg `sha512` """
        digest : str


class HashOptions(TypedDict, total=False):
    """
    Option parameters for {@link Crypto.passwordHash}
    """
    
    """ A salt to prepend to the message before hashing """
    salt : str

    """ Whether to Base64-URL-encode the result """
    encode : bool

    """ A secret to append to the salt when hashing, or undefined for no secret """
    secret : str

    """ Number of PBKDF2 iterations """
    iterations : int

    """ Length (before Base64-encoding) of the PBKDF2 key being generated """
    key_len : int

    """ PBKDF2 digest method """
    digest : str

class Crypto:
    @staticmethod
    async def passwords_equal(plaintext: str, encoded_hash: str, secret: Optional[str] = None) -> bool:
        hash = Crypto.decode_password_hash(encoded_hash)
        secret1 : str|None = None
        if hash["use_secret"]: 
            secret1 = secret
        options : HashOptions = {}
        options["salt"] = MapGetter[str].get_or_raise(hash, "salt")
        options["encode"] = False
        if (secret1 is not None): options["secret"] = secret1
        options["iterations"] = MapGetter[int].get_or_raise(hash, "iterations")
        options["key_len"] = MapGetter[int].get_or_raise(hash, "key_len")

        new_hash = await Crypto.password_hash(plaintext, options)
        if len(new_hash) != len(hash["hashed_password"]):
            raise CrossauthError(ErrorCode.PasswordInvalid)
        return hmac.compare_digest(new_hash, hash["hashed_password"])

    @staticmethod
    def base64_decode(encoded: str) -> str:
        return base64.b64decode(encoded).decode('utf-8')

    @staticmethod
    def base64_encode(text: str) -> str:
        return base64.b64encode(text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def decode_password_hash(hash: str) -> PasswordHash:
        parts = hash.split(':')
        if len(parts) != 7:
            raise CrossauthError(ErrorCode.InvalidHash)
        if parts[0] != "pbkdf2":
            raise CrossauthError(ErrorCode.UnsupportedAlgorithm)
        try:
            return {
                "hashed_password": parts[6],
                "salt": parts[5],
                "use_secret": parts[4] != "0",
                "iterations": int(parts[3]),
                "key_len": int(parts[2]),
                "digest": parts[1]
            }
        except Exception:
            raise CrossauthError(ErrorCode.InvalidHash)

    @staticmethod
    def encode_password_hash(hashed_password: str, salt: str, use_secret: bool, iterations: int, key_len: int, digest: str) -> str:
        return f"pbkdf2:{digest}:{key_len}:{iterations}:{1 if use_secret else 0}:{salt}:{hashed_password}"

    @staticmethod
    def random_salt() -> str:
        return Crypto.random_value(PBKDF2_SALTLENGTH)

    @staticmethod
    def random_value(length: int) -> str:
        return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode('utf-8')

    Base32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    @staticmethod
    def random_base32(length: int, dash_every: Optional[int] = None) -> str:
        bytes = secrets.token_bytes(length)
        str_value = ''.join(Crypto.Base32[i % 32] for i in bytes)
        if dash_every:
            return '-'.join(str_value[i:i + dash_every] for i in range(0, len(str_value), dash_every))
        return str_value

    @staticmethod
    def uuid() -> str:
        return str(secrets.token_hex(16))

    @staticmethod
    def hash(plaintext: str) -> str:
        return Crypto.sha256(plaintext)

    @staticmethod
    def base64url_to_base64(s : str) -> str:
        s = s.translate(dict(zip(map(ord, u'-_'), u'+/')))
        match (len(s) % 4):
            case 0:
                return s
            case 1:
                return s + "==="
            case 2:
                return s + "=="
            case 3:
                return "="
            case _:
                return s

    @staticmethod
    def base64_pad(s : str) -> str:
        match (len(s) % 4):
            case 0:
                return s
            case 1:
                return s + "==="
            case 2:
                return s + "=="
            case 3:
                return s + "="
            case _:
                return s

    @staticmethod
    def base64_to_base64url(s : str) -> str:
        return s.translate(dict(zip(map(ord, u'+/'), u'-_'))).replace("=","")

    @staticmethod
    def str_to_base64url(s : str) -> str:
        return base64.urlsafe_b64encode(s.encode('utf-8')).decode().replace("=", "")
    
    @staticmethod
    def base64url_to_str(s: str) -> str:
        return base64.urlsafe_b64decode(Crypto.base64_pad(s)).decode()
    
    @staticmethod
    def sha256(plaintext: str) -> str:
        d = hashlib.sha256(plaintext.encode()).digest()
        return base64.urlsafe_b64encode(d).decode().replace("=", "")

    @staticmethod
    async def password_hash(plaintext: str, options: HashOptions = {}) -> str:
        salt = MapGetter[str].get_or_none(options, "salt") or Crypto.random_salt()
        use_secret = MapGetter[bool].get(options, "use_secret", False)
        secret = MapGetter[str].get(options, "sedcret", "")
        salt_and_secret = f"{salt}!{secret}" if use_secret else salt

        iterations = MapGetter[int].get(options, "iterations", PBKDF2_ITERATIONS)
        key_len = MapGetter[int].get(options, "key_len", PBKDF2_KEYLENGTH)
        digest = MapGetter[str].get(options, "digest", PBKDF2_DIGEST)

        hash_bytes = hashlib.pbkdf2_hmac(digest, plaintext.encode(), salt_and_secret.encode(), iterations, dklen=key_len)
        password_hash = base64.urlsafe_b64encode(hash_bytes).decode('utf-8')
        if MapGetter[int].get(options, "encode", False):
            password_hash = Crypto.encode_password_hash(password_hash, salt, use_secret, iterations, key_len, digest)
        return password_hash

    @staticmethod
    def signable_token(payload: Dict[str, Any], salt: Optional[str] = None, timestamp: Optional[int] = None) -> str:
        if salt is None:
            salt = Crypto.random_salt()
        if timestamp is None:
            timestamp = int(datetime.now().timestamp())
        return base64.urlsafe_b64encode(json.dumps({**payload, 't': timestamp, 's': salt}).encode()).decode()

    @staticmethod
    def sign(payload: Union[Dict[str, Any], str], secret: str, salt: Optional[str] = None, timestamp: Optional[int] = None) -> str:
        if not isinstance(payload, str):
            payload = Crypto.signable_token(payload, salt, timestamp)
        hmac_signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{hmac_signature}"

    @staticmethod
    def unsign(signed_message: str, secret: str, expiry: Optional[int] = None) -> Dict[str, Any]:
        parts = signed_message.split(".")
        if len(parts) != 2:
            raise CrossauthError(ErrorCode.InvalidKey)
        msg = parts[0]
        sig = parts[1]
        payload = json.loads(base64.urlsafe_b64decode(msg).decode())
        if expiry:
            expire_time = payload['t'] + expiry * 1000
            if expire_time > datetime.now().timestamp():
                raise CrossauthError(ErrorCode.Expired)
        new_sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if new_sig != sig:
            raise CrossauthError(ErrorCode.InvalidKey, "Signature does not match payload")
        return payload

    @staticmethod
    def xor(value: str, mask: str) -> str:
        value_array = base64.urlsafe_b64decode(Crypto.base64_pad(value))
        mask_array = base64.urlsafe_b64decode(Crypto.base64_pad(mask))
        result_array = bytes(b ^ m for b, m in zip(value_array, mask_array))
        return base64.urlsafe_b64encode(result_array).decode().replace("=", "")
    
    
    @staticmethod
    def symmetric_encrypt(plaintext: str, key_string: str, iv : bytes|None = None) -> str:
        if (iv is None): iv = secrets.token_bytes(16)

        key = base64.urlsafe_b64decode(Crypto.base64_pad(key_string))
        cipher = AES.new(key, AES.MODE_CBC, iv=iv, use_aesni=False)  # type: ignore
        padded_plaintext = pad(plaintext.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded_plaintext)

        return f"{base64.urlsafe_b64encode(iv).decode().replace("=", "")}.{base64.urlsafe_b64encode(encrypted).decode().replace("=", "")}"

    @staticmethod
    def symmetric_decrypt(ciphertext: str, key_string: str) -> str:
        key = base64.urlsafe_b64decode(Crypto.base64_pad(key_string))
        parts = ciphertext.split(".")
        if len(parts) != 2:
            raise CrossauthError(ErrorCode.InvalidHash, "Not AES-256-CBC ciphertext")
        iv = base64.urlsafe_b64decode(Crypto.base64_pad(parts[0]))
        encrypted_text = base64.urlsafe_b64decode(Crypto.base64_pad(parts[1]))
        cipher = AES.new(key, AES.MODE_CBC, iv=iv) # type: ignore
        decrypted = unpad(cipher.decrypt(encrypted_text), AES.block_size)
        return decrypted.decode()

