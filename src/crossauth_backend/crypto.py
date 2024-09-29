# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import os
import base64
import json
import hashlib
import hmac
import secrets
from datetime import datetime
from typing import Optional, Dict, Any
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

        hashed_password : str
        """ The actual hashed password in Base64 format """

        salt : str
        """ The random salt used to create the hashed password """

        iterations : int
        """ Number of iterations for PBKDF2 """

        use_secret : bool
        """ If true, secret (application secret) is also used to hash the password"""

        key_len : int
        """ The key length parameter passed to PBKDF2 - hash will be this number of characters long """

        digest : str
        """ The digest algorithm to use, eg `sha512` """


class HashOptions(TypedDict, total=False):
    """
    Option parameters for :class:`Crypto.passwordHash`
    """
    
    salt : str
    """ A salt to prepend to the message before hashing """

    encode : bool
    """ Whether to Base64-URL-encode the result """

    secret : str
    """ A secret to append to the salt when hashing, or undefined for no secret """

    iterations : int
    """ Number of PBKDF2 iterations """

    key_len : int
    """ Length (before Base64-encoding) of the PBKDF2 key being generated """

    digest : str
    """ PBKDF2 digest method """

class Crypto:
    """ Provides cryptographic functions """

    @staticmethod
    async def passwords_equal(plaintext: str, encoded_hash: str, secret: Optional[str] = None) -> bool:
        """
        Returns true if the plaintext password, when hashed, equals the one in the hash, using
        it's hasher settings
        :param str plaintext: the plaintext password
        :param str encoded_hash: the previously-hashed version 
        :param str|None secret: if `useHash`in `encodedHash` is true, uses as a pepper for the hasher

        :return: true if they are equal, false otherwise
        """
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
        """
        Decodes a string from base64 to UTF-8
        :param str encoded: base64-encoded text

        :return: URF-8 text
        """
        return base64.urlsafe_b64decode(Crypto.base64_pad(encoded)).decode('utf-8')

    @staticmethod
    def base64_encode(text: str) -> str:
        """
        Base64-encodes UTF-8 text
        :param str: text UTF-8 text

        :return: Base64 text
        """
        return base64.urlsafe_b64encode(text.encode('utf-8')).decode('utf-8')

    @staticmethod
    def decode_password_hash(hash: str) -> PasswordHash:
        """
        Splits a hashed password into its component parts.  Return it as a :class:`PasswordHash`.
        
        The format of the hash should be
        ```
        digest:int key_len:iterations:useSecret:salt:hashedPassword
        ```
        The hashed password part is the Base64 encoding of the PBKDF2 password.
        :param str hash: the hassed password to decode.  See above for format

        :return: :class:`PasswordHash` object containing the deecoded hash components
        """
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
        """
        Encodes a hashed password into the string format it is stored as.  
        
        See :func:`decodePasswordHash` for the format it is stored in.
        
        :param str hashed_password: the Base64-encoded PBKDF2 hash of the password
        :param str salt: the salt used for the password.
        :param bool use_secret: whether or not to use the application secret as part
               of the hash.
        :param int iterations: the number of PBKDF2 iterations
        :param int key_len: the key length PBKDF2 parameter - results in a hashed password this length, before Base64,
        :param str digest: The digest algorithm, eg `pbkdf2`

        :return: a string encode the above parameters.
        """
        return f"pbkdf2:{digest}:{key_len}:{iterations}:{1 if use_secret else 0}:{salt}:{hashed_password}"

    @staticmethod
    def random_salt() -> str:
        """
        Creates a random salt

        :return: random salt as a base64 encoded string
        """
        return Crypto.random_value(PBKDF2_SALTLENGTH)

    @staticmethod
    def random_value(length: int) -> str:
        """
        Creates a random string encoded as in base64url
        :param int length: length of the string to create

        :return: the random value as a string.  Number of bytes will be greater as it is base64 encoded.
        """
        return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode('utf-8').replace("=", "")

    Base32 = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"

    @staticmethod
    def random_base32(length: int, dash_every: Optional[int] = None) -> str:
        """
        Creates a random base-23 string
        :param int length: length of the string to create

        :return: the random value as a string.  Number of bytes will be greater as it is base64 encoded.
        """
        bytes = secrets.token_bytes(length)
        str_value = ''.join(Crypto.Base32[i % 32] for i in bytes)
        if dash_every:
            return '-'.join(str_value[i:i + dash_every] for i in range(0, len(str_value), dash_every))
        return str_value

    @staticmethod
    def uuid() -> str:
        """ Creates a UUID """
        return str(secrets.token_hex(16))

    @staticmethod
    def hash(plaintext: str) -> str:
        """
        Standard hash using SHA256 (not PBKDF2 or HMAC)
        
        :param :str plaintext: text to hash

        :return: the string containing the hash 
        """
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
        """
        Standard hash using SHA256 (not PBKDF2 or HMAC)
        
        :param str plaintext: text to hash
        :return: the string containing the hash 
        """
        d = hashlib.sha256(plaintext.encode()).digest()
        return base64.urlsafe_b64encode(d).decode().replace("=", "")

    @staticmethod
    async def password_hash(plaintext: str, options: HashOptions = {}) -> str:
        """
        Hashes a password and returns it as a base64 or base64url encoded string
        :param str plaintext: password to hash
        :param HashOptions options:
               - `salt`: salt to use.  Make a random one if not passed
               - `secret`: optional application secret password to apply as a pepper
               - `encode`: if true, returns the full string as it should be stored in the database.

        :returns: the string containing the hash and the values to decode it
        """
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
        """
        hash is of a JSON containing the payload, timestamp and optionally
        a salt.
        :param Dict[str, Any]: payload the payload to hash
        :param str|None salt: optional salt (use if the payload is small)
        :param int|None timestamp: time the token will expire

        :return: a Base64-URL-encoded string that can be hashed.
        """
        if salt is None:
            salt = Crypto.random_salt()
        if timestamp is None:
            timestamp = int(datetime.now().timestamp()*1000)
        return base64.urlsafe_b64encode(json.dumps({**payload, 't': timestamp, 's': salt}).encode()).decode()

    @staticmethod
    def sign(payload: Dict[str, Any], secret: str, salt: Optional[str] = None, timestamp: Optional[int] = None) -> str:
        """
        Signs a JSON payload by creating a hash, using a secret and 
        optionally also a salt and timestamp
        
        :param Dict[str, Any] payload: object to sign (will be stringified as a JSON)
        :param str secret: secret key, which must be a string
        :param str|None salt: optionally, a salt to concatenate with the payload (must be a string)
        :paramint|None timestamp: optionally, a timestamp to include in the signed date as a Unix date

        :return: Base64-url encoded hash
        """
        payloadStr = Crypto.signable_token(payload, salt, timestamp)
        hmac_signature = hmac.new(secret.encode(), payloadStr.encode(), hashlib.sha256).hexdigest()
        return f"{payloadStr}.{hmac_signature}"

    @staticmethod
    def sign_secure_token(payload: str, secret: str) -> str:
        """
        This can be called for a string payload that is a cryptographically
        secure random string.  No salt is added and the token is assumed to
        be Base64Url already
        
        :param str payload: string to sign 
        :param str secret: the secret to sign with

        :return: Base64-url encoded hash
        """
        hmac_signature = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        return f"{payload}.{hmac_signature}"

    @staticmethod
    def unsign(signed_message: str, secret: str, expiry: Optional[int] = None) -> Dict[str, Any]:
        """
        Validates a signature and, if valid, return the unstringified payload
        :param str signed_message: signed message (base64-url encoded)
        :param str secret: secret key, which must be a string
        :param int|None expiry: if set, validation will fail if the timestamp in the payload is after this date

        :return: if signature is valid, the payload as an object

        :raises :class:`crossauth_backend.CrossauthError`: with 
                :class:`ErrorCode` of `InvalidKey` if signature
                is invalid or has expired.  
        """
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
    def unsign_secure_token(signed_message: str, secret: str, expiry: Optional[int] = None) -> str:
        """
        Validates a signature signed with `signSecureToken` and, if valid, 
        return the unstringified payload
        :param str signed_message: signed message (base64-url encoded)
        :param str secret: secret key, which must be a string

        :return: if signature is valid, the payload as a string

        :raises :class:`crossauth_backend.CrossauthError`: with 
                {:class:`ErrorCode` of `InvalidKey` if signature
                is invalid or has expired.  
        """
        parts = signed_message.split(".")
        if len(parts) != 2:
            raise CrossauthError(ErrorCode.InvalidKey)
        msg = parts[0]
        sig = parts[1]
        payload = msg
        new_sig = hmac.new(secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
        if new_sig != sig:
            raise CrossauthError(ErrorCode.InvalidKey, "Signature does not match payload")
        return payload

    @staticmethod
    def xor(value: str, mask: str) -> str:
        """
        XOR's two arrays of base64url-encoded strings
        :param str value: to XOR
        :param str mask: mask to XOR it with

        :return: an XOR'r string
        """
        value_array = base64.urlsafe_b64decode(Crypto.base64_pad(value))
        mask_array = base64.urlsafe_b64decode(Crypto.base64_pad(mask))
        result_array = bytes(b ^ m for b, m in zip(value_array, mask_array))
        return base64.urlsafe_b64encode(result_array).decode().replace("=", "")
    
    
    @staticmethod
    def symmetric_encrypt(plaintext: str, key_string: str, iv : bytes|None = None) -> str:
        """
        Symmetric encryption using a key that must be a string
        
        :param str plaintext: Text to encrypt
        :param str key_string: the symmetric key
        :param iv bytes|None: the iv value.  In None, a random one is created

        :return: Encrypted text Base64-url encoded.
        """
        if (iv is None): iv = secrets.token_bytes(16)

        key = base64.urlsafe_b64decode(Crypto.base64_pad(key_string))
        cipher = AES.new(key, AES.MODE_CBC, iv=iv, use_aesni=False)  # type: ignore
        padded_plaintext = pad(plaintext.encode(), AES.block_size)
        encrypted = cipher.encrypt(padded_plaintext)

        return f"{base64.urlsafe_b64encode(iv).decode().replace("=", "")}.{base64.urlsafe_b64encode(encrypted).decode().replace("=", "")}"

    @staticmethod
    def symmetric_decrypt(ciphertext: str, key_string: str) -> str:
        """
        Symmetric decryption using a key that must be a string
        
        :param str ciphertext: Base64-url encoded ciphertext
        :param str key_string: the symmetric key

        :return: Decrypted text
        """
        key = base64.urlsafe_b64decode(Crypto.base64_pad(key_string))
        parts = ciphertext.split(".")
        if len(parts) != 2:
            raise CrossauthError(ErrorCode.InvalidHash, "Not AES-256-CBC ciphertext")
        iv = base64.urlsafe_b64decode(Crypto.base64_pad(parts[0]))
        encrypted_text = base64.urlsafe_b64decode(Crypto.base64_pad(parts[1]))
        cipher = AES.new(key, AES.MODE_CBC, iv=iv) # type: ignore
        decrypted = unpad(cipher.decrypt(encrypted_text), AES.block_size)
        return decrypted.decode()
