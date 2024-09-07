# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
import unittest
from src.crossauth_backend import Crypto



class TypedDictCryptoTest(unittest.TestCase):

    def test_signAndUnsign(self):
        payload = {"foo": "bar"}
        secret = "SECRET"
        sig = Crypto.sign(payload, secret)
        decoded = Crypto.unsign(sig, secret)
        self.assertEqual(decoded["foo"], payload["foo"])

    def test_hashAndCompare(self):
        plaintext = "PLAINTEXT"
        hash = Crypto.hash(plaintext)
        self.assertEqual(hash, 'y0Dn2tyGFhuXmN5IUS8zLSHBQfzB4ooIb95KM3WqsbU')

    def test_xor(self):
        value = Crypto.str_to_base64url("ABCDEFG")
        mask = Crypto.str_to_base64url("HIJKLMN")
        masked_value = Crypto.xor(value, mask)
        unmasked_value = Crypto.xor(masked_value, mask)
        self.assertEqual(unmasked_value, value)

    def test_symmetricEncryption(self):
        key = "xkDDElW4zZTLdIZ3AS0v0gJbh_SZZSAo6YuWDeEtBaU"
        plaintext = "This is the plaintext"
        ciphertext = Crypto.symmetric_encrypt(plaintext, key)
        recovered_text = Crypto.symmetric_decrypt(ciphertext, key)
        self.assertEqual(recovered_text, plaintext)

    def test_symmetricEncryptionWithIv(self):
        key = "xkDDElW4zZTLdIZ3AS0v0gJbh_SZZSAo6YuWDeEtBaU"
        plaintext = "This is the plaintext"
        iv = "ABCDEFGHIJKLMNOP".encode('utf-8')
        ciphertext = Crypto.symmetric_encrypt(plaintext, key, iv=iv)
        recovered_text = Crypto.symmetric_decrypt(ciphertext, key)
        self.assertEqual(ciphertext, "QUJDREVGR0hJSktMTU5PUA.vm3j7WeBpDGM76GhB0K4gQlE7nnkUGQvVe4hoPtocSI")
        self.assertEqual(recovered_text, plaintext)

class TypedDictCryptoAsync(unittest.IsolatedAsyncioTestCase):

    async def test_passwordHashAndCompare(self):
        password = "PASSWORD"
        hash = await Crypto.password_hash(password, {"encode": True})
        equal = await Crypto.passwords_equal(password, hash)
        self.assertTrue(equal)
    
    async def test_passwordHashAndCompareWithSecret(self):
        password = "PASSWORD"
        secret = "SECRET"
        hash = await Crypto.password_hash(password, {"encode": True, "secret": secret})
        equal = await Crypto.passwords_equal(password, hash)
        self.assertTrue(equal)
    
