import unittest
import os
from crossauth_backend.storageimpl.inmemorystorage import InMemoryUserStorage
from crossauth_backend.storageimpl.ldapstorage import LdapUserStorage
from crossauth_backend.common.interfaces import UserState

class LdapUserStorageTest(unittest.IsolatedAsyncioTestCase):

    async def test_createUser(self):

        ldap_urls = os.environ.get("LDAPURLS", "ldap://localhost:1389").split(",")
        ldap_user_search_base = os.environ.get("LDAPSEARCH", "ou=users,dc=example,dc=org")
        ldap_username_attribute = os.environ.get("LDAPUSERNAMEATTR", "cn")
        username = os.environ.get("LDAPUSER", "dave")
        password = os.environ.get("LDAPPASSWORD", "davePass123")
        email = os.environ.get("LDAPEMAIL", "dave@dave.com")

        local_storage = InMemoryUserStorage()
        ldap_storage = LdapUserStorage(local_storage, {
            "ldap_urls": ldap_urls,
            "ldap_user_search_base": ldap_user_search_base,
            "ldap_username_attribute": ldap_username_attribute
        })
        await ldap_storage.create_user(
            {"username": username, "state": UserState.active, "email": email, "factor1": "none"},
            {"password": password}
        )
        user_and_secrets = await local_storage.get_user_by_username(username)
        self.assertEqual(user_and_secrets["user"]["username"], username)
    