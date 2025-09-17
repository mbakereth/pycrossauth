import unittest
from crossauth_backend.authenticators.ldapauth import LdapAuthenticator
from crossauth_backend.storageimpl.ldapstorage import LdapUserStorage
from crossauth_backend.storageimpl.inmemorystorage import InMemoryUserStorage
from crossauth_backend.common.interfaces import UserState
import os
from typing import NamedTuple, List

class Ldap(NamedTuple):
    ldap_urls : List[str]
    ldap_user_search_base: str
    ldap_username_attribute: str
    username: str
    password: str
    email: str

def get_auth():
    ldap_urls = os.environ.get("LDAPURLS", "ldap://localhost:1389").split(",")
    ldap_user_search_base = os.environ.get("LDAPSEARCH", "ou=users,dc=example,dc=org")
    ldap_username_attribute = os.environ.get("LDAPUSERNAMEATTR", "cn")
    username = os.environ.get("LDAPUSER", "dave")
    password = os.environ.get("LDAPPASSWORD", "davePass123")
    email = os.environ.get("LDAPEMAIL", "dave@dave.com")

    return Ldap(ldap_urls, ldap_user_search_base, ldap_username_attribute, username, password, email)

class default_password_validator_test(unittest.IsolatedAsyncioTestCase):

    async def test_authenticateUserInLdapAndLocal(self):
        ldap = get_auth()

        local_storage = InMemoryUserStorage()
        ldap_storage = LdapUserStorage(local_storage, {
            "ldap_urls": ldap.ldap_urls,
            "ldap_user_search_base": ldap.ldap_user_search_base,
            "ldap_username_attribute": ldap.ldap_username_attribute,
        })
        auth = LdapAuthenticator(ldap_storage, {
            "ldap_auto_create_account": False,
        })
        await ldap_storage.create_user(
            {"username": ldap.username, "state": UserState.active, "email": ldap.email, "factor1": "ldap"}, 
            {"password": ldap.password})
        user_and_secrets = await ldap_storage.get_user_by_username(ldap.username)
        await auth.authenticate_user(user_and_secrets["user"], {}, {"password": ldap.password});
