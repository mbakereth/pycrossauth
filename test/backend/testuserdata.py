from crossauth_backend.storageimpl.inmemorystorage import InMemoryUserStorage
from crossauth_backend.authenticators.passwordauth import LocalPasswordAuthenticator, LocalPasswordAuthenticatorOptions

async def get_test_user_storage(pepper : str|None = None) -> InMemoryUserStorage:
    user_storage = InMemoryUserStorage({"user_editable_fields": ["email", "dummyField"]})
    options : LocalPasswordAuthenticatorOptions = {"pbkdf2_iterations": 1_000}
    if (pepper is not None): options["secret"] = pepper
    authenticator = LocalPasswordAuthenticator(user_storage, options)
    await user_storage.create_user({
            "username": "bob", 
            "email": "bob@bob.com",
            "state": "active",
            "factor1": "localpassword"}, {
            "password": await authenticator.create_password_hash("bobPass123")
            } )
    await user_storage.create_user({
        "username": "alice", 
        "email": "alice@alice.com",
        "state": "active",
        "factor1": "localpassword"}, {
        "password": await authenticator.create_password_hash("alicePass123")
        } )

    await user_storage.create_user({
        "username": "mary", 
        "email": "mary@maryPass123.com",
        "state": "active",
        "factor1": "localpassword", 
        "factor2": "dummy"}, {
        "password": await authenticator.create_password_hash("alicePass123")
        } )
    
    return user_storage

