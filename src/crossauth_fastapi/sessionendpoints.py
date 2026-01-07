# Copyright (c) 2026 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file

#############################
# ENDPOINTS

SessionPageEndpoints = [
    "login",
    "logout",
    "changepassword",
    "updateuser",
    "deleteuser",
]
"""
When not overriding which endpoints to enable, all of these will be.
"""

SessionAdminPageEndpoints = [
    "admin/createuser",
    "admin/changepassword",
    "admin/selectuser",
    "admin/updateuser",
    "admin/changepassword",
    "admin/deleteuser",
]
"""
When not overriding which endpoints to enable, 
and with `enableAdminEndpoints` enabled, all of these will be.
"""

SessionAdminClientPageEndpoints = [
    "admin/selectclient",
    "admin/createclient",
    "admin/deleteclient",
    "admin/updateclient",
]
"""
When not overriding which endpoints to enable, and with
both `enableAdminEndpoints` and `enableAdminClientManagement` enabled,
all these will be.
"""

SessionClientPageEndpoints = [
    "selectclient",
    "createclient",
    "updateclient",
    "deleteclient",
]
"""
When not overriding which endpoints to enable, and with
`enableAdminClientManagement` enabled,
all these will be.
"""

SessionApiEndpoints = [
    "api/login",
    "api/logout",
    "api/changepassword",
    "api/userforsessionkey",
    "api/getcsrftoken",
    "api/updateuser",
    "api/deleteuser",
]
"""
When not overriding which endpoints to enable, all of these will be.
"""

SessionAdminApiEndpoints = [
    "admin/api/createuser",
    "admin/api/changepassword",
    "admin/api/updateuser",
    "admin/api/changepassword",
    "admin/api/deleteuser",
]
"""
When not overriding which endpoints to enable, 
and with `enableAdminEndpoints` enabled, all of these will be.
"""

SessionAdminClientApiEndpoints = [
    "admin/api/createclient",
    "admin/api/deleteclient",
    "admin/api/updateclient",
]
"""
When not overriding which endpoints to enable, and with
both `enableAdminEndpoints` and `enableAdminClientManagement` enabled,
all these will be.
"""

SessionClientApiEndpoints = [
    "api/deleteclient",
    "api/updateclient",
    "api/createclient",
]
"""
When not overriding which endpoints to enable, and with
`enableAdminClientManagement` enabled,
all these will be.
"""

Factor2ApiEndpoints = [
    "api/configurefactor2",
    "api/loginfactor2",
    "api/changefactor2",
    "api/factor2",
    "api/cancelfactor2",
]
"""
API (JSON) endpoints that depend on 2FA being enabled.

If not overriding which endpoints to enable with `endpoints`,
and if any 2FA factors are enabled, then this endpoints will be added.
"""

EmailVerificationPageEndpoints = [
    "verifyemail",
    "emailverified",
]
"""
Page endpoints that depend on email verification being enabled.

If not overriding which endpoints to enable with `endpoints`,
and if email verification is enabled, then this endpoints will be added.
"""

EmailVerificationApiEndpoints = [
    "api/verifyemail",
]
"""
API (JSON) endpoints that depend on email verification.

If not overriding which endpoints to enable with `endpoints`,
and if email verification is enabled, then this endpoints will be added.
"""

PasswordResetPageEndpoints = [
    "requestpasswordreset",
    "resetpassword",
]
"""
Page endpoints that depend on password reset being enabled

If not overriding which endpoints to enable with `endpoints`,
and if password reset is enabled, then this endpoints will be added.
"""

PasswordResetApiEndpoints = [
    "api/requestpasswordreset",
    "api/resetpassword",
]
"""
API (JSON) endpoints that depend on password reset being enabled 

If not overriding which endpoints to enable with `endpoints`,
and if password reset is enabled, then this endpoints will be added.
"""

SignupPageEndpoints = [
    "signup",
]
"""
Endpoints for signing a user up that display HTML

When not overriding which endpoints to enable, all of these will be.
"""

SignupApiEndpoints = [
    "api/signup",
]
"""
API (JSON) endpoints for signing a user up that display HTML

When not overriding which endpoints to enable, all of these will be.
"""

Factor2PageEndpoints = [
    "configurefactor2",
    "loginfactor2",
    "changefactor2",
    "factor2",
]
"""
Endpoints for signing a user up that display HTML
"""

AllEndpointsMinusOAuth = [
    *SignupPageEndpoints,
    *SignupApiEndpoints,
    *SessionPageEndpoints,
    *SessionApiEndpoints,
    *SessionAdminPageEndpoints,
    *SessionAdminApiEndpoints,
    *EmailVerificationPageEndpoints,
    *EmailVerificationApiEndpoints,
    *PasswordResetPageEndpoints,
    *PasswordResetApiEndpoints,
    *Factor2PageEndpoints,
    *Factor2ApiEndpoints,
]
"""
These are the endpoints created ig `endpoints` is set to `allMinusOAuth`
"""

AllEndpoints = [
    *SignupPageEndpoints,
    *SignupApiEndpoints,
    *SessionPageEndpoints,
    *SessionClientPageEndpoints,
    *SessionApiEndpoints,
    *SessionClientApiEndpoints,
    *SessionAdminPageEndpoints,
    *SessionAdminClientPageEndpoints,
    *SessionAdminApiEndpoints,
    *SessionAdminClientApiEndpoints,
    *EmailVerificationPageEndpoints,
    *EmailVerificationApiEndpoints,
    *PasswordResetPageEndpoints,
    *PasswordResetApiEndpoints,
    *Factor2PageEndpoints,
    *Factor2ApiEndpoints,
]
"""
These are all the endpoints 
"""
