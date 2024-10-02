# Crossauth.js

Crossauth is a package for authentication and authorization using username/password, LDAP and OAuth2.  It has two components, each can be used without the other: server for the backend and client for the frontend.  It is still under development and currently only the OAuth
client part is implemented.  Enough of the session manager exists to support the
OAuth client, but without user login functionality (ie just anonymous sessions).

There is also a Typescript package (in a separate repository) that provides identical functionality, plus frontend Javascript..

This package is very much in alpha and so far has been used in one project only.
Being alpha, the API is subject to change without warning.
