# Crossauth.js

Crossauth is a package for authentication and authorization using username/password, LDAP and OAuth2.  It has two components, each can be used without the other: server for the backend and client for the frontend.  It is still under development and currently only the OAuth
client part is implemented.  Enough of the session manager exists to support the
OAuth client, but without user login functionality (ie just anonymous sessions).

There is also a Typescript package at [https://github.com/mbakereth/crossauthjs](https://github.com/mbakereth/crossauthjs) that provides identical functionality, plus frontend Javascript..

The intention is to make this Python version as fully-featured as the Typescript version.  However, currently only the OAuth client and resource server functionality exist.

It is also intended to support multiple web frameworks.  Currently only [FastAPI](https://fastapi.tiangolo.com/) is supported.

## Package structure

Unlike the Typescript version, there is only one package here: `pycrossauth`.  Within this, however, are several modules:

#### crossauth_backend

Web framework-independent code for the backend server.

#### crossauth_fastapi

FastAPI version of crossauth, making use of `crossauth_backend`.

## Package dependencies

This package intends to be flexible regarding other packages that need to be present.  As well as choosing between two popular web frameworks, you can choose between several database management systems

* Postgres
* Sqlite
* Prisma

## Using this package

Pycrossuth is in PYPI.  To use it, 

```shell
pip install pycrossauth
```

## Building this package

If you want to build Crossauth from source, clone it from [https://github.com/mbakereth/pycrossauth](https://github.com/mbakereth/pycrossauth), install create and activate a virtual environment, then do the following from the top-level directory in the repo:

```bash
pip install -r requirements.txt
pip install -r requirements-optional.txt
pip install -r requirements-dev-txt
bash build.sh
```

## The Examples

The `examples` directory contains a number of examples to get you going.

They require an OAuth server to be running.  Easiest way is to clone the Typescript version, [https://github.com/mbakereth/crossauthjs](https://github.com/mbakereth/crossauthjs), and run the Sveltekit OAuth server example from there.

#### fastapiclient

An example of an OAuth client - requesting an access token

#### fastapiresserver

An exsample of an OAuth reserver server - validating an access token and providing an API endpoint.

