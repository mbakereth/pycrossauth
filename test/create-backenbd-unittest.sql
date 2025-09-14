DROP TABLE IF EXISTS User;
CREATE TABLE User (
    id                      integer PRIMARY KEY AUTOINCREMENT,
    username                text,
    username_normalized     text,
    email                   text,
    email_normalized        text,
    phone                   text null,
    state                   text default 'active',
    factor1                 text default 'password',
    factor2                 text default '',
    dummyField              text default ''
);

CREATE UNIQUE INDEX id_idx ON User(id);
CREATE UNIQUE INDEX username_idx ON User(username);
CREATE UNIQUE INDEX username_normalized_idx ON User(username_normalized);
CREATE UNIQUE INDEX email_idx ON User(email);
CREATE UNIQUE INDEX email_normalized_idx ON User(email_normalized);

DROP TABLE IF EXISTS UserSecrets;
CREATE TABLE UserSecrets (
    userid                  integer REFERENCES User(id),
    password                text,
    totpsecret              text default ''
);

CREATE UNIQUE INDEX userid ON UserSecrets(userid);

DROP TABLE IF EXISTS Key;
CREATE TABLE Key (
    id                      integer PRIMARY KEY AUTOINCREMENT,
    value                   text UNIQUE,
    userid                  integer REFERENCES User(id),
    created                 datetime,
    expires                 datetime,
    lsatactive              datetime null,
    data                    text null
);

DROP TABLE IF EXISTS ApiKey;
CREATE TABLE ApiKey (
    id                      integer PRIMARY KEY AUTOINCREMENT,
    name                    text,
    value                   text UNIQUE,
    userid                  integer null REFERENCES User(id),
    created                 datetime,
    expires                 datetime null,
    data                    text null
);

DROP TABLE IF EXISTS OAuthClient;
CREATE TABLE OAuthClient (
    client_id               text UNIQUE,
    confidential            boolean default 1,
    client_name             text,
    client_secret           text null,
    userid                  integer null references User(id)
);

DROP TABLE IF EXISTS OAuthClientRedirectUri;
CREATE TABLE OAuthClientRedirectUri (
    id                      integer PRIMARY KEY AUTOINCREMENT,
    client_id               text REFERENCES Client(client_id),
    flow                    text
);

DROP TABLE IF EXISTS OAuthAuthorization;
CREATE TABLE OAuthAuthorization (
    id                      integer PRIMARY KEY AUTOINCREMENT,
    client_id               text REFERENCES Client(client_id),
    userid                  integer null references User(id),
    scope                   text null
);

CREATE INDEX client_id_userid_idx ON OAuthAuthorization(client_id, userid);
CREATE INDEX scope_unique_idx ON OAuthAuthorization(client_id, userid, scope);
