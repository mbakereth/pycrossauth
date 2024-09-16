# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.storageimpl.dbstorage import DbKeyStorage, DbKeyStorageOptions
from crossauth_backend.storageimpl.postgresconnection import PostgresPool
import psycopg_pool

##########################################################################/
## KeyStorage

class PostgresKeyStorageOptions(DbKeyStorageOptions):
    """
    Optional parameters for :class: PostgresKeyStorage.

    See :func: PostgresKeyStorage.constructor for definitions.
    """


class PostgresKeyStorage(DbKeyStorage):
    """
    Implementation of {@link KeyStorage } where keys stored in a 
    Postgres database.
    """

    """
    Creates a PostgresKeyStorage object, optionally overriding defaults.
    :param psycopg_pool.AsyncConnectionPool pg_pool: the instance of the Posrgres client. 
    :param PostgresKeyStorageOptions options: see :class: PostgresKeyStorageOptions.
    """
    def __init__(self, pg_pool : psycopg_pool.AsyncConnectionPool, options : PostgresKeyStorageOptions = {}):
        super().__init__(PostgresPool(pg_pool), options)

