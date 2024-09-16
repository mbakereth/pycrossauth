# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.storageimpl.dbconnection import DbPool, DbConnection, DbParameter
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from abc import ABC, abstractmethod
from typing import List, Dict, Any
import psycopg

class PostgresPool(DbPool):
    def __init__(self, pg_pool: psycopg.psycopg_pool.AsyncConnectionPool):
        self.pg_pool = pg_pool

    async def connect(self) -> 'PostgresConnection':
        conn = self.pg_pool.connection()
        CrossauthLogger.logger().debug(j({"msg": "DB connect"}))
        return PostgresConnection(conn, self.pg_pool)

    def parameters(self) -> 'PostgresParameter':
        return PostgresParameter()

class PostgresConnection(DbConnection):
    def __init__(self, conn: psycopg.psycopg_pool.AsyncIterator, 
                 pool: psycopg.psycopg_pool.AsyncConnectionPool):
        self.pg_conn = conn
        self.pg_pool = pool

    def crossauth_error_from_postgres_error(self, e: Exception) -> CrossauthError:
        code = getattr(e, 'sqlstate', None)
        detail = getattr(e, 'diag', None)
        if detail:
            detail = detail.message_detail

        if code and code.startswith("23"):
            message = f"{code} : {detail or 'Constraint violation during database insert/update'}"
            return CrossauthError(ErrorCode.ConstraintViolation, message)

        message = f"{code} : {detail or 'Constraint violation during database insert/update'}" if code else "Couldn't execute database query"
        return CrossauthError(ErrorCode.Connection, message)

    async def execute(self, query: str, values: List[Any] = []) -> List[Dict[str, Any]]:
        try:
            CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
            with self.pg_conn.cursor() as cur:
                cur.execute(query, values)
                columns = [desc[0] for desc in cur.description]
                return [dict(zip(columns, row)) for row in cur.fetchall()]
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": str(e)}))
            raise self.crossauth_error_from_postgres_error(e)

    def release(self):
        CrossauthLogger.logger().debug(j({"msg": "DB release"}))
        self.pg_pool.putconn(self.pg_conn)

    async def start_transaction(self):
        CrossauthLogger.logger().debug(j({"msg": "DB start transaction"}))
        self.pg_conn.autocommit = False

    async def commit(self):
        CrossauthLogger.logger().debug(j({"msg": "DB commit"}))
        self.pg_conn.commit()

    async def rollback(self):
        CrossauthLogger.logger().debug(j({"msg": "DB rollback"}))
        self.pg_conn.rollback()

class PostgresParameter(DbParameter):
    def __init__(self):
        pass

    def next_parameter(self) -> str:
        param = f"%s"
        return param

