# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.storageimpl.dbconnection import DbPool, DbConnection, DbParameter
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from typing import List, Dict, Any, LiteralString, Mapping
import psycopg
import psycopg_pool
from psycopg.rows import dict_row

class PostgresPool(DbPool):
    def __init__(self, pg_pool: psycopg_pool.AsyncConnectionPool):
        self.pg_pool = pg_pool

    async def connect(self) -> 'PostgresConnection':
        conn = await self.pg_pool.getconn()
        CrossauthLogger.logger().debug(j({"msg": "DB connect"}))
        conn = PostgresConnection(conn, self.pg_pool)
        await conn.pg_conn.set_autocommit(True)
        return conn

    def parameters(self) -> 'PostgresParameter':
        return PostgresParameter()

class PostgresConnection(DbConnection):
    def __init__(self, conn: psycopg.AsyncConnection, 
                 pool: psycopg_pool.AsyncConnectionPool):
        self.pg_conn = conn
        self.pg_pool = pool


    def crossauth_error_from_postgres_error(self, e: Exception) -> CrossauthError:
        if (not isinstance(e, psycopg.ProgrammingError)):
            return CrossauthError.as_crossauth_error(e)
        code = e.diag.sqlstate

        #code = getattr(e, 'sqlstate', None)
        detail = getattr(e, 'diag', None)
        if detail:
            detail = detail.message_detail

        if code and code.startswith("23"):
            message = f"{code} : {detail or 'Constraint violation during database insert/update'}"
            return CrossauthError(ErrorCode.ConstraintViolation, message)

        message = f"{code} : {detail or 'Constraint violation during database insert/update'}" if code else "Couldn't execute database query"
        return CrossauthError(ErrorCode.Connection, message)

    async def execute(self, select : bool, query: LiteralString, params: DbParameter|None) -> List[Dict[str, Any]]:
        try:
            CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
            cur = self.pg_conn.cursor(row_factory=dict_row)
            if (params is None):
                await cur.execute(query, [])
            else:
                values = params.values()
                if (type(values) == Mapping):
                    raise CrossauthError(ErrorCode.Configuration, "DbParameter.values() should return list")
                await cur.execute(query, params.values())
            if (select):
                return await cur.fetchall()
            return []
        except Exception as e:
            CrossauthLogger.logger().debug(j({"err": str(e)}))
            raise self.crossauth_error_from_postgres_error(e)

    async def release(self):
        CrossauthLogger.logger().debug(j({"msg": "DB release"}))
        await self.pg_pool.putconn(self.pg_conn)

    async def start_transaction(self):
        CrossauthLogger.logger().debug(j({"msg": "DB start transaction"}))
        await self.pg_conn.set_autocommit(False)

    async def commit(self):
        CrossauthLogger.logger().debug(j({"msg": "DB commit"}))
        await self.pg_conn.commit()

    async def rollback(self):
        CrossauthLogger.logger().debug(j({"msg": "DB rollback"}))
        await self.pg_conn.rollback()

class PostgresParameter(DbParameter):
    def __init__(self):
        self._values : list[Any] = []

    def next_parameter(self, value : Any) -> str:
        param = '%s'
        self._values.append(value)
        return param
    
    def values(self) -> list[str]:
        return self._values
