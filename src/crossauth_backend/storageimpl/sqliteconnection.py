# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.storageimpl.dbconnection import DbPool, DbConnection, DbParameter
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.utils import set_parameter, ParamType
import sqlite3
from typing import List, Dict, Any, Optional
from abc import ABC, abstractmethod
import json
from datetime import datetime
from enum import Enum

# Assuming these are imported from other modules

class SqlPoolOptions:
    def __init__(self, date_fields: Optional[List[str]] = None):
        self.date_fields = date_fields

class SqlitePool(DbPool):
    def __init__(self, filename: str, options: SqlPoolOptions = SqlPoolOptions()):
        self.database = sqlite3.connect(filename)
        self.date_fields = []
        setParameter("date_fields", ParamType.JsonArray, self, options, "SQLITE_DATE_FIELDS")

    async def connect(self) -> 'SqliteConnection':
        return SqliteConnection(self.database, self.date_fields)

    def parameters(self) -> 'PostgresParameter':
        return PostgresParameter()

class SqliteConnection(DbConnection):
    def __init__(self, database: sqlite3.Connection, date_fields: List[str]):
        self.database = database
        self.date_fields = date_fields

    def crossauth_error_from_sqlite_error(self, e: Any) -> CrossauthError:
        code = getattr(e, 'sqlite_errorcode', None)
        detail = getattr(e, 'sqlite_errorname', None)
        
        if code == sqlite3.SQLITE_CONSTRAINT:
            message = f"{code} : {detail or 'Constraint violation during database insert/update'}"
            return CrossauthError(ErrorCode.ConstraintViolation, message)
        
        message = f"{code} : {detail or 'Constraint violation during database insert/update'}" if code else "Couldn't execute database query"
        return CrossauthError(ErrorCode.Connection, message)

    async def execute(self, query: str, values: List[Any] = []) -> List[Dict[str, Any]]:
        try:
            converted_values = [v.timestamp() if isinstance(v, datetime) else v for v in values]
            CrossauthLogger.logger.debug(json.dumps({"msg": "Executing query", "query": query}))
            
            cursor = self.database.cursor()
            cursor.execute(query, converted_values)
            rows = cursor.fetchall()
            
            column_names = [description[0] for description in cursor.description]
            converted_rows = []
            for row in rows:
                converted_row = {}
                for i, value in enumerate(row):
                    key = column_names[i]
                    if key in self.date_fields:
                        converted_row[key] = datetime.fromtimestamp(value)
                    else:
                        converted_row[key] = value
                converted_rows.append(converted_row)
            
            return converted_rows
        except sqlite3.Error as e:
            CrossauthLogger.logger.debug(json.dumps({"err": str(e)}))
            raise self.crossauth_error_from_sqlite_error(e)

    def release(self):
        CrossauthLogger.logger.debug(json.dumps({"msg": "DB release"}))

    async def start_transaction(self):
        CrossauthLogger.logger.debug(json.dumps({"msg": "DB start transaction"}))
        self.database.execute("BEGIN")

    async def commit(self):
        CrossauthLogger.logger.debug(json.dumps({"msg": "DB commit"}))
        self.database.commit()

    async def rollback(self):
        CrossauthLogger.logger.debug(json.dumps({"msg": "DB rollback"}))
        self.database.rollback()

class PostgresParameter(DbParameter):
    def __init__(self):
        super().__init__()

    def next_parameter(self) -> str:
        return "?"

