from crossauth_backend.storage import KeyStorage, KeyDataEntry
from crossauth_backend.common.interfaces import Key, PartialKey
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.storageimpl.dbconnection import DbPool, DbConnection
from crossauth_backend.utils import set_parameter, ParamType
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union, TypedDict, cast, Mapping
from nulltype import Null, NullType

# Assuming db_pool, DbConnection, Key, CrossauthError, ErrorCode, ParamType, set_parameter, CrossauthLogger are defined elsewhere

class DbKeyStorageOptions(TypedDict, total=False):
    """
    Optional parameters for :class: DbKeyStorage.

    See :func: DbKeyStorage__init__ for detauls
    """
    key_table : str
    userid_foreign_key_column : str

class DbKeyStorage(KeyStorage):
    def __init__(self, db_pool : DbPool, options: DbKeyStorageOptions = {}):
        self.key_table = "keys"
        self.db_pool = db_pool
        self.userid_foreign_key_column = "userid"

        set_parameter("transaction_timeout", ParamType.Number, self, options, "TRANSACTION_TIMEOUT")
        set_parameter("userid_foreign_key_column", ParamType.String, self, options, "USER_ID_FOREIGN_KEY_COLUMN")

        if "key_table" in options:
            self.key_table = options["key_table"]

    async def get_key(self, key: str) -> Key:
        db_client = await self.db_pool.connect()

        try:
            await db_client.start_transaction()
            ret = await self.get_key_in_transaction(db_client, key)
            await db_client.commit()
            return ret
        except Exception as e:
            await db_client.rollback()
            raise e
        finally:
            await db_client.release()

    async def get_key_in_transaction(self, db_client: DbConnection, keyValue: str) -> Key:
        params = self.db_pool.parameters()
        query = f"select * from {self.key_table} where value = {params.next_parameter(keyValue)}"
        res = await db_client.execute(True, query, params) # type: ignore - pylance doesn't accept this as a LiteralString
        if len(res) == 0:
            raise CrossauthError(ErrorCode.InvalidKey)

        return self.make_key(res[0])

    def make_key(self, fields: Dict[str, Any]) -> Key:
        fields = fields.copy()
        value: str
        userid: Union[int, str, NullType] = Null
        created: datetime
        expires: datetime|NullType = Null

        if self.userid_foreign_key_column in fields:
            userid = fields[self.userid_foreign_key_column]
            if self.userid_foreign_key_column != "userid":
                del fields[self.userid_foreign_key_column]

        if "value" in fields:
            value = fields["value"]
        else:
            raise CrossauthError(ErrorCode.InvalidKey, "No value in key")

        if "created" in fields:
            created = fields["created"]
        else:
            raise CrossauthError(ErrorCode.InvalidKey, "No creation date in key")

        if "expires" in fields:
            expires = fields["expires"] or Null

        if "userid" not in fields:
            fields["userid"] = Null

        key = cast(Key, {
            "value": value,
            "created": created,
            "expires": expires,
            "userid" : userid,
            **fields,
        })
        return key

    async def save_key(self, userid: str|int|None, 
                       value: str, 
                       date_created: datetime, 
                       expires: Optional[datetime] = None, 
                       data: Optional[str] = None,
                       extra_fields: Optional[Mapping[str, Any]] = None) -> None:
        error: Optional[CrossauthError] = None

        fields = [self.userid_foreign_key_column, "value", "created", "expires", "data"]
        placeholders : list[str] = []
        params = self.db_pool.parameters()
        placeholders.append(params.next_parameter(userid if userid is not None else None))
        placeholders.append(params.next_parameter(value))
        placeholders.append(params.next_parameter(date_created))
        placeholders.append(params.next_parameter(expires if expires is not None else None))
        placeholders.append(params.next_parameter(data if data is not None else ""))
        if (extra_fields is not None):
            for field in extra_fields:
                fields.append(field)
                placeholders.append(params.next_parameter(extra_fields[field]))

        fieldsString = ", ".join(fields)
        placeholdersString = ", ".join(placeholders)
        db_client = await self.db_pool.connect()

        try:
            query = f"insert into {self.key_table} ({fieldsString}) values ({placeholdersString}) returning value"
            await db_client.execute(False, query, params) # type: ignore
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            if ce.code == ErrorCode.ConstraintViolation:
                CrossauthLogger.logger().warn(j({"msg": "Attempt to create key that already exists. Stack trace follows"}))
                CrossauthLogger.logger().debug(j({"err": e}))
                error = CrossauthError(ErrorCode.KeyExists)
            else:
                CrossauthLogger.logger().debug(j({"err": e}))
                error = CrossauthError(ErrorCode.Connection, "Error saving key")
        finally:
            await db_client.release()

        if error:
            raise error

    async def delete_key(self, value: str) -> None:
        db_client = await self.db_pool.connect()

        try:
            params = self.db_pool.parameters()
            query = f"delete from {self.key_table} where value=" + params.next_parameter(value)
            CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
            await db_client.execute(False, query, params) # type: ignore
        finally:
            await db_client.release()

    async def delete_all_for_user(self, userid: Union[str, int, None], prefix: str, except_key: Optional[str] = None) -> None:
        db_client = await self.db_pool.connect()

        try:
            query = ""
            exceptClause = ""
            params = self.db_pool.parameters()
            if userid:
                query = f"delete from {self.key_table} where {self.userid_foreign_key_column} = {params.next_parameter(userid)} and value like {params.next_parameter(prefix + "%")} "
            else:
                query = f"delete from {self.key_table} where {self.userid_foreign_key_column} is null and value like {params.next_parameter(prefix + "%")}"

            if except_key:
                exceptClause = f"and value != " + params.next_parameter(except_key)

            query += " " + exceptClause

            CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
            await db_client.execute(False, query, params) # type: ignore
        except Exception as e:
            raise e
        finally:
            await db_client.release()

    async def delete_matching(self, key: PartialKey) -> None:
        db_client = await self.db_pool.connect()

        try:
            andClause: List[str] = []
            params = self.db_pool.parameters()
            for entry in key:
                column = entry if entry == "userid" else self.userid_foreign_key_column
                value : Any = key[entry]
                if value is None:
                    andClause.append(f"{column} is null")
                else:
                    andClause.append(f"{column} = {params.next_parameter(key[entry])}")

            andString = " and ".join(andClause)
            query = f"delete from {self.key_table} where {andString}"
            await db_client.execute(False, query, params) # type: ignore
        except Exception as e:
            raise e
        finally:
            await db_client.release()

    async def delete_with_prefix(self, userid: Union[str, int, None], prefix: str) -> None:
        db_client = await self.db_pool.connect()

        try:
            query: str
            params = self.db_pool.parameters()
            if userid:
                param1 = params.next_parameter(userid)
                param2 = params.next_parameter(prefix + "%")
                query = f"delete from {self.key_table} where {self.userid_foreign_key_column} = {param1} and value like {param2}"
            else:
                param1 = params.next_parameter(prefix + "%")
                query = f"delete from {self.key_table} where {self.userid_foreign_key_column} is null and value like {param1}"

            await db_client.execute(False, query, params) # type: ignore
        except Exception as e:
            raise e
        finally:
            await db_client.release()

    async def get_all_for_user(self, userid: str|int|None = None) -> List[Key]:
        db_client = await self.db_pool.connect()

        try:
            returnKeys: List[Key] = []
            query: str
            params = self.db_pool.parameters()
            if userid:
                query = f"select * from {self.key_table} where {self.userid_foreign_key_column} = {params.next_parameter(userid)}"
            else:
                query = f"select * from {self.key_table} where {self.userid_foreign_key_column} is null"

            CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
            res = await db_client.execute(True, query, params) # type: ignore
            if len(res) == 0:
                return []

            for row in res:
                key: Key = self.make_key(row)
                if self.userid_foreign_key_column != "userid":
                    key["userid"] = key[self.userid_foreign_key_column]
                    del key[self.userid_foreign_key_column]
                returnKeys.append(key)

            return returnKeys
        except Exception as e:
            raise e
        finally:
            await db_client.release()

    async def update_key(self, key: PartialKey) -> None:
        db_client = await self.db_pool.connect()

        try:
            await db_client.start_transaction()
            await self.update_key_in_transaction(db_client, key)
            await db_client.commit()
        except Exception as e:
            await db_client.rollback()
            raise e
        finally:
            await db_client.release()

    async def update_key_in_transaction(self, db_client: DbConnection, key: PartialKey) -> None:
        keyData = key.copy()
        if "value" not in key:
            raise CrossauthError(ErrorCode.InvalidKey)
        del keyData["value"]

        setFields: List[str] = []
        params = self.db_pool.parameters()
        for field in keyData:
            dbField = field
            if keyData[field] is not None and field == "userid" and self.userid_foreign_key_column != "userid":
                dbField = self.userid_foreign_key_column
            setFields.append(f"{field} = {params.next_parameter(keyData[dbField])}")

        if len(setFields) > 0:
            setString = ", ".join(setFields)
            query = f"update {self.key_table} set {setString} where value = {params.next_parameter(key["value"])}"
            CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
            await db_client.execute(False, query, params) # type: ignore

    async def update_data(self, key_name: str, data_name: str, value: Any) -> None:
        return await self.update_many_data(key_name, [{"data_name": data_name, "value": value}])

    async def update_many_data(self, key_name: str, 
                               data_array: List[KeyDataEntry]) -> None:
        db_client = await self.db_pool.connect()

        try:
            await db_client.start_transaction()
            key = await self.get_key_in_transaction(db_client, key_name)
            data: Dict[str, Any]
            if "data" not in key or not key["data"] or key["data"] == "":
                data = {}
            else:
                try:
                    data = json.loads(key["data"])
                except Exception as e:
                    CrossauthLogger.logger().debug(j({"err": e}))
                    raise CrossauthError(ErrorCode.DataFormat)

            for item in data_array:
                if ("value" in item):
                    ret = self._update_data_internal(data, item["data_name"], item["value"])
                    if not ret:
                        raise CrossauthError(ErrorCode.BadRequest, f"Parents of {item['data_name']} not found in key data")
                    data = ret

            await self.update_key_in_transaction(db_client, {"value": key["value"], "data": json.dumps(data)})
            await db_client.commit()
        except Exception as e:
            await db_client.rollback()
            if e and isinstance(e, dict) and "isCrossauthError" not in e:
                CrossauthLogger.logger().debug(j({"err": e}))
                raise CrossauthError(ErrorCode.Connection, "Failed updating session data")
            raise e
        finally:
            await db_client.release()

    async def delete_data(self, key_name: str, data_name: str) -> None:
        db_client = await self.db_pool.connect()

        try:
            await db_client.start_transaction()
            key = await self.get_key_in_transaction(db_client, key_name)
            data: Dict[str, Any] = {}
            changed = False
            if "data" in key and key["data"] != "":
                try:
                    data = json.loads(key["data"])
                except Exception as e:
                    CrossauthLogger.logger().debug(j({"err": e}))
                    raise CrossauthError(ErrorCode.DataFormat)
                changed = self._delete_data_internal(data, data_name)

            if changed:
                await self.update_key_in_transaction(db_client, {"value": key["value"], "data": json.dumps(data)})
            await db_client.commit()
        except Exception as e:
            await db_client.rollback()
            if e and isinstance(e, dict) and "isCrossauthError" not in e:
                CrossauthLogger.logger().debug(j({"err": e}))
                raise CrossauthError(ErrorCode.Connection, "Failed updating session data")
            raise e
        finally:
            await db_client.release()

