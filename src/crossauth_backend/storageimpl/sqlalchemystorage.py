from crossauth_backend.storage import KeyStorage, KeyDataEntry
from crossauth_backend.common.interfaces import Key, PartialKey
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.utils import set_parameter, ParamType
import json
from datetime import datetime
from typing import Any, Dict, List, Optional, Union, TypedDict, cast, Mapping
from nulltype import Null, NullType
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncConnection
from sqlalchemy import text, Row

class SqlAlchemyKeyStorageOptions(TypedDict, total=False):
    """
    Optional parameters for :class: DbKeyStorage.

    See :func: DbKeyStorage__init__ for detauls
    """

    __key_table : str
    __userid_foreign_key_column : str

class SqlAlchemyKeyStorage(KeyStorage):


    def __init__(self, engine : AsyncEngine, options: SqlAlchemyKeyStorageOptions = {}):
        self.__key_table = "keys"
        self.engine = engine
        self.__userid_foreign_key_column = "userid"
        set_parameter("key_table", ParamType.Number, self, options, "KEY_STORAGE_TABLE")
        set_parameter("userid_foreign_key_column", ParamType.String, self, options, "USER_ID_FOREIGN_KEY_COLUMN")

    async def get_key(self, key: str) -> Key:

        async with self.engine.begin() as conn:
            ret = await self.get_key_in_transaction(conn, key)
            return ret
        
    async def get_key_in_transaction(self, conn: AsyncConnection, keyValue: str) -> Key:
        query = f"select * from {self.__key_table} where value = :key"
        values = {"key": keyValue}
        res = await conn.execute(text(query), values)
        row = res.fetchone()
        if (row is None):
            raise CrossauthError(ErrorCode.InvalidKey)


        return self.make_key(row)

    def to_dict(self, row : Row[Any], with_relationships:bool=True) -> dict[str,Any]:
        return row._asdict() # type: ignore

    def make_key(self, row: Row[Any]) -> Key:
        fields = self.to_dict(row)
        value: str
        userid: Union[int, str, NullType] = Null
        created: datetime
        expires: datetime|NullType = Null

        if self.__userid_foreign_key_column in fields:
            userid = fields[self.__userid_foreign_key_column]
            if self.__userid_foreign_key_column != "userid":
                del fields[self.__userid_foreign_key_column]

        if "value" in fields:
            value = fields["value"]
        else:
            raise CrossauthError(ErrorCode.InvalidKey, "No value in key")

        if "created" in fields:
            # SQLite doesn't have datetime fields
            if (type(fields["created"]) == str):
                created = datetime.strptime(fields["created"], '%Y-%m-%d %H:%M:%S.%f')
            else:
                created = fields["created"]
        else:
            raise CrossauthError(ErrorCode.InvalidKey, "No creation date in key")

        if "expires" in fields:
            # SQLite doesn't have datetime fields
            if (type(fields["expires"]) == str):
                expires = datetime.strptime(fields["expires"], '%Y-%m-%d %H:%M:%S.%f')
            else:
                expires = fields["expires"] or Null

        if "userid" not in fields:
            fields["userid"] = Null

        key = cast(Key, {
            **fields,
            "value": value,
            "created": created,
            "expires": expires,
            "userid" : userid,
        })
        return key

    async def save_key(self, userid: str|int|None, 
                       value: str, 
                       date_created: datetime, 
                       expires: Optional[datetime] = None, 
                       data: Optional[str] = None,
                       extra_fields: Optional[Mapping[str, Any]] = None) -> None:

        fields = [self.__userid_foreign_key_column, "value", "created", "expires", "data"]
        placeholders : list[str] = []
        values : dict[str,Any] = {}
        placeholders.append(":userid")
        placeholders.append(":value")
        placeholders.append(":date_created")
        placeholders.append(":expires")
        placeholders.append(":data")
        values["userid"] = userid if userid is not None else None
        values["value"] = value
        values["date_created"] = date_created
        values["expires"] = expires if expires is not None else None
        values["data"] = data if data is not None else ""
        print("extraFields", extra_fields)

        if (extra_fields is not None):
            for field in extra_fields:
                fields.append(field)
                placeholders.append(":"+field)
                values[field] = extra_fields[field]
        fieldsString = ", ".join(fields)
        placeholdersString = ", ".join(placeholders)
        query = f"insert into {self.__key_table} ({fieldsString}) values ({placeholdersString})"
        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
        async with self.engine.begin() as conn:
            await conn.execute(text(query), values)

    async def delete_key(self, value: str) -> None:

        query = f"delete from {self.__key_table} where value = :value"
        values = {"value": value}
        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
        async with self.engine.begin() as conn:
            await conn.execute(text(query), values) 

    async def delete_all_for_user(self, userid: Union[str, int, None], prefix: str, except_key: Optional[str] = None) -> None:

        query = ""
        exceptClause = ""
        values : dict[str, Any] = {}
        if userid:
            query = f"delete from {self.__key_table} where {self.__userid_foreign_key_column} = :userid and value like :value"
            values = {"userid": userid, "value": prefix + "%"}
        else:
            query = f"delete from {self.__key_table} where {self.__userid_foreign_key_column} is null and value like :value"
            values = {"value": prefix + "%"}

        if except_key:
            exceptClause = f" and value != :except"

        query += exceptClause
        values["except"] = except_key

        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
        async with self.engine.begin() as conn:
            await conn.execute(text(query), values) 

    async def delete_matching(self, key: PartialKey) -> None:

        andClause: List[str] = []
        values : dict[str,Any] = {}
        for entry in key:
            column = entry if entry == "userid" else self.__userid_foreign_key_column
            value : Any = key[entry]
            if value is None:
                andClause.append(f"{column} is null")
            else:
                andClause.append(f"{column} = :"+entry)
                values[entry] = key[entry]

        andString = " and ".join(andClause)
        query = f"delete from {self.__key_table} where {andString}"
        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
        async with self.engine.begin() as conn:
            await conn.execute(text(query), values) 

    async def delete_with_prefix(self, userid: Union[str, int, None], prefix: str) -> None:

        query: str
        values : dict[str,Any] = {}
        if userid:
            values["userid"] = userid
            values["value"] = prefix + "%"
            query = f"delete from {self.__key_table} where {self.__userid_foreign_key_column} = :userid and value like :value"
        else:
            query = f"delete from {self.__key_table} where {self.__userid_foreign_key_column} is null and value like :value"
            values["value"] = prefix + "%"

        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
        async with self.engine.begin() as conn:
            await conn.execute(text(query), values) 

    async def get_all_for_user(self, userid: str|int|None = None) -> List[Key]:

        returnKeys: List[Key] = []
        query: str
        values : dict[str,Any] = {}
        if userid:
            query = f"select * from {self.__key_table} where {self.__userid_foreign_key_column} = :userid"
            values["userid"] = userid
        else:
            query = f"select * from {self.__key_table} where {self.__userid_foreign_key_column} is null"

        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
        async with self.engine.begin() as conn:
            res = await conn.execute(text(query), values) 
        rows = res.fetchall()
        if len(rows) == 0:
            return []

        for row in rows:
            key: Key = self.make_key(row)
            if self.__userid_foreign_key_column != "userid":
                key["userid"] = key[self.__userid_foreign_key_column]
                del key[self.__userid_foreign_key_column]
            returnKeys.append(key)

        return returnKeys

    async def update_key(self, key: PartialKey) -> None:

        async with self.engine.begin() as conn:
            await self.update_key_in_transaction(conn, key)

    async def update_key_in_transaction(self, conn : AsyncConnection, key: PartialKey) -> None:
        keyData = key.copy()
        if "value" not in key:
            raise CrossauthError(ErrorCode.InvalidKey)
        del keyData["value"]

        setFields: List[str] = []
        values : dict[str,Any] = {}
        for field in keyData:
            dbField = field
            if keyData[field] is not None and field == "userid" and self.__userid_foreign_key_column != "userid":
                dbField = self.__userid_foreign_key_column
            values[dbField] = keyData[dbField]
            setFields.append(f"{field} = :{dbField}")

        if len(setFields) > 0:
            setString = ", ".join(setFields)
            query = f"update {self.__key_table} set {setString} where value = :value"
            values["value"] = key["value"]
            CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
            await conn.execute(text(query), values) 

    async def update_data(self, key_name: str, data_name: str, value: Any) -> None:
        return await self.update_many_data(key_name, [{"data_name": data_name, "value": value}])

    async def update_many_data(self, key_name: str, 
                               data_array: List[KeyDataEntry]) -> None:

        async with self.engine.begin() as conn:
            key = await self.get_key_in_transaction(conn, key_name)
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

                await self.update_key_in_transaction(conn, {"value": key["value"], "data": json.dumps(data)})

    async def delete_data(self, key_name: str, data_name: str) -> None:

        async with self.engine.begin() as conn:
            key = await self.get_key_in_transaction(conn, key_name)
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
                await self.update_key_in_transaction(conn, {"value": key["value"], "data": json.dumps(data)})

