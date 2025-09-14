from crossauth_backend.storage import KeyStorage, KeyDataEntry, \
    UserStorage, UserStorageOptions, UserStorageGetOptions, UserAndSecrets
from crossauth_backend.common.interfaces import Key, PartialKey, \
    User, PartialUser, UserSecrets, UserInputFields, UserSecretsInputFields, PartialUserSecrets
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
    Optional parameters for :class: SqlAlchemyKeyStorage.

    See :func: SqlAlchemyKeyStorage__init__ for details
    """

    key_table : str
    userid_foreign_key_column : str

class SqlAlchemyKeyStorage(KeyStorage):


    def __init__(self, engine : AsyncEngine, options: SqlAlchemyKeyStorageOptions = {}):
        self.__key_table = "Key"
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
            value : Any = cast(Any, key[entry])
            if value is None:
                andClause.append(f"{column} is null")
            else:
                andClause.append(f"{column} = :"+entry)
                values[entry] = key[entry]

        andString = " and ".join(andClause)
        query = f"delete from {self.__key_table} where {andString}"
        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
        print(query, values)
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

class SqlAlchemyUserStorageOptions(UserStorageOptions, total=False):
    """
    Optional parameters for :class: SqlAlchemyUserStorage.

    See :func: SqlAlchemyUserStorage__init__ for details
    """

    user_table : str
    """ Name of user table (to Prisma, ie lowercase).  Default `user` """

    user_secrets_table : str
    """ Name of user secrets table (to Prisma, ie lowercase).  Default `userSecrets` """

    id_column : str
    """ 
    Name of the id column in the user table.  Can be set to `username` if that is your primary key.
    Default `id`. 
    """
    
    userid_foreign_key_column : str
    """
    Name of the user id column in the user secrets.  
    Default `userid`.
    """

    joins : List[str]
    """
    Other tables to join.  
    Default is [] (UserSecrets is alwayws joined)
    """

    force_id_to_number: bool
    """
    This works around a Fastify and Sveltekit limitation.  If the id passed to 
    getUserById() is a string but is numeric, first try forcing it to
    a number before selecting.  If that fails, try it as the string,
    Default true.
    """


class SqlAlchemyUserStorage(UserStorage):


    def __init__(self, engine : AsyncEngine, options: SqlAlchemyKeyStorageOptions = {}):
        self.engine = engine
        self.__user_table = "User"
        self.__user_secrets_table = "UserSecrets"
        self.__id_column = "id"
        self.__userid_foreign_key_column = "userid"
        self.__force_id_to_number = True
        set_parameter("user_table", ParamType.Number, self, options, "USER_STORAGE_TABLE")
        set_parameter("user_secrets_table", ParamType.Number, self, options, "USER_STORAGE_TABLE")
        set_parameter("id_column", ParamType.String, self, options, "USER_ID_COLUMN")
        set_parameter("userid_foreign_key_column", ParamType.String, self, options, "USER_ID_FOREIGN_KEY_COLUMN")
        set_parameter("force_id_to_number", ParamType.Boolean, self, options, "USER_FORCE_ID_TO_NUMBER")

        self.__joins : List[str] = []
        set_parameter("joins", ParamType.JsonArray, self, options, "USER_TABLE_JOINS")

    async def get_user_by(self, field: str, value: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        async with self.engine.begin() as conn:
            ret = await self.get_user_by_in_transaction(conn, field, value)
            return ret
        
    async def get_user_by_in_transaction(self, conn: AsyncConnection, field: str, value: str) -> UserAndSecrets:

        query = f"select * from {self.__user_table} where {field} = :field"
        values = {"field": value}
        res = await conn.execute(text(query), values)
        row = res.fetchone()
        if (row is None):
            raise CrossauthError(ErrorCode.UserNotExist)
        user_fields = self.to_dict(row)
        if (self.__id_column not in user_fields):
            raise CrossauthError(ErrorCode.Configuration, "No ID column found in User table")
        id = user_fields[self.__id_column]
        relations_fields : Dict[str, Dict[str,Any]] = {}
        query = f"select * from {self.__user_secrets_table} where {self.__userid_foreign_key_column} = :field"
        values = {"field": id}
        res = await conn.execute(text(query), values)
        row = res.fetchone()
        if (row is None):
            raise CrossauthError(ErrorCode.InvalidUsername, "No secrets found for user")
        secrets_fields = self.to_dict(row)
        for join in self.__joins:
            query = f"select * from {join} where {self.__userid_foreign_key_column} = :field"
            values = {"field": id}
            res = await conn.execute(text(query), values)
            row = res.fetchone()
            if (row is None):
                raise CrossauthError(ErrorCode.InvalidUsername, "No secrets found for user")
            relations_fields[join] = self.to_dict(row)

        return self.make_user_and_secrets(user_fields, secrets_fields, relations_fields)

    def to_dict(self, row : Row[Any]) -> dict[str,Any]:
        return row._asdict() # type: ignore

    def make_user_and_secrets(self, user_fields: Dict[str, Any], secrets_fields: Dict[str, Any], relations_fields: Dict[str, Dict[str, Any]]) -> UserAndSecrets:
        id: Union[int, str]
        username: str
        username_normalized: str
        email: str
        email_normalized: str
        state: int
        factor1: Union[str, NullType] = Null
        factor2: Union[str, NullType] = Null
        password: Union[str, NullType] = Null
        totpsecret: Union[str, NullType] = Null
        otp: Union[str, NullType] = Null
        expires: Union[int, NullType] = Null

        if self.__id_column in user_fields:
            id = user_fields[self.__id_column]
            if self.__id_column != "id":
                del user_fields[self.__id_column]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No user id in user")

        if "username" in user_fields:
            username = user_fields["username"]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No username in user")
        if "username_normalized" in user_fields:
            username_normalized = user_fields["username_normalized"]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No username_normalized in user")

        if "email" in user_fields:
            email = user_fields["email"]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No username in user")
        if "email_normalized" in user_fields:
            email_normalized = user_fields["email_normalized"]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No email_normalized in user")

        if "state" in user_fields:
            state = user_fields["state"]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No state in user")

        if "factor1" in user_fields:
            factor1 = user_fields["factor1"]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No factor1 in user")
        if "factor2" in user_fields:
            factor2 = user_fields["factor2"]

        if self.__userid_foreign_key_column in secrets_fields:
            id = user_fields[self.__id_column]
            if self.__userid_foreign_key_column != "userid":
                del secrets_fields[self.__userid_foreign_key_column]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No user id in user secrets")

        if "password" in secrets_fields:
            password = secrets_fields["password"]
        if "totpsecret" in secrets_fields:
            totpsecret = secrets_fields["totpsecret"]
        if "otp" in secrets_fields:
            otp = secrets_fields["otp"]

        if "expires" in secrets_fields:
            expires = secrets_fields["expires"]

        user = cast(User, {
            **user_fields,
            "id": id, 
            "username": username,
            "username_normalized": username_normalized,
            "email": email,
            "email_normalized": email_normalized,
            "state": state,
            "factor1": factor1,
            "factor2": factor2,

        })
        for relation in relations_fields:
            fields = relations_fields[relation]
            if self.__userid_foreign_key_column in fields:
                id = fields[self.__id_column]
                if self.__userid_foreign_key_column != "userid":
                    del fields[self.__userid_foreign_key_column]
            else:
                raise CrossauthError(ErrorCode.InvalidUsername, "No user id in "+relation)
            user = cast(User, {
                **user_fields,
                **fields
            })
            
        secrets = cast(UserSecrets, {
            **secrets_fields,
            "userid": id, 
            "password": password,
            "totpsecret": totpsecret,
            "otp": otp,
            "expires": expires,
        })

        return {"user": user, "secrets": secrets}
        
    async def get_user_by_username(self, username: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        raise NotImplementedError

    async def get_user_by_id(self, id: Union[str, int], options: UserStorageGetOptions = {}) -> UserAndSecrets:
        raise NotImplementedError

    async def get_user_by_email(self, email: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        raise NotImplementedError

    async def create_user(self, user: UserInputFields, secrets: Optional[UserSecretsInputFields] = None) -> User:
        raise NotImplementedError

    async def update_user(self, user: PartialUser, secrets: Optional[PartialUserSecrets] = None) -> None:
        raise NotImplementedError

    async def delete_user_by_username(self, username: str) -> None:
        raise NotImplementedError

    async def delete_user_by_id(self, id: str|int) -> None:
        raise NotImplementedError

    async def get_users(self, skip: Optional[int] = None, take: Optional[int] = None) -> List[User]:
        raise NotImplementedError
