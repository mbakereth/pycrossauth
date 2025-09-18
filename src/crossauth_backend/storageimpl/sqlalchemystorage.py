from crossauth_backend.storage import KeyStorage, KeyDataEntry, \
    UserStorage, UserStorageOptions, UserStorageGetOptions, UserAndSecrets, \
    OAuthClientStorage, OAuthClientStorageOptions, \
        OAuthAuthorizationStorage, OAuthAuthorizationStorageOptions
from crossauth_backend.common.interfaces import Key, PartialKey, \
    User, PartialUser, UserSecrets, UserInputFields, UserSecretsInputFields, PartialUserSecrets, \
    OAuthClient, PartialOAuthClient
from crossauth_backend.common.error import CrossauthError, ErrorCode
from crossauth_backend.common.logger import CrossauthLogger, j
from crossauth_backend.utils import set_parameter, ParamType
import json
from datetime import date, datetime
from typing import Any, Dict, List, Optional, Union, TypedDict, cast, Mapping
from nulltype import Null, NullType
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncConnection
from sqlalchemy import text, Row, RowMapping
import re
import sqlite3

###################
## KeyStorage

class SqlAlchemyKeyStorageOptions(TypedDict, total=False):
    """
    Optional parameters for :class: SqlAlchemyKeyStorage.

    See :func: SqlAlchemyKeyStorage__init__ for details
    """

    key_table : str
    userid_foreign_key_column : str

class SqlAlchemyKeyStorage(KeyStorage):


    def __init__(self, engine : AsyncEngine, options: SqlAlchemyKeyStorageOptions = {}):
        super().__init__()
        self.__key_table = "Key"
        self.engine = engine
        self.__userid_foreign_key_column = "userid"
        set_parameter("key_table", ParamType.String, self, options, "KEY_STORAGE_TABLE")
        set_parameter("userid_foreign_key_column", ParamType.String, self, options, "USER_ID_FOREIGN_KEY_COLUMN")
        if (re.match(r'^[A-Za-z0-9_]+$', self.__key_table) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid key table name " + self.__key_table)
        if (re.match(r'^[A-Za-z0-9_]+$', self.__userid_foreign_key_column) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid key userid foreign key name " + self.__userid_foreign_key_column)

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


        return self._make_key(row)

    def to_dict(self, row : Row[Any], with_relationships:bool=True) -> dict[str,Any]:
        return row._asdict() # type: ignore

    def _make_key(self, row: Row[Any]) -> Key:
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
            elif (type(fields["created"]) == int):
                created = datetime.fromtimestamp(int(fields["created"]))
            elif (type(fields["expires"]) == float):
                created = datetime.fromtimestamp(float(fields["created"]))
            else:
                created = fields["created"]
        else:
            raise CrossauthError(ErrorCode.InvalidKey, "No creation date in key")

        if "expires" in fields:
            # SQLite doesn't have datetime fields
            if (type(fields["expires"]) == str):
                expires = datetime.strptime(fields["expires"], '%Y-%m-%d %H:%M:%S.%f')
            elif (type(fields["expires"]) == int):
                expires = datetime.fromtimestamp(int(fields["expires"]))
            elif (type(fields["expires"]) == float):
                expires = datetime.fromtimestamp(float(fields["expires"]))
            else:
                expires = cast(datetime, fields["expires"])

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
            if (re.match(r'^[A-Za-z0-9_]+$', entry) == None):
                raise CrossauthError(ErrorCode.BadRequest, f"Invalid field {entry}")
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
            key: Key = self._make_key(row)
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

###################
## UserStorage

class SqlAlchemyUserStorageOptions(UserStorageOptions, total=False):
    """
    Optional parameters for :class: SqlAlchemyUserStorage.

    See :func: SqlAlchemyUserStorage__init__ for details
    """

    user_table : str
    """ Name of user table Default `User` """

    user_secrets_table : str
    """ Name of user secrets table (Default `UserSecrets` """

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


    def __init__(self, engine : AsyncEngine, options: SqlAlchemyUserStorageOptions = {}):
        self.engine = engine
        self.__user_table = "User"
        self.__user_secrets_table = "UserSecrets"
        self.__id_column = "id"
        self.__userid_foreign_key_column = "userid"
        self.__force_id_to_number = True
        set_parameter("user_table", ParamType.String, self, options, "USER_TABLE")
        set_parameter("user_secrets_table", ParamType.String, self, options, "USER_SECRETS_TABLE")
        set_parameter("id_column", ParamType.String, self, options, "USER_ID_COLUMN")
        set_parameter("userid_foreign_key_column", ParamType.String, self, options, "USER_ID_FOREIGN_KEY_COLUMN")
        set_parameter("force_id_to_number", ParamType.Boolean, self, options, "USER_FORCE_ID_TO_NUMBER")

        self.__joins : List[str] = []
        set_parameter("joins", ParamType.JsonArray, self, options, "USER_TABLE_JOINS")

        if (re.match(r'^[A-Za-z0-9_]+$', self.__user_table) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid user table name " + self.__user_table)
        if (re.match(r'^[A-Za-z0-9_]+$', self.__user_secrets_table) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid user secrets table name " + self.__user_secrets_table)
        if (re.match(r'^[A-Za-z0-9_]+$', self.__userid_foreign_key_column) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid user userid foreign key name " + self.__userid_foreign_key_column)
        if (re.match(r'^[A-Za-z0-9_]+$', self.__id_column) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid user user id name " + self.__id_column)

    async def get_user_by(self, field: str, value: Union[str, int], options: UserStorageGetOptions = {}) -> UserAndSecrets:
        async with self.engine.begin() as conn:
            ret = await self.get_user_by_in_transaction(conn, field, value)
            return ret
        
    async def get_user_by_in_transaction(self, conn: AsyncConnection, field: str, value: Union[str, int]) -> UserAndSecrets:

        if (field == "username"):
            value = self.normalize(value if type(value) == str else str(value))
            field = "username_normalized"
        elif (field == "email"):
            value = self.normalize(value if type(value) == str else str(value))
            field = "email_normalized"
        elif (field != "id"):
            raise CrossauthError(ErrorCode.BadRequest, "Can only get user by username, id or email")
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
        secrets_fields : Dict[str,Any]|None = None
        if (row is not None):
            secrets_fields = self.to_dict(row)
        for join in self.__joins:
            query = f"select * from {join} where {self.__userid_foreign_key_column} = :field"
            values = {"field": id}
            res = await conn.execute(text(query), values)
            row = res.fetchone()
            if (row is not None):
                relations_fields[join] = self.to_dict(row)

        return self._make_user_and_secrets(user_fields, secrets_fields, relations_fields)

    def to_dict(self, row : Row[Any]) -> dict[str,Any]:
        return row._asdict() # type: ignore

    def _make_user_and_secrets(self, user_fields: Dict[str, Any], secrets_fields: Dict[str, Any]|None, relations_fields: Dict[str, Dict[str, Any]]) -> UserAndSecrets:
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
            

        if secrets_fields:
            if self.__userid_foreign_key_column in secrets_fields:
                if self.__userid_foreign_key_column != "userid":
                    del secrets_fields[self.__userid_foreign_key_column]

            if "password" in secrets_fields:
                password = secrets_fields["password"]
            if "totpsecret" in secrets_fields:
                totpsecret = secrets_fields["totpsecret"]
            if "otp" in secrets_fields:
                otp = secrets_fields["otp"]

            if "expires" in secrets_fields:
                expires = secrets_fields["expires"]

            secrets = cast(UserSecrets, {
                **secrets_fields,
                "userid": id, 
                "password": password,
                "totpsecret": totpsecret,
                "otp": otp,
                "expires": expires,
            })

            return {"user": user, "secrets": secrets}
        
        else:

            return {"user": user, "secrets": {"userid": id}}

        
    async def get_user_by_username(self, username: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        return await self.get_user_by("username", username, options)

    async def get_user_by_id(self, id: Union[str, int], options: UserStorageGetOptions = {}) -> UserAndSecrets:
        return await self.get_user_by("id", id, options)

    async def get_user_by_email(self, email: str, options: UserStorageGetOptions = {}) -> UserAndSecrets:
        return await self.get_user_by("email", email, options)

    async def create_user(self, user: UserInputFields, secrets: Optional[UserSecretsInputFields] = None) -> User:
        if (secrets is not None and "password" not in secrets):
            raise CrossauthError(ErrorCode.PasswordFormat, "Password required when creating user")

        username_normalized = ""
        email_normalized : str|None = None

        try:
            if "email" in user and "email_normalized" not in user:
                email_normalized = self.normalize(user["email"])
            if ("username_normalized" not in user):
                username_normalized = self.normalize(user["username"])
        
            for field in user:
                if (re.match(r'^[A-Za-z0-9_\.]+$', field) is None):
                    raise CrossauthError(ErrorCode.BadRequest, "Invalid user field name " + field)
            if secrets:
                for field in secrets:
                    if (re.match(r'^[A-Za-z0-9_\.]+$', field) is None):
                        raise CrossauthError(ErrorCode.BadRequest, "Invalid secrets field name " + field)

            field_names : List[str] = []
            field_placeholders : List[str] = []
            field_values : Dict[str, Any] = {}
            
            for field in user:
                field_names.append(field)
                field_placeholders.append(":"+field)
                field_values[field] = user[field]
            if ("username_normalized" not in field_values):
                field_names.append("username_normalized")
                field_placeholders.append(":username_normalized")
                field_values["username_normalized"] = username_normalized
            if (email_normalized and "email_normalized" not in field_values):
                field_names.append("email_normalized")
                field_placeholders.append(":email_normalized")
                field_values["email_normalized"] = email_normalized

            field_names_str = ", ".join(field_names)
            field_placeholders_str = ", ".join(field_placeholders)

            query = f"INSERT INTO {self.__user_table} ({field_names_str}) VALUES ({field_placeholders_str})"
            CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
            async with self.engine.begin() as conn:
                await conn.execute(text(query), field_values) 
                ret = await self.get_user_by_in_transaction(conn, "username", user["username"])

                if (secrets):
                    field_names : List[str] = []
                    field_placeholders : List[str] = []
                    field_values : Dict[str, Any] = {}
                    
                    for field in secrets:
                        if (field != "userid"):
                            field_names.append(field)
                            field_placeholders.append(":"+field)
                            field_values[field] = secrets[field]

                    field_names.append(self.__userid_foreign_key_column)
                    field_placeholders.append(":" + self.__userid_foreign_key_column)
                    field_values[self.__userid_foreign_key_column] = ret["user"]["id"]

                    field_names_str = ", ".join(field_names)
                    field_placeholders_str = ", ".join(field_placeholders)

                    query = f"INSERT INTO {self.__user_secrets_table} ({field_names_str}) VALUES ({field_placeholders_str})"
                    CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                    await conn.execute(text(query), field_values) 

                return ret["user"]
                
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": ce}))
            print(e)
            raise ce

    
    async def update_user(self, user: PartialUser, secrets: Optional[PartialUserSecrets] = None) -> None:
        if (secrets is not None and "password" not in secrets):
            raise CrossauthError(ErrorCode.PasswordFormat, "Password required when creating user")

        username_normalized = ""
        email_normalized : str|None = None
        if ("id" not in user):
            raise CrossauthError(ErrorCode.BadRequest, "Must pass id in user when updating")
        id : str|int = user["id"]

        try:
            if "email" in user and "email_normalized" not in user:
                email_normalized = self.normalize(user["email"])
            if ("username" in user and "username_normalized" not in user):
                username_normalized = self.normalize(user["username"])
        
            for field in user:
                if (re.match(r'^[A-Za-z0-9_\.]+$', field) is None):
                    raise CrossauthError(ErrorCode.BadRequest, "Invalid user field name " + field)
            if secrets:
                for field in secrets:
                    if (re.match(r'^[A-Za-z0-9_\.]+$', field) is None):
                        raise CrossauthError(ErrorCode.BadRequest, "Invalid secrets field name " + field)

            field_placeholders : List[str] = []
            field_values : Dict[str, Any] = {}
            
            for field in user:
                if (field != "id"):
                    field_placeholders.append(field + " = :"+field)
                    field_values[field] = user[field]
            if ("username_normalized" not in field_values and "username" in user):
                field_placeholders.append("username_normalized = :username_normalized")
                field_values["username_normalized"] = username_normalized
            if (email_normalized and "email_normalized" not in field_values and "email" in user):
                field_placeholders.append("email_normalized = :email_normalized")
                field_values["email_normalized"] = email_normalized

            field_placeholders_str = ", ".join(field_placeholders)
            field_values[self.__id_column] = id

            async with self.engine.begin() as conn:

                if (len(field_placeholders) > 0):
                    query = f"UPDATE {self.__user_table} SET {field_placeholders_str} WHERE {self.__id_column} = :{self.__id_column}"
                    CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                    await conn.execute(text(query), field_values) 

                if (secrets):
                    field_placeholders : List[str] = []
                    field_values : Dict[str, Any] = {}
                    
                    for field in secrets:
                        if (field != "id"):
                            field_placeholders.append(field + " = :"+field)
                            field_values[field] = secrets[field]

                    field_placeholders_str = ", ".join(field_placeholders)
                    field_values[self.__userid_foreign_key_column] = id

                    query = f"UPDATE {self.__user_secrets_table} SET {field_placeholders_str} WHERE {self.__userid_foreign_key_column} = :{self.__userid_foreign_key_column}"
                    CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                    await conn.execute(text(query), field_values) 
                
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": ce}))
            raise ce

    async def delete_user_by_username(self, username: str) -> None:
        query = f"delete from {self.__user_table} where username_normalized = :value"
        values = {"value": self.normalize(username)}
        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
        async with self.engine.begin() as conn:
            await conn.execute(text(query), values) 

    async def delete_user_by_id(self, id: str|int) -> None:
        query = f"delete from {self.__user_table} where {self.__id_column} = :value"
        values = {"value": id}
        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
        async with self.engine.begin() as conn:
            await conn.execute(text(query), values) 

    async def get_users(self, skip: Optional[int] = None, take: Optional[int] = None) -> List[User]:
        raise NotImplementedError
    
####################################
## OAuthClientStorage

class SqlAlchemyOAuthClientStorageOptions(OAuthClientStorageOptions, total=False):
    """
    Optional parameters for :class: SqlAlchemyUserStorage.

    See :func: SqlAlchemyUserStorage__init__ for details
    """

    client_table : str
    """ Name of client table.  Default `OAuthClient` """

    valid_flow_table : str
    """ Name of the valid flows table.  Default `OAuthClientValidFlow` """

    redirect_uri_table : str
    """ 
    Name of the redirect uri table.  Default `OAuthClientRedirectUri`. 
    """

    userid_foreign_key_column : str
    """
    Column name for the userid field in the client table. Default `userid`
    """

class SqlAlchemyOAuthClientStorage(OAuthClientStorage):


    def __init__(self, engine : AsyncEngine, options: SqlAlchemyOAuthClientStorageOptions = {}):
        self.engine = engine
        self.__client_table = "OAuthClient"
        self.__valid_flow_table = "OAuthClientValidFlow"
        self.__redirect_uri_table = "OAuthClientRedirectUri"
        self.__userid_foreign_key_column = "userid"

        set_parameter("client_table", ParamType.String, self, options, "OAUTH_CLIENT_TABLE")
        set_parameter("valid_flow_table", ParamType.String, self, options, "OAUTH_REDIRECTURI_TABLE")
        set_parameter("redirect_uri_table", ParamType.String, self, options, "OAUTH_VALID_FLOW_TABLE")
        set_parameter("userid_foreign_key_column", ParamType.String, self, options, "USER_ID_FOREIGN_KEY_COLUMN")

        self.__joins : List[str] = []
        set_parameter("joins", ParamType.JsonArray, self, options, "USER_TABLE_JOINS")

        if (re.match(r'^[A-Za-z0-9_]+$', self.__client_table) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid oauth client table name " + self.__client_table)
        if (re.match(r'^[A-Za-z0-9_]+$', self.__valid_flow_table) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid user oauth client valid flows table name " + self.__valid_flow_table)
        if (re.match(r'^[A-Za-z0-9_]+$', self.__redirect_uri_table) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid user oauth client redirect uris table name " + self.__redirect_uri_table)

    async def get_client_by_id(self, client_id: str) -> OAuthClient:
        async with self.engine.begin() as conn:
            ret = await self.get_client_in_transaction(conn, "client_id", client_id)
            return ret[0]
        
    async def get_client_in_transaction(self, conn: AsyncConnection, field: str|None, value: str|None, userid: Optional[int|str|NullType] = None, skip: int|None=None, take: int|None=None) -> List[OAuthClient]:

        if (field is not None and (field != "client_id" and field != "client_name")):
            raise CrossauthError(ErrorCode.BadRequest, "Invalid get_client_by field " + field)
        where : List[str] = []
        values : Dict[str,Any] = {}
        limit = ""
        offset = ""
        if (field is not None):
            where.append(f"{field} = :field")
            values["field"] = value
        if (userid == Null):
            where.append(f"{self.__userid_foreign_key_column} is NULL")
        elif (userid is not None):
            where.append(f"{self.__userid_foreign_key_column} = :userid")
            values["userid"] = userid
        if (skip is not None):
            offset = "OFFSET " + str(int(skip))
        if (take is not None):
            limit = "LIMIT " + str(int(take))
        where_str = " AND ".join(where)
        if (len(where_str) > 0):
            where_str = "WHERE " + where_str
        query = f"select * from {self.__client_table} {where_str} {limit} {offset}"
        res = await conn.execute(text(query), values)
        clients : List[OAuthClient] = []
        for row in res.mappings():
            if ("client_id" not in row):
                raise CrossauthError(ErrorCode.Configuration, "No client_id in client table")
            client_id = row["client_id"]

            query = f"select * from {self.__redirect_uri_table} where client_id = :field"
            values = {"field": client_id}
            redirect_uri_res = await conn.execute(text(query), values)
            redirect_uri_mappings : List[RowMapping] = []
            for redirect_uri_row in redirect_uri_res.mappings():
                redirect_uri_mappings.append(redirect_uri_row)

            query = f"select * from {self.__valid_flow_table} where client_id = :field"
            values = {"field": client_id}
            valid_flow_res = await conn.execute(text(query), values)
            valid_flow_mappings : List[RowMapping] = []
            for valid_flow_row in valid_flow_res.mappings():
                valid_flow_mappings.append(valid_flow_row)

            client = self._make_client(row, redirect_uri_mappings, valid_flow_mappings)
            clients.append(client)
        if (field == "client_id" and len(clients) == 0):
            raise CrossauthError(ErrorCode.InvalidClientId, "No client exists with " + field + " " + str(value))
        return clients

    def _make_client(self, client_fields: RowMapping, redirect_uri_fields: List[RowMapping], valid_flow_fields: List[RowMapping]) -> OAuthClient:
        client_id: str
        confidential: bool
        client_name: str
        client_secret: str|NullType|None = None

        if "client_id" in client_fields:
            client_id = client_fields["client_id"]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No client id in client table")

        if "confidential" in client_fields:
            confidential = client_fields["confidential"]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No confidential field in client table")

        if "client_name" in client_fields:
            client_name = client_fields["client_name"]
        else:
            raise CrossauthError(ErrorCode.InvalidUsername, "No client_name field in client table")

        if "client_secret" in client_fields:
            client_secret = client_fields["client_secret"]

        client = cast(OAuthClient, {
            **client_fields,
            "client_id": client_id,
            "confidential": confidential,
            "client_name": client_name,
        })
        if (client_secret is not None):
            if (type(client_secret) == NullType):
                client["client_secret"] = None
            else:
                client["client_secret"] = client_secret  # type: ignore

        client["redirect_uri"] = []
        for row in redirect_uri_fields:
            if ("uri" in row):
                client["redirect_uri"].append(row["uri"])

        client["valid_flow"] = []
        for row in valid_flow_fields:
            if ("flow" in row):
                client["valid_flow"].append(row["flow"])

        return client

    async def get_client_by_name(self, name: str, userid: str|int|None|NullType = None) -> List[OAuthClient]:
        async with self.engine.begin() as conn:
            ret = await self.get_client_in_transaction(conn, "client_name", name , userid)
            return ret

    async def get_clients(self, skip: Optional[int] = None, take: Optional[int] = None, userid: str|int|None|NullType = None) -> List[OAuthClient]:
        async with self.engine.begin() as conn:
            ret = await self.get_client_in_transaction(conn, None, None, userid, skip, take)
            return ret

    async def create_client(self, client: OAuthClient) -> OAuthClient:

        try:        
            for field in client:
                if (re.match(r'^[A-Za-z0-9_\.]+$', field) is None):
                    raise CrossauthError(ErrorCode.BadRequest, "Invalid client field name " + field)

            field_names : List[str] = []
            field_placeholders : List[str] = []
            field_values : Dict[str, Any] = {}
            
            for field in client:
                if (field != "redirect_uri" and field != "valid_flow"):
                    field_names.append(field)
                    field_placeholders.append(":"+field)
                    field_values[field] = client[field]

            if ("client_id" not in client):
                raise CrossauthError(ErrorCode.InvalidClientId, "CLient ID not given when creating client")
            client_id = client["client_id"]

            field_names_str = ", ".join(field_names)
            field_placeholders_str = ", ".join(field_placeholders)

            query = f"INSERT INTO {self.__client_table} ({field_names_str}) VALUES ({field_placeholders_str})"
            CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
            async with self.engine.begin() as conn:
                await conn.execute(text(query), field_values) 

                for uri in client["redirect_uri"]:
                    query = f"INSERT INTO {self.__redirect_uri_table} (client_id, uri) VALUES (:client_id, :uri)"
                    CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                    await conn.execute(text(query), {"client_id": client_id, "uri": uri}) 

                for flow in client["valid_flow"]:
                    query = f"INSERT INTO {self.__valid_flow_table} (client_id, flow) VALUES (:client_id, :flow)"
                    CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                    await conn.execute(text(query), {"client_id": client_id, "flow": flow}) 

            return await self.get_client_by_id(client_id)
                
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": ce}))
            print(e)
            raise ce

    async def update_client(self, client: PartialOAuthClient) -> None:

        try:
        
            for field in client:
                if (re.match(r'^[A-Za-z0-9_\.]+$', field) is None):
                    raise CrossauthError(ErrorCode.BadRequest, "Invalid user field name " + field)

            field_placeholders : List[str] = []
            field_values : Dict[str, Any] = {}
            if ("client_id" not in client):
                raise CrossauthError(ErrorCode.InvalidClientId, "Cannot update client without the client_id")
            client_id = client["client_id"]
            for field in client:
                if (field != "client_id" and field != "redirect_uri" and field != "valid_flow"):
                    field_placeholders.append(field + " = :"+field)
                    field_values[field] = client[field]
            field_placeholders_str = ", ".join(field_placeholders)
            field_values["client_id"] = client_id

            async with self.engine.begin() as conn:

                if (len(field_placeholders) > 0):
                    query = f"UPDATE {self.__client_table} SET {field_placeholders_str} WHERE client_id = :client_id"
                    CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                    await conn.execute(text(query), field_values) 
                
                # redirect_uris
                if ("redirect_uri" in client):
                    query = f"DELETE FROM {self.__redirect_uri_table} WHERE client_id = :client_id"
                    CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                    await conn.execute(text(query), {"client_id": client_id}) 
                    query = f"INSERT INTO {self.__redirect_uri_table} (client_id, uri) VALUES (:client_id, :uri)"
                    for uri in client["redirect_uri"]:
                        query = f"INSERT INTO {self.__redirect_uri_table} (client_id, uri) VALUES (:client_id, :uri)"
                        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                        await conn.execute(text(query), {"client_id": client_id, "uri": uri}) 

                # valid flows
                if ("valid_flow" in client):
                    query = f"DELETE FROM {self.__valid_flow_table} WHERE client_id = :client_id"
                    CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                    await conn.execute(text(query), {"client_id": client_id}) 
                    query = f"INSERT INTO {self.__valid_flow_table} (client_id, uri) VALUES (:client_id, :uri)"
                    for flow in client["valid_flow"]:
                        query = f"INSERT INTO {self.__valid_flow_table} (client_id, flow) VALUES (:client_id, :flow)"
                        CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                        await conn.execute(text(query), {"client_id": client_id, "flow": flow}) 

        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": ce}))
            raise ce


    async def delete_client(self, client_id: str) -> None:
            async with self.engine.begin() as conn:

                query = f"DELETE FROM {self.__client_table} WHERE client_id = :client_id"
                CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                await conn.execute(text(query), {"client_id": client_id}) 

                query = f"DELETE FROM {self.__redirect_uri_table} WHERE client_id = :client_id"
                CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                await conn.execute(text(query), {"client_id": client_id}) 

                query = f"DELETE FROM {self.__valid_flow_table} WHERE client_id = :client_id"
                CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                await conn.execute(text(query), {"client_id": client_id}) 

####################################
## OAuthAuthorizationStorage

class SqlAlchemyOAuthAuthorizationStorageOptions(OAuthAuthorizationStorageOptions, total=False):
    """
    Optional parameters for :class: SqlAlchemyUserStorage.

    See :func: SqlAlchemyUserStorage__init__ for details
    """

    azuthorization_table : str
    """ Name of client table.  Default `OAuthClient` """

    userid_foreign_key_column : str
    """Name of the user id column in the table. Default userid """

class SqlAlchemyOAuthAuthorizationStorage(OAuthAuthorizationStorage):


    def __init__(self, engine : AsyncEngine, options: SqlAlchemyOAuthAuthorizationStorageOptions = {}):
        self.engine = engine
        self.__authorization_table = "OAuthAuthorization"
        self.__userid_foreign_key_column = "userid"
        set_parameter("authorization_table", ParamType.String, self, options, "OAUTH_AUTHORIZATION_TABLE")
        set_parameter("userid_foreign_key_column", ParamType.String, self, options, "USER_ID_FOREIGN_KEY_COLUMN")

        self.__joins : List[str] = []
        set_parameter("joins", ParamType.JsonArray, self, options, "USER_TABLE_JOINS")

        if (re.match(r'^[A-Za-z0-9_]+$', self.__authorization_table) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid oauth authorization table name " + self.__authorization_table)
        if (re.match(r'^[A-Za-z0-9_]+$', self.__userid_foreign_key_column) == None):
            raise CrossauthError(ErrorCode.Configuration, "Invalid userid foreiggn key column " + self.__userid_foreign_key_column)

    async def get_authorizations(self, client_id: str, userid: str|int|None = None) -> List[Optional[str]]:

        try :
            return_values: List[Optional[str]] = []
            query: str = f"SELECT scope FROM {self.__authorization_table} WHERE client_id = :client_id"
            values : dict[str,Any] = {"client_id": client_id}
            if userid:
                query += f" AND {self.__userid_foreign_key_column} = :{self.__userid_foreign_key_column}"
                values[self.__userid_foreign_key_column] = userid
            else:
                query += f" AND {self.__userid_foreign_key_column} is NULL"

            CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
            async with self.engine.begin() as conn:
                res = await conn.execute(text(query), values) 

                for row in res.mappings():
                    return_values.append(row["scope"])

            return return_values
        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": ce}))
            raise ce

    
    
    async def update_authorizations(self, client_id: str, userid: str|int|None, authorizations: List[str|None]) -> None:
        try :
            query: str = f"DELETE FROM {self.__authorization_table} WHERE client_id = :client_id"
            values : dict[str,Any] = {"client_id": client_id}
            if userid:
                query += f" AND {self.__userid_foreign_key_column} = :{self.__userid_foreign_key_column}"
                values[self.__userid_foreign_key_column] = userid
            else:
                query += f" AND {self.__userid_foreign_key_column} IS NULL"

            async with self.engine.begin() as conn:
                CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                await conn.execute(text(query), values) 

                for scope in authorizations:
                    if (userid != Null):
                        query: str = f"INSERT INTO {self.__authorization_table} (client_id, scope, userid) VALUES (:client_id, :scope, :userid)"
                        values : dict[str,Any] = {"client_id": client_id, "scope": scope, "userid": userid}
                    else:
                        query: str = f"INSERT INTO {self.__authorization_table} (client_id, scope) VALUES (:client_id, :scope)"
                        values : dict[str,Any] = {"client_id": client_id, "scope": scope}

                    CrossauthLogger.logger().debug(j({"msg": "Executing query", "query": query}))
                    await conn.execute(text(query), values) 

        except Exception as e:
            ce = CrossauthError.as_crossauth_error(e)
            CrossauthLogger.logger().debug(j({"err": ce}))
            raise ce
    
#########################
## SQLite adapters

def adapt_date_iso_real(val : datetime): 
    """Adapt datetime.date to ISO 8601 date."""
    return val.isoformat() 

def adapt_datetime_iso_real(val : datetime): #
    """Adapt datetime.datetime to timezone-naive ISO 8601 date."""
    return val.isoformat() #

def adapt_datetime_epoch_real(val : datetime): 
    """Adapt datetime.datetime to Unix timestamp."""
    return val.timestamp() 

def convert_date_real(val : str|bytes):
    """Convert ISO 8601 date to datetime.date object."""
    if (type(val) == str):
        return datetime.fromisoformat(val) 
    return date.fromisoformat(val.decode()) # type: ignore

def convert_datetime_real(val: str|bytes): 
    """Convert ISO 8601 datetime to datetime.datetime object."""
    if (type(val) == str):
        return datetime.fromisoformat(val) 
    return datetime.fromisoformat(val.decode()) # type: ignore

def convert_timestamp_real(val : float): 
    """Convert Unix epoch timestamp to datetime.datetime object."""
    return datetime.fromtimestamp(val) 

def adapt_date_iso_int(val : datetime): 
    """Adapt datetime.date to ISO 8601 date."""
    return val.isoformat() 

def adapt_datetime_iso_int(val : datetime): 
    """Adapt datetime.datetime to timezone-naive ISO 8601 date."""
    return int(val.isoformat()) 

def adapt_datetime_epoch_int(val : datetime): 
    """Adapt datetime.datetime to Unix timestamp."""
    return val.timestamp() 

def convert_date_int(val : bytes|str): 
    """Convert ISO 8601 date to datetime.date object."""
    if (type(val) == str):
        return datetime.fromisoformat(val) 
    return date.fromisoformat(val.decode())  # type: ignore

def convert_datetime_int(val : bytes|str): 
    """Convert ISO 8601 datetime to datetime.datetime object."""
    if (type(val) == str):
        return datetime.fromisoformat(val) 
    return datetime.fromisoformat(val.decode())  # type: ignore

def convert_timestamp_int(val : int): 
    """Convert Unix epoch timestamp to datetime.datetime object."""
    return datetime.fromtimestamp(int(val)) 

def register_sqlite_datetime():
    """
    SQLite has no date column types.  As of Python 3.12, the default adapters
    which made this seamless don't work.

    If you don't have your own adapters and you want to store dates etc as
    real, call this function to register the ones supplied with Crossauth
    and declare your columns as date/datetime/timestamp as normal.
    """
    sqlite3.register_adapter(date, adapt_date_iso_real) # type: ignore
    sqlite3.register_adapter(datetime, adapt_datetime_iso_real) # type: ignore
    sqlite3.register_adapter(datetime, adapt_datetime_epoch_real) # type: ignore

    sqlite3.register_converter("date", convert_date_real) # type: ignore
    sqlite3.register_converter("datetime", convert_datetime_real) # type: ignore
    sqlite3.register_converter("timestamp", convert_timestamp_real) # type: ignore
