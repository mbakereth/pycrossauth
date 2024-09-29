# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from crossauth_backend.common.error import CrossauthError, ErrorCode

from typing import Any, Mapping, TypeVar, Generic, cast
from enum import Enum, auto
import os
import json
from nulltype import Null, NullType

class ParamType(Enum):
    """
    Type of parameter that can be parsed from an option value or 
    environment variable
    """

    String = auto()
    Number = auto()
    Boolean = auto()
    Json = auto()
    JsonArray = auto()

def get_option(param: str, options: Mapping[str, Any]) -> Any:
    parts = param.split(".")
    obj = options
    for part in parts:
        if part not in obj or obj[part] is None:
            return None
        obj = obj[part]
    return obj

def has_option(param: str, options: Mapping[str, Any]) -> bool:
    parts = param.split(".")
    obj = options
    for part in parts:
        if part not in obj or obj[part] is None:
            return False
        obj = obj[part]
    return True

def set_from_option(instance: Any, param: str, options: Mapping[str, Any], public : bool =False, protected : bool =False) -> None:
    value = get_option(param, options)
    param = attr_name(instance, param, public=public, protected=protected)
    setattr(instance, param, value)

def set_from_env(instance: Any, param: str, param_type: ParamType, name_in_env_file: str, public : bool = False, protected : bool =False) -> None:
    param = attr_name(instance, param.replace(".", "_"), public=public, protected=protected)

    env_value = os.environ.get(name_in_env_file)
    if (env_value is None): return

    if param_type == ParamType.String:
        setattr(instance, param, None if env_value == "null" else env_value)
    elif param_type == ParamType.Number:
        setattr(instance, param, None if env_value == "null" else float(env_value))
    elif param_type == ParamType.Boolean:
        setattr(instance, param, env_value.lower() in ["1", "true"] if env_value else False)
    elif param_type == ParamType.Json:
        setattr(instance, param, json.loads(env_value or "{}"))
    elif param_type == ParamType.JsonArray:
        setattr(instance, param, json.loads(env_value or "[]"))

def attr_name(instance : Any, param : str, public:bool=False, protected:bool=False):
    param = param.replace(".", "_")
    if (protected): 
        param = "_" + param
    elif (not public):
        param = "_" + instance.__class__.__name__ + "__" + param
    return param


def set_parameter(param: str,
                  param_type: ParamType,
                  instance: Any,
                  options: Mapping[str, Any],
                  env_name: str | None = None,
                  required: bool = False,
                  public : bool = False,
                  protected : bool = False) -> None:
    """
    Sets an instance variable in the passed object from the passed options
    object and environment variable.
    
    If the named parameter exists in the options object, then the instance
    variable is set to that value. Otherwise, if the named environment
    variable exists, it is set from that. Otherwise, the instance variable
    is not updated.
    
    :param str param: The name of the parameter in the options variable and the
            name of the variable in the instance.
    :param ParamType param_type: The type of variable. If the value is `JsonArray` or `Json`,
                both the option and the environment variable value should be a
                string, which will be parsed.
    :param Any instance: Options present in the `options` or environment variables
                will be set on a corresponding instance variable in this
                class or object.
    :param Dict[str, Any] options: Object containing options as key/value pairs.
    :param str env_name: Name of environment variable.
    :param bool required: If true, an exception will be thrown if the variable is 
                not present in `options` or the environment variable.
    :param bool public: If false, `_` will be prepended to the field nam,e
                in the target.  Default False.
    :param bool protected: If true, `__` will be prepended to the field nam,e
                in the target.  Default False.  Don't use this and `public` together.
    
    :raises: :class:`crossauth_backend.CrossauthError`: with :class:`ErrorCode` Configuration if `required`
                        is set but the option was not present, or if there was a parsing
                        error.
    """
    name_in_env_file = f"CROSSAUTH_{env_name}" if env_name else None
    
    if required and not has_option(param, options) and not (name_in_env_file and name_in_env_file in os.environ):
        raise CrossauthError(ErrorCode.Configuration, f"{param} is required")
    
    attr = attr_name(instance, param, public=public, protected=protected)
    if (not attr in instance.__dict__):
        raise CrossauthError(ErrorCode.Configuration, attr + " does not exist")

    if has_option(param, options):
        set_from_option(instance, param, options, public=public, protected=protected)
    elif env_name and name_in_env_file in os.environ and name_in_env_file is not None:
        set_from_env(instance, param, param_type, name_in_env_file, public=public, protected=protected)


T = TypeVar('T')

class MapGetter(Generic[T]):
        
    @classmethod
    def get_or_raise(cls, mapping : Mapping[str, Any], field : str) -> T:
        if (field not in mapping):
            raise CrossauthError(ErrorCode.ValueError, f"{field} is missing or wrong type")
        return cast(T, mapping[field])

    @classmethod
    def get_or_none(cls, mapping : Mapping[str, Any], field : str) -> T|None:
        if (field not in mapping):
            return None
        return cast(T, mapping[field])

    @classmethod
    def get(cls, mapping : Mapping[str, Any], field : str, default : T) -> T:
        if (field not in mapping):
            return default
        return cast(T, mapping[field])

    @classmethod
    def get_or_null(cls, mapping : Mapping[str, Any], field : str) -> T | NullType:
        if (field not in mapping):
            return Null
        return cast(T, mapping[field])
