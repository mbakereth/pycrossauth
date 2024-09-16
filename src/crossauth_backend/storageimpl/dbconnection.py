# Copyright (c) 2024 Matthew Baker.  All rights reserved.  Licenced under the Apache Licence 2.0.  See LICENSE file
from abc import ABC, abstractmethod
from typing import List, Dict, Any, LiteralString, Mapping

class DbPool(ABC):
    def __init__(self):
        pass

    @abstractmethod
    async def connect(self) -> 'DbConnection':
        pass

    @abstractmethod
    def parameters(self) -> 'DbParameter':
        pass

class DbParameter(ABC):
    def __init__(self):
        pass

    @abstractmethod
    def next_parameter(self, value : Any) -> str:
        pass

    @abstractmethod
    def values(self) -> Mapping[str,Any]|List[Any]:
        pass

class DbConnection(ABC):
    @abstractmethod
    async def execute(self, select : bool, query: LiteralString, params: DbParameter|None) -> List[Dict[str, Any]]:
        pass

    @abstractmethod
    async def start_transaction(self) -> None:
        pass

    @abstractmethod
    async def commit(self) -> None:
        pass

    @abstractmethod
    async def rollback(self) -> None:
        pass

    @abstractmethod
    async def release(self) -> None:
        pass

