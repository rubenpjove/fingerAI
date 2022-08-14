from __future__ import annotations
from abc import ABC, abstractmethod

from ai_fingerprinting_tool.sniff import AbstractTrafficCapture


class AbstractSignature(ABC):
    
    @abstractmethod
    def addFeature(self, key, value) -> None:
        pass
    
    @abstractmethod
    def getDict(self) -> dict:
        pass
    
    @abstractmethod
    def getList(self) -> list:
        pass
    
    @abstractmethod
    def getDataFrame(self) -> list:
        pass


class AbstractSignatureGenerator(ABC):
    
    @abstractmethod
    def generateSignature(self, TrafficCapture: AbstractTrafficCapture) -> None:
        pass
    
    @abstractmethod
    def getSignature(self) -> AbstractSignature:
        pass