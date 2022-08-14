from __future__ import annotations
from abc import ABC, abstractmethod

from ai_fingerprinting_tool.sniff import AbstractTrafficCapture


class AbstractTrafficPreprocessor(ABC):
    
    @abstractmethod
    def preprocessTraffic(self,trafficCapture: AbstractTrafficCapture) -> None:
        pass
    
    @abstractmethod
    def getPreprocessedTraffic(self) -> AbstractTrafficCapture:
        pass
