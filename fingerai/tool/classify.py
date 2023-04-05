from __future__ import annotations
from abc import ABC, abstractmethod
 

class AbstractClassificator(ABC):
    
    @abstractmethod
    def classify(self,signature) -> None:
        pass