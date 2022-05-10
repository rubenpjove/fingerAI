from __future__ import annotations
from abc import ABC, abstractmethod

from ai_fingerprinting_tool.ui import Options


class AbstractClassificator(ABC):
    
    @abstractmethod
    def classify(self,signature) -> None:
        pass
    

class p0fClassificator(AbstractClassificator):
    
    def __init__(self):
        pass
    
    def classify(self,signature):
        print(signature)
        return 'not implemented'