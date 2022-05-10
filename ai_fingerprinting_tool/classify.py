from __future__ import annotations
from abc import ABC, abstractmethod
from ai_fingerprinting_tool.preprocess import AbstractSignature


class AbstractClassificator(ABC):
    
    @abstractmethod
    def classify(self,signature) -> None:
        pass
    

class p0fClassificator(AbstractClassificator):
    
    def __init__(self):
        pass
    
    def classify(self, signature:AbstractSignature):
        print(signature.getList())
        return 'not implemented'