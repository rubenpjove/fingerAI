from __future__ import annotations
from abc import ABC, abstractmethod
from ai_fingerprinting_tool.preprocess import AbstractSignature
from joblib import load

class AbstractClassificator(ABC):
    
    @abstractmethod
    def classify(self,signature) -> None:
        pass
    

class p0fClassificator(AbstractClassificator):
    
    def __init__(self):
        pass
    
    def classify(self, signature:AbstractSignature):
        # print(signature.getList())
        
        encoders = load('../persistance/encoders.joblib')

        return 'not implemented'