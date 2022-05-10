from __future__ import annotations
from abc import ABC, abstractmethod

from ai_fingerprinting_tool.sniff import AbstractSniffer, p0fSniffer
from ai_fingerprinting_tool.preprocess import AbstractTrafficPreprocessor, AbstractSignatureGenerator, p0fTrafficPreprocessor, p0fSignatureGenerator
from ai_fingerprinting_tool.classify import AbstractClassificator, p0fClassificator


class AbstractScan(ABC):
    @abstractmethod
    def createSniffer(self) -> AbstractSniffer:
        pass

    @abstractmethod
    def createTrafficPreprocessor(self) -> AbstractTrafficPreprocessor:
        pass
    
    @abstractmethod
    def createSignatureGenerator(self) -> AbstractSignatureGenerator:
        pass
    
    @abstractmethod
    def createClassificator(self) -> AbstractClassificator:
        pass


class p0fScan(AbstractScan):

    def createSniffer(self,options) -> AbstractSniffer:
        return p0fSniffer(options)

    def createTrafficPreprocessor(self,options) -> AbstractTrafficPreprocessor:
        return p0fTrafficPreprocessor(options)
    
    def createSignatureGenerator(self) -> AbstractSignatureGenerator:
        return p0fSignatureGenerator()
    
    def createClassificator(self) -> AbstractClassificator:
        return p0fClassificator()