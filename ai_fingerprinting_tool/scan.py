from __future__ import annotations
from abc import ABC, abstractmethod
import importlib

from ai_fingerprinting_tool.ui import AbstractOptions, p0fOptions
from ai_fingerprinting_tool.sniff import AbstractTrafficCapture, p0fTrafficCapture
from ai_fingerprinting_tool.sniff import AbstractSniffer, p0fSniffer
from ai_fingerprinting_tool.preprocess import AbstractTrafficPreprocessor, p0fTrafficPreprocessor
from ai_fingerprinting_tool.preprocess import AbstractSignatureGenerator, p0fSignatureGenerator
from ai_fingerprinting_tool.preprocess import AbstractSignature, p0fSignature
from ai_fingerprinting_tool.classify import AbstractClassificator, p0fClassificator

class ScanGenerator():
    
    def createScan(self,options):
        scanName = options.getScan()
        
        module = importlib.import_module("ai_fingerprinting_tool.scan")
        class_ = getattr(module, scanName+"Scan")
        scanInstance = class_()
        
        options2 = scanInstance.createOptions(options)
        
        return scanInstance, options2

class AbstractScan(ABC):
    
    @abstractmethod
    def createOptions(self,options) -> AbstractOptions:
        pass
    
    @abstractmethod
    def createSniffer(self,options) -> AbstractSniffer:
        pass

    @abstractmethod
    def createTrafficPreprocessor(self,options) -> AbstractTrafficPreprocessor:
        pass
    
    @abstractmethod
    def createSignatureGenerator(self) -> AbstractSignatureGenerator:
        pass
    
    @abstractmethod
    def createClassificator(self) -> AbstractClassificator:
        pass


class p0fScan(AbstractScan):
    
    def createOptions(self,options) -> AbstractOptions:
        return p0fOptions(options.getArgs())
    
    def createSniffer(self,options) -> AbstractSniffer:
        return p0fSniffer(options)

    def createTrafficPreprocessor(self,options) -> AbstractTrafficPreprocessor:
        return p0fTrafficPreprocessor(options)
    
    def createSignatureGenerator(self) -> AbstractSignatureGenerator:
        return p0fSignatureGenerator()
    
    def createClassificator(self) -> AbstractClassificator:
        return p0fClassificator()