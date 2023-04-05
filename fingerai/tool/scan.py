from __future__ import annotations
from abc import ABC, abstractmethod
import importlib

from fingerai.tool.options import AbstractOptions
from fingerai.tool.sniff import AbstractSniffer
from fingerai.tool.preprocess import AbstractTrafficPreprocessor
from fingerai.tool.signature_generation import AbstractSignatureGenerator
from fingerai.tool.classify import AbstractClassificator


class ScanGenerator():
    
    def createScan(self,options):
        scanName = options.getScan()
        
        module = importlib.import_module("fingerai.tool.scanners"+"."+scanName)
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
