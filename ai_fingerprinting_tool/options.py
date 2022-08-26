from abc import ABC, abstractmethod
import argparse
import importlib

from ai_fingerprinting_tool.constants import SCANS


class Options():
    
    def __init__(self):
        self.__parser = argparse.ArgumentParser(description='Fingerprinting tool based on artifial intelligence',
                                                prog='ai_fingerprinting_tool')
        self.__parser.add_argument('-v', '--verbose', action='store_true', default=False, help='print verbose messages')
        self.__parser.add_argument('-d', '--debug', action='store_true', default=False, help='print debug messages')
        self.__parser.add_argument('-q', '--quiet', action='store_true', default=False, help='do not print any messages to stdout')
        self.__parser.add_argument('-o', '--outputFormat', choices=['normal','json','grep'], default='normal', required=False, help='output format')
        self.__parser.add_argument('-oF', '--outputFile', required=False, help='output file')
        
        self.__parser.add_argument('scan', choices=SCANS, help='type of scan')
        
        for scanName in SCANS:
            module = importlib.import_module("ai_fingerprinting_tool.scanners."+scanName)
            class_ = getattr(module, scanName+"SpecificParser")
            scanInstance = class_()
            scanInstance.createSpecificParser(self.__parser)
    
    def parseArguments(self, externalArgs=None):
        if externalArgs is not None:
            self.args = self.__parser.parse_args(externalArgs)
        else:
            self.args = self.__parser.parse_args()
    
    def getArgs(self):
        return self.args
    
    def getScan(self):
        return self.args.scan
    
    def getVerbose(self):
        return ( self.args.verbose or self.args.debug ) and not self.args.quiet
    
    def getDebug(self):
        return self.args.debug and not self.args.quiet
    
    def getQuiet(self):
        return self.args.quiet
    
    def getOutputFormat(self):
        return self.args.outputFormat
    
    def getOutputFile(self):
        return self.args.outputFile
    
################################################################################


class AbstractOptions(ABC):
    pass
    
################################################################################


class AbstractSpecificParser(ABC):
    
    @abstractmethod
    def createSpecificParser(self) -> None:
        pass
        
################################################################################