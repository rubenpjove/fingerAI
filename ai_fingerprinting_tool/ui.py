from __future__ import annotations
from abc import ABC, abstractmethod
import argparse
import os
import importlib
import json
import sys
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
            module = importlib.import_module("ai_fingerprinting_tool.ui")
            class_ = getattr(module, scanName+"SpecificParser")
            scanInstance = class_()
            scanInstance.createSpecificParser(self.__parser)
        
    def parseArguments(self):
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

class p0fOptions(Options,AbstractOptions):
    
    def __init__(self,args):
        self.args = args
    
    def getMode(self):
        return self.args.mode
    
    def getTarget(self):
        return self.args.target
    
    def getInterface(self):
        return self.args.interface

    def getTimeout(self):
        return self.args.timeout
    
    def getPort(self):
        return self.args.port
    
    def getInputFile(self):
        return self.args.inputFile
    
    def getp0fToolResult(self):
        return self.args.p0fToolResult
    
    
################################################################################

class AbstractSpecificParser(ABC):
    
    @abstractmethod
    def createSpecificParser(self) -> None:
        pass
    
class p0fSpecificParser(AbstractSpecificParser):
    
    def createSpecificParser(self,parser) -> None:
        parser.add_argument('mode', choices=['active','passive'], help='mode of operation')
        parser.add_argument('target', help='target of the scan')
        parser.add_argument('-p', '--port', type=int, default=80, help='port to scan (active mode)')
        parser.add_argument('-i', '--interface', help='interface to sniff')
        parser.add_argument('-t', '--timeout', type=int, help='timeout for sniffing')
        parser.add_argument('-iF', '--inputFile', required=False, help='PCAP input file')
        parser.add_argument('-p0f', '--p0fToolResult', action='store_true', default=False, help='prints also the result from the original p0f tool')
        
################################################################################

class SingletonUI(type):

    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]

class UI(metaclass=SingletonUI):
    
    def __init__(self):
        self.__options = Options()
    
    def parseOptions(self):
        self.__options.parseArguments()
        
        if os.getuid() != 0:
            sys.exit('You must be root to run this program (UID: {})'.format(os.getuid()))
        
        return self.__options
    
    def updateOptions(self,options):
        self.__options = options
        
    def getOptions(self):
        return self.__options
    
    def printMessage(self,message):
        if not self.__options.getQuiet():
            print(message)
    
    def printVerbose(self,message):
        if not self.__options.getQuiet() and ( self.__options.getVerbose() or self.__options.getDebug() ):
            print(message)
    
    def printDebug(self,message):
        if not self.__options.getQuiet() and (self.__options.getDebug()):
            print(message)
    
    def showResults(self,inResult):
        self.printVerbose('--- Results ---')
        
        if self.__options.getOutputFormat() == 'json':
            resultDict = {self.__options.getTarget():inResult[0]}
            result = json.dumps(resultDict)
            
        elif self.__options.getOutputFormat() == 'grep':
            result = '{}\t{}'.format(self.__options.getTarget(),inResult[0])
            
        else :
            result = '{} -> {}'.format(self.__options.getTarget(),inResult[0])
            
        self.printMessage(result)
        
        if self.__options.getOutputFile():
            with open(self.__options.getOutputFile(), 'a') as f:
                f.write(result + '\n')