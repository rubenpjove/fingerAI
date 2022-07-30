from __future__ import annotations
from abc import ABC, abstractmethod
import argparse
import os
import sys

class Options:
    
    def __init__(self):

        self.__parser = argparse.ArgumentParser(description='Fingerprinting tool based on artifial intelligence',
                                                prog='ai_fingerprinting_tool',
                                                epilog="See '<command> --help' to read about a specific sub-command.")
        self.__parser.add_argument('-v', '--verbose', action='store_true', default=False, help='print verbose messages')
        self.__parser.add_argument('-d', '--debug', action='store_true', default=False, help='print debug messages')
        
        subparsers = self.__parser.add_subparsers(dest='command', help='Scans available')
        
        p0fparser = p0fSpecificParser()
        p0fparser.createSpecificParser(subparsers)
        
    def parseArguments(self):
        self.__args = self.__parser.parse_args()
        if self.__args.command is not None:
            print(self.__args)
        else:
            self.__parser.print_help()
            sys.exit()
        
    def getMode(self):
        return self.__args.mode
    
    def getTarget(self):
        return self.__args.target
    
    def getInterface(self):
        return self.__args.interface

    def getTimeout(self):
        return self.__args.timeout
    
    def getVerbose(self):
        return self.__args.verbose or self.__args.debug
    
    def getDebug(self):
        return self.__args.debug
    
class AbstractSpecificOptions(ABC):
    
    @abstractmethod
    def createSpecificParser(self) -> None:
        pass

class p0fSpecificParser(AbstractSpecificOptions,Options):
    
    def createSpecificParser(self,subparsers) -> None:
        p0fparser = subparsers.add_parser('p0f', help='Based on p0f database')
        
        p0fparser.add_argument('-i', '--interface', help='interface to sniff')
        p0fparser.add_argument('-t', '--timeout', type=int, help='timeout for sniffing')
        
        subparsers2 = p0fparser.add_subparsers(dest='mode', help='Scans available')
        activeparser = subparsers2.add_parser('active', help='Active scan')
        activeparser.add_argument('-p', '--port', type=int, default=80)
        activeparser.add_argument('target', help='target of the scan')
        
        passiveparser = subparsers2.add_parser('passive', help='Passive scan')
        passiveparser.add_argument('target', help='target of the scan')
        
        
        
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
    
    def printMessage(self,message):
        print(message)
    
    def printVerbose(self,message):
        if self.__options.getVerbose() is True or self.__options.getDebug() is True:
            print(message)
    
    def printDebug(self,message):
        if self.__options.getDebug() is True:
            print(message)
    
    def showResults(self,result):
        print('Results:')
        print('\tTarget: {} -> OS: {}'.format(self.__options.getTarget(),result[0]))