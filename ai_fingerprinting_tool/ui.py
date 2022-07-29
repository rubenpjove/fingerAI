import argparse
import os
import sys

class Options:
    
    def __init__(self):
        self.__parser = argparse.ArgumentParser(description='Fingerprinting tool based on artifial intelligence',
                                                prog='ai_fingerprinting_tool')
        self.__parser.add_argument('mode', choices=['active','passive'], help='mode of operation')
        self.__parser.add_argument('target', help='target of the scan')
        self.__parser.add_argument('-i', '--interface', help='interface to sniff')
        self.__parser.add_argument('-t', '--timeout', type=int, help='timeout for sniffing')
        self.__parser.add_argument('-v', '--verbose', action='store_true', default=False, help='print verbose messages')
        self.__parser.add_argument('-d', '--debug', action='store_true', default=False, help='print debug messages')
        
    def parseArguments(self):
        self.__args = self.__parser.parse_args()
        
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