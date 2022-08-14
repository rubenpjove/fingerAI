from __future__ import annotations
import os
import json
import sys

from ai_fingerprinting_tool.options import Options


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