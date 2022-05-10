import argparse

class Options:
    
    def __init__(self):
        self.__parser = argparse.ArgumentParser(description='Fingerprinting tool based on artifial intelligence',
                                                prog='ai_fingerprinting_tool')
        self.__parser.add_argument('mode', choices=['active','passive'], nargs=1, help='mode of operation')
        self.__parser.add_argument('target', nargs=1, help='target of the scan')
        self.__parser.add_argument('-i', '--interface', nargs=1, help='interface to sniff')
        self.__parser.add_argument('-t', '--timeout', nargs=1, type=int, help='timeout for sniffing')
        
    def parseArguments(self):
        self.__args = self.__parser.parse_args()
        
    def getMode(self):
        return self.__args.mode[0]
    
    def getTarget(self):
        return self.__args.target[0]
    
    def getInterface(self):
        return self.__args.interface
    
    def getTimeout(self):
        return self.__args.timeout
        
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
        return self.__options
    
    def showResults(self):
        pass
        