import argparse

class UI:
    
    def __init__(self):
        self.__parser = argparse.ArgumentParser(description='Fingerprinting tool based on Artifial Intelligence')
        self.__parser.add_argument('mode', choices=['active','passive'], nargs=1, help='mode of operation')
        self.__parser.add_argument('-i', '--interface', nargs=1, help='interface to sniff')
        self.__parser.add_argument('-t', '--timeout', nargs=1, type=int, help='timeout for sniffing')
    
    def parseOptions(self):
        self.args = self.__parser.parse_args()