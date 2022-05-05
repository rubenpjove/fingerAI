from scapy.all import sniff as scapy_sniff
from scapy.all import sr as scapy_sr
from scapy.layers.all import IP, TCP
from ai_fingerprinting_tool.ui import Options

class Sniffer:
    
    def __init__(self,options:Options):
        self.__mode = options.getMode()
        
        self.__target = options.getTarget()
        self.__interface = options.getInterface()
        self.__timeout = options.getTimeout()
        self.__monitor = False
        self.__stop_filter = None
        
        self.__captured_packets = None
    
    def sniff(self):
        if self.__mode == 'active':
            self.__captured_packets,_ = scapy_sr(IP(dst=self.__target)/TCP(dport=80,flags="S"),
                                                timeout=self.__timeout)
            
        elif self.__mode == 'passive':
            self.__captured_packets = scapy_sniff(iface=self.__interface,
                                            timeout=self.__timeout,
                                            monitor=self.__monitor,
                                            stop_filter=self.__stop_filter)
            
        else:
            raise Exception('Unknown mode')
    
    def setTarget(self, target):
        self.__target = target
    
    def setInterface(self, interface):
        self.__interface = interface
        
    def setTimeout(self, timeout):
        self.__timeout = timeout
        
    def setMonitor(self, monitor):
        self.__monitor = monitor
        
    def setStopFilter(self, stop_filter):
        self.__stop_filter = stop_filter
    
    def getCapturedPackets(self):
        return self.__captured_packets