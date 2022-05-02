from scapy.all import sniff

class Sniffer:
    
    def __init__(self):
        self.__interface = None
        self.__timeout = None
        self.__monitor = False
        self.__stop_filter = None
        
        self.__captured_packets = None
    
    def sniff(self):
        self.__captured_packets = sniff(iface=self.__interface,
                               timeout=self.__timeout,
                               monitor=self.__monitor,
                               stop_filter=self.__stop_filter)
    
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