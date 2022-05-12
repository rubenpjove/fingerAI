from __future__ import annotations
from abc import ABC, abstractmethod

import signal
from numpy import sign

from scapy.all import sniff as scapy_sniff
from scapy.all import sr as scapy_sr
from scapy.plist import PacketList
from scapy.layers.all import IP, TCP
from ai_fingerprinting_tool.ui import Options


class AbstractSniffer(ABC):
    
    @abstractmethod
    def sniff(self) -> None:
        pass
    
    @abstractmethod
    def getCapturedPackets(self) -> AbstractTrafficCapture:
        pass

class p0fSniffer(AbstractSniffer):
    
    def __init__(self,options:Options):
        self.__mode = options.getMode()
        
        self.__target = options.getTarget()
        self.__interface = options.getInterface()
        self.__timeout = options.getTimeout()
        self.__monitor = False
        self.__stop_filter = None
        
        self.__captured_packets = None
    
    # def __signal_handler(sig, frame):
    #     res = input("trl+C fue presionado. Estas seguro de que quieres parar de capturar paquetes de red? [s]:")
    #     if res == 's':
    #         raise KeyboardInterrupt
    
    def sniff(self):
        # signal.signal(signal.SIGINT, p0fSniffer.__signal_handler)
        
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
    
    def getCapturedPackets(self):
        return p0fTrafficCapture(self.__captured_packets)
    
#################################################################################

class AbstractTrafficCapture(ABC):
    
    @abstractmethod
    def getPacketList(self) -> PacketList:
        pass
    

class p0fTrafficCapture(AbstractTrafficCapture):
    
    def __init__(self,packets: PacketList):
        self.__packets = packets
        
    def getPacketList(self):
        return self.__packets