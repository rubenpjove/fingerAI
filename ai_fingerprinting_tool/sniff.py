from __future__ import annotations
from abc import ABC, abstractmethod

import socket
from contextlib import closing
import random
from datetime import datetime
from numpy import sign

from scapy.all import sniff as scapy_sniff
from scapy.all import sr1 as scapy_sr
from scapy.plist import PacketList
from scapy.layers.all import IP, TCP
from ai_fingerprinting_tool.ui import Options
from ai_fingerprinting_tool.ui import UI

from scapy.layers.all import IP, TCP

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
        self.__verbose = options.getVerbose()
        self.__debug = options.getDebug()
        
        self.__captured_packets = None
        
        self.__prn_function = lambda pkt: "%s: %s" % (pkt.sniffed_on, pkt.summary())
        
        # self.__prn_function = lambda pkt: "%s: %s" % (pkt.sniffed_on, pkt.summary()) if ( (pkt != None and pkt.haslayer(IP) and pkt.haslayer(TCP)) and 
        #                                                                                 ( ('S' in pkt[TCP].flags and pkt[IP].src == self.__target) )) else None
    
    
    def sniff(self):
        ui = UI()
        
        ui.printVerbose("Sniffing network traffic... Press Ctrl+C to stop")
        
        if self.__mode == 'active':
            
            sport=0
            while sport == 0:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sport = random.randint(1024,65535)
                    if sock.connect_ex(('127.0.0.1', sport)) != 0:
                        sport = 0

            arguments = {'x' : IP(dst=self.__target)/TCP(sport=sport, dport=80,flags="S",options=[('MSS',1460),('SAckOK',''),('Timestamp',(int(datetime.timestamp(datetime.now())),0)),('NOP',0),('WScale',7)]),
                         'iface' : self.__interface,
                        'timeout' : self.__timeout,
                        'verbose' : self.__verbose}
            
            self.__captured_packets = scapy_sr(**arguments)
            
            
        elif self.__mode == 'passive':
            arguments = {'iface' : self.__interface,
                        'timeout' : self.__timeout,
                        'monitor' : self.__monitor,
                        'stop_filter' : self.__stop_filter}
                
            if self.__debug: 
                arguments.update({'prn' : self.__prn_function})
            
            self.__captured_packets = scapy_sniff(**arguments)
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