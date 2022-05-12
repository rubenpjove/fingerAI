from __future__ import annotations
from abc import ABC, abstractmethod

from scapy.plist import PacketList
from scapy.layers.all import IP, TCP
from ai_fingerprinting_tool.ui import Options
from ai_fingerprinting_tool.sniff import AbstractTrafficCapture, p0fTrafficCapture

class AbstractTrafficPreprocessor(ABC):
    
    @abstractmethod
    def preprocessTraffic(self,trafficCapture: AbstractTrafficCapture) -> None:
        pass
    
    @abstractmethod
    def getPreprocessedTraffic(self) -> AbstractTrafficCapture:
        pass
    
    
class p0fTrafficPreprocessor(AbstractTrafficPreprocessor):
    
    def __init__(self,options:Options):
        self.__options = options
        pass
    
    def preprocessTraffic(self, trafficCapture: AbstractTrafficCapture):
        result = []
        
        target = self.__options.getTarget()
        
        packets = trafficCapture.getPacketList()
        
        for packet in packets:
            if (
                packet != None and 
                packet.haslayer(IP) and 
                packet.haslayer(TCP)
                ):
                if (
                    packet[TCP].flags == 'S' and
                    packet[IP].src == target
                    ):
                    result.append(packet)
                elif (
                    packet[TCP].flags == 'SA' and
                    packet[IP].src == target
                ):
                    result.append(packet)
        
        self.__preprocessedTraffic = PacketList(result)

    def getPreprocessedTraffic(self):
        return p0fTrafficCapture(self.__preprocessedTraffic)

################################################################################

class AbstractSignatureGenerator(ABC):
    
    @abstractmethod
    def generateSignature(self, TrafficCapture: AbstractTrafficCapture) -> None:
        pass
    
    @abstractmethod
    def getSignature(self) -> AbstractSignature:
        pass

    
class p0fSignatureGenerator(AbstractSignatureGenerator):
    
    def __init__(self):
        pass

    def generateSignature(self, trafficCapture: AbstractTrafficCapture):
        packets = trafficCapture.getPacketList()
        
        if len(packets) == 0:
            raise Exception('No packets available')
        
        packet = packets[0]
        
        if not packet.haslayer(TCP):
            raise Exception("No TCP packet")
        
        tcpPacket = packet[TCP]
        tcpOptions = dict(packet[TCP].options)
        
        signature = {
            'sig_direction': None,
            'initial_ttl': None,
            'mss': '*',
            'window_size': None,
            'window_scaling': None,
            'tcp_options': None,
            'quirk_df': 0,
            'quirk_id': 0,
            'quirk_ts': 0
        }
        
        # Signature Direction
        if (
            tcpPacket.flags == 'S'
            ):
            signature['sig_direction'] = 'request'
        elif (
            tcpPacket.flags == 'SA'
        ):
            signature['sig_direction'] = 'response'
            
        # Initial TTL
        signature['initial_ttl'] = packet[IP].ttl
        
        # MSS
        if 'MSS' in tcpOptions:
            signature['mss'] = tcpOptions['MSS']
            
        # Window Size
        signature['window_size'] = tcpPacket.window
        
        # Windows Scaling
        if 'WScale' in tcpOptions:
            signature['window_scaling'] = tcpOptions['WScale']
            
        # TCP Options
        signature['tcp_options'] = tcpOptions.keys()
        
        # Quirks
        #   DF
        if packet[IP].flags.value == 2:
            signature['quirk_df'] = 1
        #   ID
        if (
            signature['quirk_df'] == 1 and
            packet[IP].id != 0
        ):
            signature['quirk_id'] = 1
        #   TS
        if (
            'Timestamp' in tcpOptions and
            tcpOptions['Timestamp'][0] == 0
        ):
            signature['quirk_ts'] = 1
        
        self.__signature = signature
        
    def getSignature(self):
        return p0fSignature(self.__signature)
        
    
        
################################################################################

class AbstractSignature(ABC):
    
    @abstractmethod
    def addFeature(self, key, value) -> None:
        pass
    
    @abstractmethod
    def getDict(self) -> dict:
        pass
    
    @abstractmethod
    def getList(self) -> list:
        pass
    

class p0fSignature(AbstractSignature):
    
    def __init__(self):
        self.__signature = {}
    
    def __init__(self,signature: dict):
        self.__signature = signature
        
    def addFeature(self,key,value) -> None:
        self.__signature[key] = value
    
    def getDict(self):
        return self.__signature
    
    def getList(self):
        return [
            self.__signature['sig_direction'],
            self.__signature['initial_ttl'],
            self.__signature['mss'],
            self.__signature['window_size'],
            self.__signature['window_scaling'],
            self.__signature['tcp_options'],
            self.__signature['quirk_df'],
            self.__signature['quirk_id'],
            self.__signature['quirk_ts']
        ]