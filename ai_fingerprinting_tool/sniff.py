from __future__ import annotations
from abc import ABC, abstractmethod

from scapy.plist import PacketList


class AbstractSniffer(ABC):
    
    @abstractmethod
    def sniff(self) -> None:
        pass
    
    @abstractmethod
    def getCapturedPackets(self) -> AbstractTrafficCapture:
        pass
    
#################################################################################


class AbstractTrafficCapture(ABC):
    
    @abstractmethod
    def getPacketList(self) -> PacketList:
        pass