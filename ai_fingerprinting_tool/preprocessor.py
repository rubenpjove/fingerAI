from scapy.all import Packet
from scapy.all import PacketList
from scapy.layers.all import IP, TCP
from ai_fingerprinting_tool.ui import Options

class TrafficPreprocessor:
    
    def __init__(self,options:Options):
        self.__options = options
        pass
    
    def processTraffic(self, packets):
        result = []
        
        target = self.__options.getTarget()
        
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
        
        return PacketList(result)


    
class SignatureGenerator:
    
    def __init__(self):
        pass

    def generateSignature(self, packets):
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
        
        self.__signature_dict = signature
        
    def getSignatureDict(self):
        return self.__signature_dict
    
    def getSignatureArray(self):
        return [
            self.__signature_dict['sig_direction'],
            self.__signature_dict['initial_ttl'],
            self.__signature_dict['mss'],
            self.__signature_dict['window_size'],
            self.__signature_dict['window_scaling'],
            self.__signature_dict['tcp_options'],
            self.__signature_dict['quirk_df'],
            self.__signature_dict['quirk_id'],
            self.__signature_dict['quirk_ts']
        ]