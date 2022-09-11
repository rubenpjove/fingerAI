from __future__ import annotations

from ai_fingerprinting_tool.ui import UI, AbstractResult, Options

from ai_fingerprinting_tool.sniff import AbstractTrafficCapture
from ai_fingerprinting_tool.signature_generation import AbstractSignature

import ai_fingerprinting_tool.conf as conf

from scapy.plist import PacketList
from scapy.layers.all import IP, TCP

################################################################################

from ai_fingerprinting_tool.scan import AbstractScan

from ai_fingerprinting_tool.options import AbstractOptions
from ai_fingerprinting_tool.sniff import AbstractSniffer
from ai_fingerprinting_tool.preprocess import AbstractTrafficPreprocessor
from ai_fingerprinting_tool.signature_generation import AbstractSignatureGenerator
from ai_fingerprinting_tool.classify import AbstractClassificator


class nmapScan(AbstractScan):
    
    def createOptions(self,options) -> AbstractOptions:
        return nmapOptions(options.getArgs())
    
    def createSniffer(self,options) -> AbstractSniffer:
        return nmapSniffer(options)

    def createTrafficPreprocessor(self,options) -> AbstractTrafficPreprocessor:
        return nmapTrafficPreprocessor(options)
    
    def createSignatureGenerator(self) -> AbstractSignatureGenerator:
        return nmapSignatureGenerator()
    
    def createClassificator(self) -> AbstractClassificator:
        return nmapClassificator()
    
################################################################################

from ai_fingerprinting_tool.options import AbstractSpecificParser


class nmapOptions(Options,AbstractOptions):
    
    def __init__(self,args):
        AbstractOptions.__init__(self,args)


class nmapSpecificParser(AbstractSpecificParser):
    
    def createSpecificParser(self,parser) -> None:
        pass
           
################################################################################

import socket
from contextlib import closing
import random
from datetime import datetime
from scapy.all import sniff as scapy_sniff
from scapy.all import sr1 as scapy_sr


class nmapSniffer(AbstractSniffer):
    
    def __init__(self,options):
        self.__mode = options.getMode()
        
        self.__target = options.getTarget()
        self.__interface = options.getInterface()
        self.__timeout = options.getTimeout()
        self.__monitor = True
        self.__stop_filter = lambda pkt: True if ( (pkt != None and pkt.haslayer(IP) and pkt.haslayer(TCP)) and ( ('S' in pkt[TCP].flags and 'A' in pkt[TCP].flags and pkt[IP].src == self.__target) )) else False
        self.__verbose = options.getVerbose()
        self.__debug = options.getDebug()
        self.__port = options.getPort()
        self.__inputFile = options.getInputFile()
        
        self.__captured_packets = None
        
        self.__prn_function = lambda pkt: "%s: %s" % (pkt.sniffed_on, pkt.summary()) if ( (pkt != None and pkt.haslayer(IP) and pkt.haslayer(TCP)) and 
                                                                                     ( ('S' in pkt[TCP].flags and 'A' in pkt[TCP].flags and pkt[IP].src == self.__target) )) else None
    
    
    def sniff(self):
        ui = UI()
        
        if self.__mode == 'active':
            
            sport=0
            while sport == 0:
                with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                    sport = random.randint(1024,65535)
                    if sock.connect_ex(('127.0.0.1', sport)) != 0:
                        sport = 0

            arguments = {'x' : IP(dst=self.__target)/TCP(sport=sport, dport=self.__port,flags="S",options=[('MSS',1460),('SAckOK',''),('Timestamp',(int(datetime.timestamp(datetime.now())),0)),('NOP',0),('WScale',7)]),
                         'iface' : self.__interface,
                        'timeout' : self.__timeout,
                        'verbose' : self.__debug}
            
            ui.printVerbose("Sending probes for active scan... Press Ctrl+C to abort\n")
            
            self.__captured_packets = scapy_sr(**arguments)
            
            if (not self.__stop_filter(self.__captured_packets)):
                ui.printMessage("\nProbes unsuccessfully responded, aborting the scan...")
                sys.exit(1)
                
            ui.printDebug('\nSuitable traffic sniffed:\n%s\n' % self.__captured_packets.summary())
            
            ui.printVerbose("Probes successfully responded, generating traffic signature...\n")
            
            
        elif self.__mode == 'passive':
            
            arguments = {'stop_filter' : self.__stop_filter}
            
            if self.__debug:
                    arguments.update({'prn' : self.__prn_function})
            
            if self.__inputFile:
                
                ui.printVerbose("Reading packets from PCAP file... This process will stop automatically when suitable traffic is found... Press Ctrl+C to abort\n")
                
                ui.printDebug("Suitable traffic sniffed:")
                    
                self.__captured_packets = scapy_sniff(offline=self.__inputFile, **arguments)
                
            else: 
                
                arguments.update({'iface' : self.__interface,
                                    'timeout' : self.__timeout,
                                    'monitor' : self.__monitor})
                
                ui.printVerbose("Sniffing network traffic... This process will stop automatically when suitable traffic is found... Press Ctrl+C to abort\n")
                
                ui.printDebug("Suitable traffic sniffed:")
                
                self.__captured_packets = scapy_sniff(**arguments)
                
            
            ui.printDebug("")        
                
            ui.printVerbose("Suitable traffic found, generating its signature...\n")
            
        else:
            raise Exception('Unknown mode')
    
    def getCapturedPackets(self):
        return nmapTrafficCapture(self.__captured_packets)


class nmapTrafficCapture(AbstractTrafficCapture):
    
    def __init__(self,packets: PacketList):
        self.__packets = packets
        
    def getPacketList(self):
        return self.__packets

################################################################################


class nmapTrafficPreprocessor(AbstractTrafficPreprocessor):
    
    def __init__(self,options:Options):
        self.__target = options.getTarget()
        pass
    
    def preprocessTraffic(self, trafficCapture: AbstractTrafficCapture):
        result = []
        
        target = self.__target
        
        packets = trafficCapture.getPacketList()
        
        if packets is None:
            print('No packets captured')
            sys.exit(1)
        
        for packet in packets:
            if (
                packet != None and 
                packet.haslayer(IP) and 
                packet.haslayer(TCP)
                ):
                if (
                    'S' in packet[TCP].flags and
                    'A' in packet[TCP].flags and
                    packet[IP].src == target
                ):
                    result.append(packet)
        
        self.__preprocessedTraffic = PacketList(result)

    def getPreprocessedTraffic(self):
        return nmapTrafficCapture(self.__preprocessedTraffic)

################################################################################

import pandas as pd
import sys


class nmapSignatureGenerator(AbstractSignatureGenerator):
    
    def __init__(self):
        pass

    def generateSignature(self, trafficCapture: AbstractTrafficCapture):
        packets = trafficCapture.getPacketList()
        
        if len(packets) == 0:
            print('No packets captured')
            sys.exit(1)
        
        packet = packets[0]
        
        ui = UI()
        ui.printDebug('Generating signature for packet:\n%s' % packet.show(dump=True))
        
        if not packet.haslayer(TCP):
            raise Exception("No TCP packet")
        
        tcpPacket = packet[TCP]
        tcpOptions = dict(packet[TCP].options)
        
        signature = {
            'initial_ttl': '*',
            'mss': '*',
            'window_size': '*',
            'window_scaling': '*',
            'tcp_options': '',
            'quirk_df': 0,
            'quirk_ts': 0
        }
            
        # Initial TTL
        signature['initial_ttl'] = str(packet[IP].ttl)
        
        # MSS
        if 'MSS' in tcpOptions:
            signature['mss'] = str(tcpOptions['MSS'])
            
        # Window Size
        signature['window_size'] = str(tcpPacket.window)
        
        # Windows Scaling
        if 'WScale' in tcpOptions:
            signature['window_scaling'] = str(tcpOptions['WScale'])
            
        # TCP Options
        tcpOptionsResult = []
        for k in tcpOptions:
            if k == 'MSS':
                tcpOptionsResult.append('mss')
            elif k == 'NOP':
                tcpOptionsResult.append('nop')
            elif k == 'Timestamp':
                tcpOptionsResult.append('ts')
            elif k == 'WScale':
                tcpOptionsResult.append('ws')
            elif k == 'SAckOK':
                tcpOptionsResult.append('sok')
            elif k == 'EOL':
                tcpOptionsResult.append('eol')
            else:
                tcpOptionsResult.append('*')
        
        signature['tcp_options'] = ','.join(tcpOptionsResult)
        
        # Quirks
        #   DF
        if packet[IP].flags.value == 2:
            signature['quirk_df'] = 1
        #   TS
        if (
            'Timestamp' in tcpOptions and
            tcpOptions['Timestamp'][0] == 0
        ):
            signature['quirk_ts'] = 1
        
        self.__signature = signature
        
    def getSignature(self):
        return nmapSignature(self.__signature)
        
################################################################################


class nmapSignature(AbstractSignature):
    
    def __init__(self):
        self.__signature = {}
        self.__signature['os'] = '*'
    
    def __init__(self,signature: dict):
        self.__signature = signature
        self.__signature['os'] = '*'
        
    def addFeature(self,key,value) -> None:
        self.__signature[key] = value
    
    def getDict(self):
        return self.__signature
    
    def getList(self):
        return [
            self.__signature['initial_ttl'],
            self.__signature['mss'],
            self.__signature['window_size'],
            self.__signature['window_scaling'],
            self.__signature['tcp_options'],
            self.__signature['quirk_df'],
            self.__signature['quirk_ts']
        ]
        
    def getDataFrame(self):
        result = pd.DataFrame(self.__signature, index=[0])
        result.reset_index(inplace=True, drop=True)
        return result


################################################################################

from joblib import load
import pandas as pd
# from ai_model_creation.ai_nmap_model_creation.transformers import *
import warnings
import os

class nmapClassificator(AbstractClassificator):
    
    def __init__(self):
        pass
    
    def classify(self, signature:AbstractSignature):
        ui = UI()
        
        warnings.filterwarnings("ignore")
        
        encoders = load(conf.nmap_ENCODERS)
        
        df_signature = signature.getDataFrame()
        
        ui.printDebug("Signature to be analyzed:")
        ui.printDebug(df_signature.to_string(index=False))
        ui.printDebug("")
        
        transformed_signature = encoders.transform(df_signature)
        transformed_signature = pd.DataFrame(
            transformed_signature,
            columns=encoders.get_feature_names_out()
        )

        classifier = load(conf.nmap_CLASSIFIER)
        
        Xdata = transformed_signature.drop(['os'],axis = 1).values
        
        guessOS = classifier.predict(Xdata)
        
        ui = UI()
        result = nmapResult(ui.getOptions().getTarget(),guessOS[0])
        
        return result


class nmapResult(AbstractResult):
    
    def __init__(self,target,os):
        self.__result = {'os': os,
                         'target': target}
    
    def setTarget(self, target: str):
        self.__result['target'] = target
        
    def setOS(self, os: str):
        self.__result['os'] = os
    
    def getTarget(self):
        return self.__result['target']
    
    def getOS(self):
        return self.__result['os']
    
    def getAdditionalInfo(self,key):
        return self.__result[key]
    
    def setAdditionalInfo(self, key, value):
        self.__result[key] = value