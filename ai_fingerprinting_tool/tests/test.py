from scapy.all import *
from scapy.layers.all import *

# t = AsyncSniffer(iface="wlo1",filter="ip proto \icmp")
# t.start()
# time.sleep(5)
# print('1')
# sr1(IP(dst="8.8.8.8")/ICMP())
# print('2')
# t.stop()
# t.results.summary()

# sniff(lfilter=lambda pkt: ICMP in pkt, prn=lambda x: x.summary())