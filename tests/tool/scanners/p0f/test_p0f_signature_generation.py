import pytest
from fingerai.tool.ui import UI
from fingerai.tool.scan import ScanGenerator
from fingerai.tool.scanners.p0f import p0fTrafficCapture

from scapy.plist import PacketList
from scapy.layers.all import IP, TCP, UDP, ICMP, IPv6
from datetime import datetime

@pytest.fixture(scope='module')
def preparation():
    ui = UI()
    options = ui.parseOptions(["active","p0f","1.1.1.1"],True)
    scanGenerator = ScanGenerator()
    scan,options = scanGenerator.createScan(options)
    ui.updateOptions(options)
    return scan,options


def test_preprocessing_no_traffic(preparation):
    with pytest.raises(SystemExit):
        scan,options = preparation
    
        signatureGenerator = scan.createSignatureGenerator()
        signatureGenerator.generateSignature(p0fTrafficCapture(PacketList()))
    
    
def test_preprocessing_none_traffic(preparation):
    with pytest.raises(SystemExit):
        scan,options = preparation
    
        signatureGenerator = scan.createSignatureGenerator()
        signatureGenerator.generateSignature(p0fTrafficCapture(PacketList(None)))
    
    
@pytest.mark.parametrize("packet,initial_ttl,window_scaling,tcp_options,quirk_df,quirk_id,quirk_ts", [
    (IP(src="1.1.1.1",
        ttl=64)/
     TCP(dport=80,
         flags="S",
         window=2,
         options=[('MSS',1460),
                  ('SAckOK',''),
                  ('Timestamp',(int(datetime.timestamp(datetime.now())),0)),
                  ('NOP',0),
                  ('WScale',7)]),
     "64","7","mss,sok,ts,nop,ws",0,0,0
     ),
    (IP(src="1.1.1.1",
        ttl=128,
        flags=2,
        id=90)/
     TCP(dport=80,
         flags="SA",
         window=9,
         options=[('SAckOK',''),
                  ('Timestamp',(0,0)),
                  ('NOP',0)]),
     "128","*","sok,ts,nop",1,1,1
     )
])
def test_preprocessing_packets(preparation,packet,initial_ttl,window_scaling,tcp_options,quirk_df,quirk_id,quirk_ts):
    scan,options = preparation
    
    signatureGenerator = scan.createSignatureGenerator()
    signatureGenerator.generateSignature(p0fTrafficCapture(PacketList(packet)))
    signature = signatureGenerator.getSignature().getDict()
    
    # assert signature['sig_direction'] == sig_direction
    assert signature['initial_ttl'] == initial_ttl
    # assert signature['window_size'] == window_size
    assert signature['window_scaling'] == window_scaling
    assert signature['tcp_options'] == tcp_options
    assert signature['quirk_df'] == quirk_df
    assert signature['quirk_id'] == quirk_id
    assert signature['quirk_ts'] == quirk_ts