import pytest
from ai_fingerprinting_tool.ui import UI
from ai_fingerprinting_tool.scan import ScanGenerator
from ai_fingerprinting_tool.scanners.p0f import p0fTrafficCapture

from scapy.plist import PacketList
from scapy.layers.all import IP, TCP, UDP, ICMP, IPv6

@pytest.fixture(scope='module')
def preparation():
    ui = UI()
    options = ui.parseOptions(["p0f","active","1.1.1.1"],True)
    scanGenerator = ScanGenerator()
    scan,options = scanGenerator.createScan(options)
    ui.updateOptions(options)
    return scan,options

    
def test_preprocessing_no_traffic(preparation):
    scan,options = preparation

    preprocessor = scan.createTrafficPreprocessor(options)
    preprocessor.preprocessTraffic(p0fTrafficCapture(PacketList()))
    processedTraffic = preprocessor.getPreprocessedTraffic()
    
    assert len(processedTraffic.getPacketList()) == 0
    
    
def test_preprocessing_none_traffic(preparation):
    with pytest.raises(SystemExit):
        scan,options = preparation
    
        preprocessor = scan.createTrafficPreprocessor(options)
        preprocessor.preprocessTraffic(p0fTrafficCapture(None))
    
    
@pytest.mark.parametrize("packet,expected", [
    (IP(src="1.1.1.1")/TCP(dport=80,flags="S"),1),
    (IP(src="1.1.1.1")/TCP(dport=80,flags="SA"),1),
    (IP(src="2.2.2.2")/TCP(dport=80,flags="S"),0),
    (IP(src="2.2.2.2")/TCP(dport=80,flags="SA"),0),
    (IP(src="1.1.1.1")/UDP(),0),
    (IP(src="1.1.1.1")/ICMP(),0),
    (IPv6(src="::1"),0),
    (None,0),
    ([IP(src="2.2.2.2")/TCP(dport=80,flags="S"),
    IP(src="2.2.2.2")/TCP(dport=80,flags="SA"),
    IP(src="1.1.1.1")/UDP(),
    IP(src="1.1.1.1")/TCP(dport=80,flags="S"),
    IP(src="1.1.1.1")/ICMP(),
    IPv6(src="::1"),
    IP(src="1.1.1.1")/TCP(dport=80,flags="SA")],2)
])
def test_preprocessing_packets(preparation,packet,expected):
    scan,options = preparation

    preprocessor = scan.createTrafficPreprocessor(options)
    preprocessor.preprocessTraffic(p0fTrafficCapture(PacketList(packet)))
    processedTraffic = preprocessor.getPreprocessedTraffic()
    
    assert len(processedTraffic.getPacketList()) == expected
