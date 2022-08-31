ubuntu = {
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '65160',
    'window_scaling': '7',
    'tcp_options': 'mss,sok,ts,nop,ws',
    'quirk_df': 1,
    'quirk_ts': 0,
    'os': 'Linux'
}

windows = {
    'initial_ttl': '128',
    'mss': '1460',
    'window_size': '65535',
    'window_scaling': '8',
    'tcp_options': 'mss,nop,ws,sok',
    'quirk_df': 1,
    'quirk_ts': 0,
    'os': 'Windows'
}

solaris = {
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '64074',
    'window_scaling': '2',
    'tcp_options': 'sok,ts,mss,nop,ws',
    'quirk_df': 1,
    'quirk_ts': 0,
    'os': 'Solaris'
}

freebsd = {
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '65535',
    'window_scaling': '6',
    'tcp_options': 'mss,nop,ws,sok,ts',
    'quirk_df': 1,
    'quirk_ts': 0,
    'os': 'FreeBSD'
}

openbsd = {
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '16384',
    'window_scaling': '6',
    'tcp_options': 'mss,nop,sok,ws,ts',
    'quirk_df': 1,
    'quirk_ts': 0,
    'os': 'OpenBSD'
}

macosx = {
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '65535',
    'window_scaling': '5',
    'tcp_options': 'mss,nop,ws,ts,sok,eol',
    'quirk_df': 1,
    'quirk_ts': 0,
    'os': 'Mac OS X'
}


import pytest
from ai_fingerprinting_tool.ui import UI
from ai_fingerprinting_tool.scan import ScanGenerator
from ai_fingerprinting_tool.scanners.p0f import p0fSignature

@pytest.fixture(scope='module')
def preparation():
    ui = UI()
    options = ui.parseOptions(["nmap","active","target"],True)
    scanGenerator = ScanGenerator()
    scan,options = scanGenerator.createScan(options)
    ui.updateOptions(options)
    return scan

@pytest.mark.parametrize("signature,nmapExpected", [
    (ubuntu,"Linux"),
    (windows,"Windows"),
    (solaris,"Solaris"),
    (freebsd,"FreeBSD"),
    (openbsd,"OpenBSD"),
    (macosx,"mac OS"),
])
def test_classification(preparation, signature, nmapExpected):
    expected_result = signature['os']
    signature.pop('os')
    
    p0fsig = p0fSignature(signature)
    
    classificator = preparation.createClassificator()
    
    assert classificator.classify(p0fsig).getOS() == expected_result
    
    
@pytest.mark.parametrize("signature,nmapExpected", [
    (ubuntu,"Linux"),
    (windows,"Windows"),
    (solaris,"Solaris"),
    (freebsd,"FreeBSD"),
    (openbsd,"OpenBSD"),
    (macosx,"Mac OS X"),
])
def test_nmap_classification(preparation, signature, nmapExpected):
    expected_result = nmapExpected
    signature.pop('os')
    
    p0fsig = p0fSignature(signature)
    
    classificator = preparation.createClassificator()
    
    assert classificator.classify(p0fsig).getOS() == expected_result