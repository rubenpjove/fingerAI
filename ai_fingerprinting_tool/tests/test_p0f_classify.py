ubuntu = {
    'sig_direction': 'response',
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '65160',
    'window_scaling': '7',
    'tcp_options': 'mss,sok,ts,nop,ws',
    'quirk_df': 1,
    'quirk_id': 0,
    'quirk_ts': 0,
    'os': 'Linux'
}

ubuntu2 = {
    'sig_direction': 'request',
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '65160',
    'window_scaling': '7',
    'tcp_options': 'mss,sok,ts,nop,ws',
    'quirk_df': 1,
    'quirk_id': 0,
    'quirk_ts': 0,
    'os': 'Linux'
}

windows = {
    'sig_direction': 'response',
    'initial_ttl': '128',
    'mss': '1460',
    'window_size': '65535',
    'window_scaling': '8',
    'tcp_options': 'mss,nop,ws,sok',
    'quirk_df': 1,
    'quirk_id': 1,
    'quirk_ts': 0,
    'os': 'Windows'
}

windows2 = {
    'sig_direction': 'request',
    'initial_ttl': '128',
    'mss': '1460',
    'window_size': '64240',
    'window_scaling': '8',
    'tcp_options': 'mss,nop,ws,sok',
    'quirk_df': 1,
    'quirk_id': 1,
    'quirk_ts': 0,
    'os': 'Windows'
}

solaris = {
    'sig_direction': 'response',
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '64074',
    'window_scaling': '2',
    'tcp_options': 'sok,ts,mss,nop,ws',
    'quirk_df': 1,
    'quirk_id': 1,
    'quirk_ts': 0,
    'os': 'Solaris'
}

solaris2 = {
    'sig_direction': 'request',
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '64240',
    'window_scaling': '2',
    'tcp_options': 'mss,sok,ts,nop,ws',
    'quirk_df': 1,
    'quirk_id': 1,
    'quirk_ts': 0,
    'os': 'Solaris'
}

freebsd = {
    'sig_direction': 'response',
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '65535',
    'window_scaling': '6',
    'tcp_options': 'mss,nop,ws,sok,ts',
    'quirk_df': 1,
    'quirk_id': 0,
    'quirk_ts': 0,
    'os': 'FreeBSD'
}

freebsd2 = {
    'sig_direction': 'request',
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '65535',
    'window_scaling': '6',
    'tcp_options': 'mss,nop,ws,sok,ts',
    'quirk_df': 1,
    'quirk_id': 0,
    'quirk_ts': 0,
    'os': 'FreeBSD'
}

openbsd = {
    'sig_direction': 'response',
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '16384',
    'window_scaling': '6',
    'tcp_options': 'mss,nop,sok,ws,ts',
    'quirk_df': 1,
    'quirk_id': 1,
    'quirk_ts': 0,
    'os': 'OpenBSD'
}

openbsd2 = {
    'sig_direction': 'request',
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '16384',
    'window_scaling': '6',
    'tcp_options': 'mss,nop,sok,ws,ts',
    'quirk_df': 1,
    'quirk_id': 1,
    'quirk_ts': 0,
    'os': 'OpenBSD'
}

macosx = {
    'sig_direction': 'response',
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '65535',
    'window_scaling': '5',
    'tcp_options': 'mss,nop,ws,ts,sok,eol',
    'quirk_df': 1,
    'quirk_id': 0,
    'quirk_ts': 0,
    'os': 'Mac OS X'
}

macosx2 = {
    'sig_direction': 'request',
    'initial_ttl': '64',
    'mss': '1460',
    'window_size': '65535',
    'window_scaling': '5',
    'tcp_options': 'mss,nop,ws,ts,sok,eol',
    'quirk_df': 1,
    'quirk_id': 0,
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
    options = ui.parseOptions(["p0f","active","target"],True)
    scanGenerator = ScanGenerator()
    scan,options = scanGenerator.createScan(options)
    ui.updateOptions(options)
    return scan

@pytest.mark.parametrize("signature,p0fExpected", [
    (ubuntu,"Linux"),
    (ubuntu2,"Linux"),
    (windows,"Windows"),
    (windows2,"Windows"),
    (solaris,"Solaris"),
    (solaris2,"Solaris"),
    (freebsd,"FreeBSD"),
    (freebsd2,"FreeBSD"),
    (openbsd,"OpenBSD"),
    (openbsd2,"OpenBSD"),
    (macosx,"Mac OS X"),
    (macosx2,"Mac OS X")
])
def test_classification(preparation, signature, p0fExpected):
    expected_result = signature['os']
    signature.pop('os')
    
    p0fsig = p0fSignature(signature)
    
    classificator = preparation.createClassificator()
    
    assert classificator.classify(p0fsig).getOS() == expected_result
    
    
@pytest.mark.parametrize("signature,p0fExpected", [
    (ubuntu,"Linux"),
    (ubuntu2,"Linux"),
    (windows,"Windows"),
    (windows2,"Windows"),
    (solaris,"Solaris"),
    (solaris2,"Linux"),
    (freebsd,"FreeBSD"),
    (freebsd2,"FreeBSD"),
    (openbsd,"FreeBSD"),
    (openbsd2,"Windows"),
    (macosx,"Linux"),
    (macosx2,"Windows")
])
def test_p0f_classification(preparation, signature, p0fExpected):
    expected_result = p0fExpected
    signature.pop('os')
    
    p0fsig = p0fSignature(signature)
    
    classificator = preparation.createClassificator()
    
    assert classificator.classify(p0fsig).getOS() == expected_result