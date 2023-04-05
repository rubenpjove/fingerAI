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
    'os': 'BSD'
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
    'os': 'BSD'
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
    'os': 'BSD'
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
    'os': 'BSD'
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
from fingerai.tool.ui import UI
from fingerai.tool.scan import ScanGenerator
from fingerai.tool.scanners.p0f import p0fSignature

@pytest.fixture(scope='module')
def preparation():
    ui = UI()
    options = ui.parseOptions(["active","p0f","target"],True)
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
    (freebsd,"BSD"),
    (freebsd2,"BSD"),
    (openbsd,"BSD"),
    (openbsd2,"BSD"),
    (macosx,"Mac OS X"),
    (macosx2,"Mac OS X")
])
def test_classification(preparation, signature, p0fExpected):
    expected_result = signature['os']
    signature.pop('os')
    
    p0fsig = p0fSignature(signature)
    
    classificator = preparation.createClassificator()
    
    assert classificator.classify(p0fsig).getOS() == expected_result