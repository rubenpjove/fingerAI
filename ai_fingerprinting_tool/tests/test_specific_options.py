import pytest
from ai_fingerprinting_tool.options import Options
from ai_fingerprinting_tool.scanners.p0f import p0fOptions

def optionsFixture(params):
    options = Options()
    options.parseArguments(params)
    options = p0fOptions(options.getArgs())
    return options


def test_no_options():
    with pytest.raises(SystemExit):
        optionsFixture([])
        
def test_no_mode():
    with pytest.raises(SystemExit):
        optionsFixture(["target"])

def test_active_mode():
    assert optionsFixture(["active","p0f","target"]).getMode() == "active"
    
def test_passive_mode():
    assert optionsFixture(["passive","nmap","target"]).getMode() == "passive"

def test_no_target():
    with pytest.raises(SystemExit):
        optionsFixture(["active","p0f"])

def test_target():
    assert optionsFixture(["active","nmap","target"]).getTarget() == "target"

def test_port():
    assert optionsFixture(["active","nmap","target","-p","8000"]).getPort() == 8000

def test_default_port():
    assert optionsFixture(["active","nmap","target"]).getPort() == 80

def test_interface():
    assert optionsFixture(["active","nmap","target","-i","eth0"]).getInterface() == "eth0"
    
def test_timeout():
    assert optionsFixture(["active","nmap","target","-t","50"]).getTimeout() == 50
    
def test_inputFile():
    assert optionsFixture(["active","nmap","target","-iF","./inputFile"]).getInputFile() == "./inputFile"
    
def test_real_p0f_result():
    assert optionsFixture(["active","nmap","target","-realp0f"]).getp0fToolResult() == True