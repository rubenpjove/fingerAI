from ai_fingerprinting_tool.options import Options

def optionsFixture(params):
    options = Options()
    options.parseArguments(["active","p0f","target"]+params)
    return options

        
def test_verbose():
    assert optionsFixture(["-v"]).getVerbose() == True
    
def test_no_verbose():
    assert optionsFixture([]).getVerbose() == False
    
def test_debug():
    assert optionsFixture(["-d"]).getDebug() == True
    
def test_no_debug():
    assert optionsFixture([]).getDebug() == False
    
def test_verbose_with_debug():
    assert optionsFixture(["-d"]).getVerbose() == True
    
def test_quiet():
    assert optionsFixture(["-q"]).getQuiet() == True
    
def test_no_quiet():
    assert optionsFixture([]).getQuiet() == False

def test_verbose_with_quiet():
    assert optionsFixture(["-v","-q"]).getVerbose() == False
    
def test_debug_with_quiet():
    assert optionsFixture(["-d","-q"]).getDebug() == False

def test_outputFormat_default():
    assert optionsFixture([]).getOutputFormat() == "normal"

def test_outputFormat_normal():
    assert optionsFixture(["-o","normal"]).getOutputFormat() == "normal"
    
def test_outputFormat_json():
    assert optionsFixture(["-o","json"]).getOutputFormat() == "json"
    
def test_outputFormat_grep():
    assert optionsFixture(["-o","grep"]).getOutputFormat() == "grep"

def test_outputFile():
    assert optionsFixture(["-oF","./output"]).getOutputFile() == "./output"
