from capture.sniffer import Sniffer
from ui.ui import UI

def run():
    ui = UI()
    ui.parseOptions()
    print(ui.args)
    
    sniffer = Sniffer()
    sniffer.sniff()
    
    # preprocessor = Preprocessor()
    # signature = preprocessor.process(packets)
    
    # classificator = Classificator()
    # result = classificator.classify(signature)
    
    # ui.showResult(result)
    
    
if __name__ == '__main__':
    run()