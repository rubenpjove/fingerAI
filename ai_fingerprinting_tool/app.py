from ai_fingerprinting_tool.sniffer import Sniffer
from ai_fingerprinting_tool.ui import UI
from ai_fingerprinting_tool.preprocessor import *

from scapy.all import *

def run():
    # Create the UI and parse user arguments
    ui = UI()
    options = ui.parseOptions()
    
    # Scan the network traffic
    sniffer = Sniffer(options)
    sniffer.sniff()
    capture = sniffer.getCapturedPackets()
    
    # Preprocess the captured packets
    preprocessor = TrafficPreprocessor(options)
    processedTraffic = preprocessor.processTraffic(capture)
    
    # Generate the signature
    signatureGenerator = SignatureGenerator()
    signatureGenerator.generateSignature(processedTraffic)
    signature = signatureGenerator.getSignatureDict()
    
    # Classify the signature    
    # classificator = Classificator()
    # result = classificator.classify(signature)
    
    # Show the results
    # ui.showResult(result)
    
    
if __name__ == '__main__':
    run()