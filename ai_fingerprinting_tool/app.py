from ai_fingerprinting_tool.ui import UI
from ai_fingerprinting_tool.scan import ScanGenerator

def run():
    # Create the UI and parse user arguments
    ui = UI()
    options = ui.parseOptions()
    
    # Create the set of classes depending on the options
    scanGenerator = ScanGenerator()
    scan,options = scanGenerator.createScan(options)
    ui.updateOptions(options)
    
    # Scan the network traffic
    sniffer = scan.createSniffer(options)
    sniffer.sniff()
    capture = sniffer.getCapturedPackets()
    
    # Preprocess the captured packets
    preprocessor = scan.createTrafficPreprocessor(options)
    preprocessor.preprocessTraffic(capture)
    processedTraffic = preprocessor.getPreprocessedTraffic()
    
    # Generate the signature
    signatureGenerator = scan.createSignatureGenerator()
    signatureGenerator.generateSignature(processedTraffic)
    signature = signatureGenerator.getSignature()
    
    # Classify the signature
    classificator = scan.createClassificator()
    result = classificator.classify(signature)
    
    # Show the results
    ui.showResults(result)
    
    
if __name__ == '__main__':
    run()