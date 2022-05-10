from ai_fingerprinting_tool.scan import p0fScan
from ai_fingerprinting_tool.ui import UI

def run():
    # Create the factory depending on the scan algorithm
    scan = p0fScan()
    
    
    # Create the UI and parse user arguments
    ui = UI()
    options = ui.parseOptions()
    
    
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
    signature = signatureGenerator.getSignatureList()

    
    # Classify the signature
    classificator = scan.createClassificator()
    result = classificator.classify(signature)
    
    
    # Show the results
    # ui.showResult(result)
    
    
if __name__ == '__main__':
    run()