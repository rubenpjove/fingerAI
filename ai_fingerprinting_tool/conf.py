import os

SCANS = ['p0f','nmap']

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PERSISTENCE_DIR = os.path.abspath(os.path.join(os.path.join(ROOT_DIR, os.pardir),'persistence'))

PERSISTENCE_p0f_DIR = os.path.join(PERSISTENCE_DIR, 'p0f')
p0f_ENCODERS = os.path.join(PERSISTENCE_p0f_DIR, 'p0f_encoders.joblib')
p0f_REQUEST_CLASSIFIER = os.path.join(PERSISTENCE_p0f_DIR, 'p0f_classifier_request.joblib')
p0f_RESPONSE_CLASSIFIER = os.path.join(PERSISTENCE_p0f_DIR, 'p0f_classifier_response.joblib')

PERSISTENCE_nmap_DIR = os.path.join(PERSISTENCE_DIR, 'nmap')
nmap_ENCODERS = os.path.join(PERSISTENCE_nmap_DIR, 'nmap_encoders.joblib')
nmap_CLASSIFIER = os.path.join(PERSISTENCE_nmap_DIR, 'nmap_classifier.joblib')