from __future__ import annotations
from abc import ABC, abstractmethod
from ai_fingerprinting_tool.preprocess import AbstractSignature
from joblib import load
import pandas as pd
from ai_model_creation.transformers import *
import warnings 
from ai_fingerprinting_tool.ui import UI

class AbstractClassificator(ABC):
    
    @abstractmethod
    def classify(self,signature) -> None:
        pass
    

class p0fClassificator(AbstractClassificator):
    
    def __init__(self):
        pass
    
    def classify(self, signature:AbstractSignature):
        ui = UI()
        
        warnings.filterwarnings("ignore")
        
        encoders = load('persistance/encoders.joblib')
        
        df_signature = signature.getDataFrame()
        
        ui.printDebug(df_signature)
        
        transformed_signature = encoders.transform(df_signature)
        transformed_signature = pd.DataFrame(
            transformed_signature,
            columns=encoders.get_feature_names_out()
        )

        if transformed_signature.sig_direction.values[0] == 'request':
            classifier = load('persistance/classifier_request.joblib')
        else:
            classifier = load('persistance/classifier_response.joblib')
            
        Xdata = transformed_signature.drop(['os','sig_direction'],axis = 1).values
        
        result = classifier.predict(Xdata)
        
        return result