from sklearn.base import BaseEstimator
from sklearn.base import TransformerMixin
from sklearn.preprocessing import OneHotEncoder
import pandas as pd

class WindowSizeTransformer(BaseEstimator, TransformerMixin):
    def __init__(self):
        pass
    
    def fit(self, X):
        return self 

    def transform(self,X):
        return X.drop(X.columns[0],axis=1)
    
    def get_feature_names_out(self,names='window_size'):
        # return [self.feature_name+str(i) for i in range(self.max_options)]
        return []

class TCPOptionsTransformer(BaseEstimator, TransformerMixin):
    def __init__(self):
        self.max_options = 0
        self.feature_name = ''
        self.classes = []
        self.headers = {}
        self.names_out = []
    
    def fit(self, X):
        X_2 = pd.DataFrame(X).reset_index(drop=True)
        self.feature_name = X_2.columns[0]
        for row in X_2[self.feature_name]:
            values = row.split(',')
            if len(values) > self.max_options:
                self.max_options = len(values)
            for v in values:
                if v not in self.classes:
                    self.classes.append(v)
        self.headers = {self.feature_name+str(i):'*' for i in range(self.max_options)}
        return self
    
    def transform(self, X):
        X_2 = pd.DataFrame(X).reset_index(drop=True)
        X_2 = X_2.assign(**self.headers)
        
        row_i = 0
        for row in X_2[self.feature_name]:
            values = row.split(',')
            values_len = len(values)
            for i in range(values_len):
                if i < self.max_options:
                    if values[i].startswith('eol'):
                        X_2.at[row_i,self.feature_name+str(i)] = 'eol'
                    else:
                        X_2.at[row_i,self.feature_name+str(i)] = values[i]
            row_i += 1
            
        X_2.drop(self.feature_name, inplace=True, axis=1)
        
        encoder2_tcp_options = OneHotEncoder(categories=[self.classes]*self.max_options,sparse=False,handle_unknown='ignore')
        
        encoder2_tcp_options.fit(X_2[list(self.headers.keys())])
        result = encoder2_tcp_options.transform(X_2[list(self.headers.keys())])
        
        self.names_out = encoder2_tcp_options.get_feature_names_out()
        
        return result
    
    def get_feature_names_out(self,names='tcp_options'):
        # return [self.feature_name+str(i) for i in range(self.max_options)]
        return self.names_out
