import numpy as np
import pandas as pd
import p0f_db_parser as parser
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
<<<<<<<< HEAD:ai_model_creation/p0f/old/models_creation_seeds.py
from ai_model_creation.p0f.transformers import *
========
from fingerai.ai_models.p0f.transformers import *
>>>>>>>> develop:ai_models_development/p0f/models_creation_seeds.py
from sklearn.compose import make_column_transformer
from sklearn.compose import make_column_selector
from sklearn.model_selection import train_test_split
import time
from sklearn.model_selection import cross_val_score, GridSearchCV, StratifiedKFold
from sklearn.metrics import confusion_matrix,accuracy_score, roc_auc_score,f1_score, recall_score, precision_score
from sklearn.utils import class_weight
from sklearn.neighbors import KNeighborsClassifier
from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.ensemble import GradientBoostingClassifier, BaggingClassifier, AdaBoostClassifier
from sklearn.metrics import classification_report
from sklearn.naive_bayes import GaussianNB
from sklearn.discriminant_analysis import LinearDiscriminantAnalysis
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.svm import SVC
from sklearn.neural_network import MLPClassifier

dataset,column_names = parser.parse_database("/home/ruben/AIFingerprintingTool/ai_model_creation/ai_p0f_model_creation/p0f.fp")
df = pd.DataFrame(dataset,columns=column_names)
del dataset
del column_names

# Encoding
df = df[df.os.isin(['Linux', 'Windows', 'Mac OS X', 'Solaris', 'OpenBSD', 'FreeBSD'])]
df.reset_index(inplace=True, drop=True)
df.drop('version', inplace=True, axis=1)
solaris = pd.DataFrame({
    'sig_direction': 'response',
    'initial_ttl': 64,
    'mss': '1460',
    'window_size': '64074',
    'window_scaling': '2',
    'tcp_options': 'sok,ts,mss,nop,ws',
    'quirk_df': 1,
    'quirk_id': 1,
    'quirk_ts': 0,
    'os': 'Solaris'
},index=[0])

solaris2 = pd.DataFrame({
    'sig_direction': 'request',
    'initial_ttl': 64,
    'mss': '1460',
    'window_size': '64240',
    'window_scaling': '2',
    'tcp_options': 'mss,sok,ts,nop,ws',
    'quirk_df': 1,
    'quirk_id': 1,
    'quirk_ts': 0,
    'os': 'Solaris'
},index=[0])

openbsd = pd.DataFrame({
    'sig_direction': 'response',
    'initial_ttl': 64,
    'mss': '1460',
    'window_size': '16384',
    'window_scaling': '6',
    'tcp_options': 'mss,nop,sok,ws,ts',
    'quirk_df': 1,
    'quirk_id': 1,
    'quirk_ts': 0,
    'os': 'OpenBSD'
},index=[0])

openbsd2 = pd.DataFrame({
    'sig_direction': 'request',
    'initial_ttl': 64,
    'mss': '1460',
    'window_size': '16384',
    'window_scaling': '6',
    'tcp_options': 'mss,nop,sok,ws,ts',
    'quirk_df': 1,
    'quirk_id': 1,
    'quirk_ts': 0,
    'os': 'OpenBSD'
},index=[0])

macosx = pd.DataFrame({
    'sig_direction': 'response',
    'initial_ttl': 64,
    'mss': '1460',
    'window_size': '65535',
    'window_scaling': '5',
    'tcp_options': 'mss,nop,ws,ts,sok,eol',
    'quirk_df': 1,
    'quirk_id': 0,
    'quirk_ts': 0,
    'os': 'Mac OS X'
},index=[0])

macosx2 = pd.DataFrame({
    'sig_direction': 'request',
    'initial_ttl': 64,
    'mss': '1460',
    'window_size': '65535',
    'window_scaling': '5',
    'tcp_options': 'mss,nop,ws,ts,sok,eol',
    'quirk_df': 1,
    'quirk_id': 0,
    'quirk_ts': 0,
    'os': 'Mac OS X'
},index=[0])

df = pd.concat([df,solaris,solaris2,openbsd,openbsd2,macosx,macosx2], ignore_index = True,axis=0)
ttl_factor = 10
array = df.to_numpy()
ttl_i = df.columns.get_loc('initial_ttl')
for row in array:
    for i in range(1,ttl_factor+1):
        new_row = row.copy()
        new_row[ttl_i] = row[ttl_i] - i
        
        array = np.vstack((array, new_row))  
df = pd.DataFrame(array, columns = df.columns)
df.drop('mss', inplace=True, axis=1)
encoder_window_size = WindowSizeTransformer()
encoder_window_scaling = OneHotEncoder(drop=['*'], sparse=False, handle_unknown='ignore')
encoder_tcp_options = TCPOptionsTransformer()
df.reset_index(inplace=True, drop=True)
encoders = make_column_transformer(
    (encoder_window_size, ['window_size']),
    (encoder_window_scaling, ['window_scaling']),
    (encoder_tcp_options, ['tcp_options']),
    remainder='passthrough',
    verbose_feature_names_out=False)
transformed = encoders.fit_transform(df)
transformed_df = pd.DataFrame(
    transformed,
    columns=encoders.get_feature_names_out()
)
df = transformed_df
OutVar = df.os.name
df = df.drop_duplicates()
df_request = df[df.sig_direction.isin(['request'])].drop('sig_direction', axis=1)
df_response = df[df.sig_direction.isin(['response'])].drop('sig_direction', axis=1)
df_request.reset_index(inplace=True, drop=True)
df_response.reset_index(inplace=True, drop=True)
del df

# Get data as arrays
Ydata_request = df_request[OutVar].values
Xdata_request = df_request.drop(OutVar,axis = 1).values
Ydata_response = df_response[OutVar].values
Xdata_response = df_response.drop(OutVar,axis = 1).values

def set_weights(y_data, option='balanced'):
    """Estimate class weights for umbalanced dataset
       If ‘balanced’, class weights will be given by n_samples / (n_classes * np.bincount(y)). 
       If a dictionary is given, keys are classes and values are corresponding class weights. 
       If None is given, the class weights will be uniform """
    cw = class_weight.compute_class_weight(class_weight=option, classes=np.unique(y_data), y=y_data)
    w = {i:j for i,j in zip(np.unique(y_data), cw)}
    return w

def ML_baseline(cls, X_tr, y_tr, X_ts, y_ts, seed=42, classes=['0','1']):
    ACC = 0
    AUROC = 0
    precision = 0 
    recall = 0
    f1score = 0
    
    cls_name = type(cls).__name__
    
    start_time = time.time()
    cls.fit(X_tr, y_tr) # TRAINING!
    # print('\n---->', "training: %0.2f mins \n\n" % ((time.time() - start_time)/60))
    
    # predictions
    y_pred  = cls.predict(X_ts)             # predict classes
    y_probs = cls.predict_proba(X_ts)[:, 1] # predict probabilities of classes
    cls_rep = classification_report(y_ts, y_pred, target_names=classes,
                                    output_dict=True, digits=3)
    # print classification report
    #print(cls_rep)
    
    ACC       = accuracy_score(y_ts, y_pred)
    #AUROC     = roc_auc_score(y_ts, y_probs) # this is working for 2-classes classification only!!!
    precision = cls_rep['weighted avg']['precision']
    recall    = cls_rep['weighted avg']['recall']
    f1score   = cls_rep['weighted avg']['f1-score']  
    
    # print metrics
    # print("\n", "ACC=", ACC, "precision=", precision, "recall=", recall, "f1score=",f1score)
    
    return cls, ACC, precision, recall, f1score

statistics_ML_request = pd.DataFrame(columns=['Method', 'ACC','precision' ,'recall' ,'f1-score' ])
statistics_ML_response = pd.DataFrame(columns=['Method', 'ACC','precision' ,'recall' ,'f1-score' ])

# Data split
for seed in range(1,10):
    
    np.random.seed(seed)
    X_train_request, X_test_request, y_train_request, y_test_request = train_test_split(Xdata_request, Ydata_request,
                                                                        stratify=Ydata_request, 
                                                                        test_size=0.10,
                                                                        random_state=seed)

    X_train_response, X_test_response, y_train_response, y_test_response = train_test_split(Xdata_response, Ydata_response,
                                                                            stratify=Ydata_response, 
                                                                            test_size=0.10,
                                                                            random_state=seed)
    
    class_weights_request = set_weights(Ydata_request)
    class_weights_response = set_weights(Ydata_response)
    
    classifiers_request = [
        GaussianNB(),
        LinearDiscriminantAnalysis(), # No random_state
        LogisticRegression(n_jobs=-1,solver='lbfgs',random_state=seed,class_weight=class_weights_request),
        MLPClassifier(hidden_layer_sizes= (30), random_state = seed, shuffle=False, solver='adam',activation='relu',batch_size=500, max_iter=5000),
        DecisionTreeClassifier(random_state=seed,class_weight=class_weights_request),
        RandomForestClassifier(n_jobs=-1,random_state=seed,class_weight=class_weights_request),
        BaggingClassifier(n_jobs=-1,random_state=seed)
    ]

    classifiers_response = [
        GaussianNB(),
        LinearDiscriminantAnalysis(), # No random_state
        LogisticRegression(n_jobs=-1,solver='lbfgs',random_state=seed,class_weight=class_weights_response),
        MLPClassifier(hidden_layer_sizes= (30), random_state = seed, shuffle=False, solver='adam',activation='relu',batch_size=500, max_iter=5000),
        DecisionTreeClassifier(random_state=seed,class_weight=class_weights_response),
        RandomForestClassifier(n_jobs=-1,random_state=seed,class_weight=class_weights_response),
        BaggingClassifier(n_jobs=-1,random_state=seed)
    ]   
    
    
    models_ML_request = pd.DataFrame(columns=['Method', 'Model' ])

    classes_names = np.unique(Ydata_request)

    for cls in classifiers_request:
        cls_fit, ACC, precision,recall,f1score=ML_baseline(cls, X_train_request, y_train_request, X_test_request, y_test_request, seed=seed,classes=classes_names)
        
        statistics_ML_request = statistics_ML_request.append({'Method': str(type(cls).__name__),
                                                                'ACC': float(ACC),
                                                                #'AUROC': float(AUROC),
                                                                'precision': float(precision),
                                                                'recall': float(recall),
                                                                'f1-score': float(f1score)}, ignore_index=True)
        
        models_ML_request = models_ML_request.append({'Method': str(type(cls).__name__)+str(seed),
                                                    'Model' : cls_fit}, ignore_index=True)
        
    
    
    models_ML_response = pd.DataFrame(columns=['Method', 'Model' ])

    classes_names = np.unique(Ydata_response)

    for cls in classifiers_response:
        cls_fit, ACC, precision,recall,f1score=ML_baseline(cls, X_train_response, y_train_response, X_test_response, y_test_response, seed=seed,classes=classes_names)
        
        statistics_ML_response = statistics_ML_response.append({'Method': str(type(cls).__name__),
                                                                'ACC': float(ACC),
                                                                #'AUROC': float(AUROC),
                                                                'precision': float(precision),
                                                                'recall': float(recall),
                                                                'f1-score': float(f1score)}, ignore_index=True)
        
        models_ML_response = models_ML_response.append({'Method': str(type(cls).__name__)+str(seed),
                                                        'Model' : cls_fit}, ignore_index=True)
    
    
    statistics_ML_request.to_csv('statistics_ML_request.csv')
    statistics_ML_response.to_csv('statistics_ML_response.csv')
    
    print(statistics_ML_request)
    print()
    print(statistics_ML_response)