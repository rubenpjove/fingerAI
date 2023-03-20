import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder
<<<<<<<< HEAD:ai_models_development/nmap/models_creation_seeds.py
from fingerai.ai_models.p0f.transformers import *
========
from ai_model_creation.p0f.transformers import *
>>>>>>>> 56abc9e (Refactoring):ai_model_creation/nmap/models_creation_seeds.py
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

df = pd.read_csv('./dataset.csv',low_memory=False)
df = df[['Class.OSfamily',
         'T1.R', 'T1.DF', 'T1.TG','WIN.W1','OPS.O1',
         'T1.R', 'T1.DF', 'T1.TG','WIN.W2','OPS.O2',
         'T1.R', 'T1.DF', 'T1.TG','WIN.W3','OPS.O3',
         'T1.R', 'T1.DF', 'T1.TG','WIN.W4','OPS.O4',
         'T1.R', 'T1.DF', 'T1.TG','WIN.W5','OPS.O5',
         'T1.R', 'T1.DF', 'T1.TG','WIN.W6','OPS.O6',
         'T2.R', 'T2.DF', 'T2.TG', 'T2.W',  'T2.O',   
         'T3.R', 'T3.DF', 'T3.TG', 'T3.W',  'T3.O',   
         'T4.R', 'T4.DF', 'T4.TG', 'T4.W',  'T4.O',   
         'T5.R', 'T5.DF', 'T5.TG', 'T5.W',  'T5.O',   
         'T6.R', 'T6.DF', 'T6.TG', 'T6.W',  'T6.O',   
         'T7.R', 'T7.DF', 'T7.TG', 'T7.W',  'T7.O'
         ]]

df.columns = ['os',
         '1.R', '1.DF', '1.TG','1.W','1.O',
         '2.R', '2.DF', '2.TG','2.W','2.O',
         '3.R', '3.DF', '3.TG','3.W','3.O',
         '4.R', '4.DF', '4.TG','4.W','4.O',
         '5.R', '5.DF', '5.TG','5.W','5.O',
         '6.R', '6.DF', '6.TG','6.W','6.O',
         '7.R', '7.DF', '7.TG', '7.W',  '7.O',   
         '8.R', '8.DF', '8.TG', '8.W',  '8.O',   
         '9.R', '9.DF', '9.TG', '9.W',  '9.O',   
         '10.R', '10.DF', '10.TG', '10.W', '10.O',   
         '11.R', '11.DF', '11.TG', '11.W', '11.O',   
         '12.R', '12.DF', '12.TG', '12.W', '12.O'
         ]
df_list = df.to_dict('records')
del df
new_df_list = []

for row in df_list:
    for i in range(1,13):
        if row[str(i)+'.R'] == "Y" and row[str(i)+'.W'] != 0:
            new_row = {}
            istr = str(i)
            new_row['os'] = row['os']
            new_row['initial_ttl'] = row[istr+'.TG']
            new_row['window_size'] = row[istr+'.W']
            new_row['quirk_df'] = 1 if row[istr+'.DF'] == "Y" else 0
            new_row['quirk_ts'] = 0
            new_row['mss'] = '*'
            new_row['window_scaling'] = '*'
            
            options = str(row[istr+'.O'])
            options = options.split(',')
            final_options = []
            for options_item in options:
                if options_item in ["eol","nop","sok"]:
                    final_options.append(options_item)
                if "mss" in options_item :
                    new_row['mss'] = options_item.split('.')[1]
                    final_options.append("mss")
                if "ws" in options_item:
                    new_row['window_scaling'] = options_item.split('.')[1]
                    final_options.append("ws")
                if "ts" in options_item:
                    new_row['quirk_ts'] = 1 if options_item.split('.')[1][0] == '0' else 0
                    final_options.append("ts")
                    
            new_row['tcp_options'] = ','.join(final_options)
            new_df_list.append(new_row)
            
del df_list
df = pd.DataFrame(new_df_list)
del new_df_list
df.drop_duplicates(keep=False, inplace=True)

# Encoding
df = df[df.os.isin(['Linux', 'Windows', 'Mac OS X', 'Solaris', 'OpenBSD', 'FreeBSD'])]
df.reset_index(inplace=True, drop=True)
solaris = pd.DataFrame({
    'initial_ttl': 64,
    'window_size': '64074',
    'window_scaling': '2',
    'tcp_options': 'sok,ts,mss,nop,ws',
    'quirk_df': 1,
    'quirk_ts': 0,
    'os': 'Solaris'
},index=[0])

openbsd = pd.DataFrame({
    'initial_ttl': 64,
    'window_size': '16384',
    'window_scaling': '6',
    'tcp_options': 'mss,nop,sok,ws,ts',
    'quirk_df': 1,
    'quirk_ts': 0,
    'os': 'OpenBSD'
},index=[0])


df = pd.concat([df,openbsd,solaris], ignore_index = True,axis=0)
df.drop_duplicates(keep=False, inplace=True)
print('Shape after removing duplicates=', df.shape)

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

# Get data as arrays
Ydata = df[OutVar].values
Xdata = df.drop(OutVar,axis = 1).values

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

statistics_ML = pd.DataFrame(columns=['Method', 'ACC','precision' ,'recall' ,'f1-score' ])

# Data split
for seed in range(1,10):
    
    np.random.seed(seed)
    X_train, X_test, y_train, y_test = train_test_split(Xdata, Ydata,
                                                    stratify=Ydata, 
                                                    test_size=0.10,
                                                    random_state=seed)
    
    class_weights = set_weights(Ydata)
    
    classifiers = [
        GaussianNB(),
        LinearDiscriminantAnalysis(), # No random_state
        LogisticRegression(n_jobs=-1,solver='lbfgs',random_state=seed,class_weight=class_weights),
        MLPClassifier(hidden_layer_sizes= (30), random_state = seed, shuffle=False, solver='adam',activation='relu',batch_size=500, max_iter=5000),
        DecisionTreeClassifier(random_state=seed,class_weight=class_weights),
        RandomForestClassifier(n_jobs=-1,random_state=seed,class_weight=class_weights),
        BaggingClassifier(n_jobs=-1,random_state=seed)
    ]

    models_ML = pd.DataFrame(columns=['Method', 'Model' ])

    classes_names = np.unique(Ydata)

    for cls in classifiers:
        cls_fit, ACC, precision,recall,f1score=ML_baseline(cls, X_train, y_train, X_test, y_test, seed=seed,classes=classes_names)
        
        statistics_ML = statistics_ML.append({'Method': str(type(cls).__name__),
                                                                'ACC': float(ACC),
                                                                #'AUROC': float(AUROC),
                                                                'precision': float(precision),
                                                                'recall': float(recall),
                                                                'f1-score': float(f1score)}, ignore_index=True)
        
        models_ML = models_ML.append({'Method': str(type(cls).__name__)+str(seed),
                                                    'Model' : cls_fit}, ignore_index=True)
        
    

    statistics_ML.to_csv('statistics_ML.csv')
    
    print(statistics_ML)