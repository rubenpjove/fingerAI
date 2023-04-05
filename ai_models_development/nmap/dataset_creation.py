import pandas as pd
import nmap_db_parser as p

in_classes = p.parse_in_classes("./os-classes")
dataset_list, column_names = p.parse_database("./nmap-os-db",10000,in_classes,True)

df = pd.DataFrame(dataset_list, columns=column_names)

def group_classes(os_class):
    if os_class in ['MacOS','macOS','MacOSX','OSX']:
        return 'Mac OS X'
    # elif os_class in ['IOS','iOS','iPhoneOS']:
    #     return 'iOS'
    # elif 'BSD' in os_class:
    #     return 'BSD'
    else:
        return os_class
df['Class.OSfamily'] = df['Class.OSfamily'].apply(group_classes)

df.pop('Class.device')
df.reset_index(drop=True, inplace=True)

df.to_csv(r'./dataset.csv', index=False)