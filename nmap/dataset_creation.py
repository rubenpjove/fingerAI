import pandas as pd
import nmap_db_parser as p

in_classes = p.parse_in_classes("./nmap_files/os-classes-db79-IN.txt")
dataset_list, column_names = p.parse_database("./db7.9.txt",100000,in_classes,True)

df = pd.DataFrame(dataset_list, columns=column_names)

def group_classes(os_class):
    if os_class in ['MacOS','macOS','MacOSX','OSX']:
        return 'macOS'
    elif os_class in ['IOS','iOS','iPhoneOS']:
        return 'iOS'
    elif 'BSD' in os_class:
        return 'BSD'
    else:
        return os_class
df['Class.OSfamily_0'] = df['Class.OSfamily_0'].apply(group_classes)

df.pop('Class.vendor_0')
df.pop('Class.OSgen_0')
df.pop('Class.device_0')
df.reset_index(drop=True, inplace=True)

df.to_feather(r'./dataset.feather')