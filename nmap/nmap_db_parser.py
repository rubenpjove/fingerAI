# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %%
import sys
import re
import time
import pandas as pd
import numpy as np
import itertools
from nmap_db_parser_responses_format import *

# %%
probes_sent_dict = {
    'SEQ': re.compile(r'SEQ\((?P<SEQ>.*)\)'),
    'OPS': re.compile(r'OPS\((?P<OPS>.*)\)'),
    'WIN': re.compile(r'WIN\((?P<WIN>.*)\)'),
    'ECN': re.compile(r'ECN\((?P<ECN>.*)\)'),
    'T1': re.compile(r'T1\((?P<T1>.*)\)'),
    'T2': re.compile(r'T2\((?P<T2>.*)\)'),
    'T3': re.compile(r'T3\((?P<T3>.*)\)'),
    'T4': re.compile(r'T4\((?P<T4>.*)\)'),
    'T5': re.compile(r'T5\((?P<T5>.*)\)'),
    'T6': re.compile(r'T6\((?P<T6>.*)\)'),
    'T7': re.compile(r'T7\((?P<T7>.*)\)'),
    'U1': re.compile(r'U1\((?P<U1>.*)\)'),
    'IE': re.compile(r'IE\((?P<IE>.*)\)'),
}

test_parser = re.compile(r'(?P<key>.*)=(?P<value>.*)')

fingerprint_template = {
    'Class.vendor':[np.nan],
    'Class.OSfamily':[np.nan],
    'Class.OSgen':[np.nan],
    'Class.device':[np.nan],

    'SEQ.SP':[-1],
    'SEQ.GCD':[-1],
    'SEQ.ISR':[-1],
    'SEQ.TI':[[-1,-1]],
    'SEQ.CI':[[-1,-1]],
    'SEQ.II':[[-1,-1]],
    'SEQ.SS':[-1],
    'SEQ.TS':[[-1,-1]],

    'OPS.O1':[[-1,-1,-1,-1,-1,-1]],
    'OPS.O2':[[-1,-1,-1,-1,-1,-1]],
    'OPS.O3':[[-1,-1,-1,-1,-1,-1]],
    'OPS.O4':[[-1,-1,-1,-1,-1,-1]],
    'OPS.O5':[[-1,-1,-1,-1,-1,-1]],
    'OPS.O6':[[-1,-1,-1,-1,-1,-1]],

    'WIN.W1':[-1],
    'WIN.W2':[-1],
    'WIN.W3':[-1],
    'WIN.W4':[-1],
    'WIN.W5':[-1],
    'WIN.W6':[-1],

    'ECN.R':[-1],
    'ECN.DF':[-1],
    'ECN.T':[-1],
    'ECN.TG':[-1],
    'ECN.W':[-1],
    'ECN.O':[-1],
    'ECN.CC':[-1],
    'ECN.Q':[[-1,-1]],

    'T1.R':[-1],
    'T1.DF':[-1],
    'T1.T':[-1],
    'T1.TG':[-1],
    'T1.S':[-1],
    'T1.A':[-1],
    'T1.F':[[-1,-1,-1,-1,-1,-1,-1]],
    'T1.RD':[-1],
    'T1.Q':[[-1,-1]],

    'T2.R':[-1],
    'T2.DF':[-1],
    'T2.T':[-1],
    'T2.TG':[-1],
    'T2.W':[-1],
    'T2.S':[-1],
    'T2.A':[-1],
    'T2.F':[[-1,-1,-1,-1,-1,-1,-1]],
    'T2.O':[-1],
    'T2.RD':[-1],
    'T2.Q':[[-1,-1]],

    'T3.R':[-1],
    'T3.DF':[-1],
    'T3.T':[-1],
    'T3.TG':[-1],
    'T3.W':[-1],
    'T3.S':[-1],
    'T3.A':[-1],
    'T3.F':[[-1,-1,-1,-1,-1,-1,-1]],
    'T3.O':[-1],
    'T3.RD':[-1],
    'T3.Q':[[-1,-1]],

    'T4.R':[-1],
    'T4.DF':[-1],
    'T4.T':[-1],
    'T4.TG':[-1],
    'T4.W':[-1],
    'T4.S':[-1],
    'T4.A':[-1],
    'T4.F':[[-1,-1,-1,-1,-1,-1,-1]],
    'T4.O':[-1],
    'T4.RD':[-1],
    'T4.Q':[[-1,-1]],

    'T5.R':[-1],
    'T5.DF':[-1],
    'T5.T':[-1],
    'T5.TG':[-1],
    'T5.W':[-1],
    'T5.S':[-1],
    'T5.A':[-1],
    'T5.F':[[-1,-1,-1,-1,-1,-1,-1]],
    'T5.O':[-1],
    'T5.RD':[-1],
    'T5.Q':[[-1,-1]],

    'T6.R':[-1],
    'T6.DF':[-1],
    'T6.T':[-1],
    'T6.TG':[-1],
    'T6.W':[-1],
    'T6.S':[-1],
    'T6.A':[-1],
    'T6.F':[[-1,-1,-1,-1,-1,-1,-1]],
    'T6.O':[-1],
    'T6.RD':[-1],
    'T6.Q':[[-1,-1]],

    'T7.R':[-1],
    'T7.DF':[-1],
    'T7.T':[-1],
    'T7.TG':[-1],
    'T7.W':[-1],
    'T7.S':[-1],
    'T7.A':[-1],
    'T7.F':[[-1,-1,-1,-1,-1,-1,-1]],
    'T7.O':[-1],
    'T7.RD':[-1],
    'T7.Q':[[-1,-1]],

    'U1.R':[-1],
    'U1.DF':[-1],
    'U1.T':[-1],
    'U1.TG':[-1],
    'U1.IPL':[-1],
    'U1.UN':[-1],
    'U1.RIPL':[[-1,-1]],
    'U1.RID':[[-1,-1]],
    'U1.RIPCK':[[-1,-1]],
    'U1.RUCK':[-1],
    'U1.RUD':[-1],

    'IE.R':[-1],
    'IE.DFI':[-1],
    'IE.T':[-1],
    'IE.TG':[-1],
    'IE.CD':[[-1,-1]]
}

responses_format_dict = {
    # 'Class.vendor':np.nan,
    # 'Class.OSfamily':np.nan,
    # 'Class.OSgen':np.nan,
    # 'Class.device':np.nan,

    'SEQ.SP': hex_value,  # <hex_value>
    'SEQ.GCD': hex_value,  # <hex_value>
    'SEQ.ISR': hex_value,  # <hex_value>

    'SEQ.TI': TI_CI_II, #
    'SEQ.CI': TI_CI_II, # Z , RD , RI , BI , I , <hex_value>
    'SEQ.II': TI_CI_II, #

    'SEQ.SS': SS, # S , O
    'SEQ.TS': TS, # U , 0 , 1 , 7 , 8 , <hex_value>

    'OPS.O1':O, # 
    'OPS.O2':O, #
    'OPS.O3':O, # Order of the TCP header options
    'OPS.O4':O, # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    'OPS.O5':O, #
    'OPS.O6':O, #

    'WIN.W1':hex_value, #
    'WIN.W2':hex_value, #
    'WIN.W3':hex_value, # <hex_value>
    'WIN.W4':hex_value, #
    'WIN.W5':hex_value, #
    'WIN.W6':hex_value, #

    'ECN.R':Y_N, # Y , N
    'ECN.DF':Y_N, # Y , N
    'ECN.T':hex_value, # <hex_value>
    'ECN.TG':hex_value, # <hex_value>
    'ECN.W':hex_value, # <hex_value>
    'ECN.O':O, # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    'ECN.CC':CC, # N , S , Y , O
    'ECN.Q':Q, # [RU]{2}

    'T1.R':Y_N, # Y , N
    'T1.DF':Y_N, # Y , N
    'T1.T':hex_value, # <hex_value>
    'T1.TG':hex_value, # <hex_value>
    'T1.S':S, # Z , A , A+ , O
    'T1.A':A, # Z , S , S+ , O
    'T1.F':F, # E , U , A , P , R , S , F (in this order)
    'T1.RD':hex_value, # 0 , <CRC32_hex_value>
    'T1.Q':Q, # [RU]{2}

    'T2.R':Y_N, # Y , N
    'T2.DF':Y_N, # Y , N
    'T2.T':hex_value, # <hex_value>
    'T2.TG':hex_value, # <hex_value>
    'T2.W':hex_value, # <hex_value>
    'T2.S':S, # Z , A , A+ , O
    'T2.A':A, # Z , S , S+ , O
    'T2.F':F, # E , U , A , P , R , S , F (in this order)
    'T2.O':O, # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    'T2.RD':hex_value, # 0 , <CRC32_hex_value>
    'T2.Q':Q, # [RU]{2}

    'T3.R':Y_N, # Y , N
    'T3.DF':Y_N, # Y , N
    'T3.T':hex_value, # <hex_value>
    'T3.TG':hex_value, # <hex_value>
    'T3.W':hex_value, # <hex_value>
    'T3.S':S, # Z , A , A+ , O
    'T3.A':A, # Z , S , S+ , O
    'T3.F':F, # E , U , A , P , R , S , F (in this order)
    'T3.O':O, # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    'T3.RD':hex_value, # 0 , <CRC32_hex_value>
    'T3.Q':Q, # [RU]{2}

    'T4.R':Y_N, # Y , N
    'T4.DF':Y_N, # Y , N
    'T4.T':hex_value, # <hex_value>
    'T4.TG':hex_value, # <hex_value>
    'T4.W':hex_value, # <hex_value>
    'T4.S':S, # Z , A , A+ , O
    'T4.A':A, # Z , S , S+ , O
    'T4.F':F, # E , U , A , P , R , S , F (in this order)
    'T4.O':O, # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    'T4.RD':hex_value, # 0 , <CRC32_hex_value>
    'T4.Q':Q, # [RU]{2}

    'T5.R':Y_N, # Y , N
    'T5.DF':Y_N, # Y , N
    'T5.T':hex_value, # <hex_value>
    'T5.TG':hex_value, # <hex_value>
    'T5.W':hex_value, # <hex_value>
    'T5.S':S, # Z , A , A+ , O
    'T5.A':A, # Z , S , S+ , O
    'T5.F':F, # E , U , A , P , R , S , F (in this order)
    'T5.O':O, # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    'T5.RD':hex_value, # 0 , <CRC32_hex_value>
    'T5.Q':Q, # [RU]{2}

    'T6.R':Y_N, # Y , N
    'T6.DF':Y_N, # Y , N
    'T6.T':hex_value, # <hex_value>
    'T6.TG':hex_value, # <hex_value>
    'T6.W':hex_value, # <hex_value>
    'T6.S':S, # Z , A , A+ , O
    'T6.A':A, # Z , S , S+ , O
    'T6.F':F, # E , U , A , P , R , S , F (in this order)
    'T6.O':O, # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    'T6.RD':hex_value, # 0 , <CRC32_hex_value>
    'T6.Q':Q, # [RU]{2}

    'T7.R':Y_N, # Y , N
    'T7.DF':Y_N, # Y , N
    'T7.T':hex_value, # <hex_value>
    'T7.TG':hex_value, # <hex_value>
    'T7.W':hex_value, # <hex_value>
    'T7.S':S, # Z , A , A+ , O
    'T7.A':A, # Z , S , S+ , O
    'T7.F':F, # E , U , A , P , R , S , F (in this order)
    'T7.O':O, # (ORDER) L , N , M<hex_value> , W<hex_value> , T[01]{2} , S
    'T7.RD':hex_value, # 0 , <CRC32_hex_value>
    'T7.Q':Q, # [RU]{2}

    'U1.R':Y_N, # Y , N
    'U1.DF':Y_N, # Y , N
    'U1.T':hex_value, # <hex_value>
    'U1.TG':hex_value, # <hex_value>
    'U1.IPL':hex_value, # <hex_value>
    'U1.UN':hex_value, # <hex_value>
    'U1.RIPL':RIPL_RID_RUCK, # <hex_value> , G
    'U1.RID':RIPL_RID_RUCK, # G , <hex_value>
    'U1.RIPCK':RIPCK, # G , Z , I
    'U1.RUCK':RIPL_RID_RUCK, # G , <hex_value>
    'U1.RUD':RUD, # G , I

    'IE.R':Y_N, # Y , N
    'IE.DFI':DFI, # N , S , Y , O
    'IE.T':hex_value, # <hex_value>
    'IE.TG':hex_value, # <hex_value>
    'IE.CD':CD, # Z , S , <hex_value> , O
}

# %%
def _debug_output(dataset,f_added,f_skipped,comb_added,comb_skipped,classes_skipped):
    print("\nDATASET:")
    print("Size (Bytes / MB):")
    print(sys.getsizeof(dataset), end=" / ")
    print(sys.getsizeof(dataset)/1048576)
    print("Rows:")
    print(f'{len(dataset):,}')
    print("Columns:") 
    columns=len(dataset[0])
    not_equal=False
    for row in dataset:
        if len(row)!=columns:
            not_equal=True
    if not_equal:
        print("Not same columns in all rows")
    else:
        print(columns)
    print()
    print("FINGERPRINTS: {:,}".format(f_added+f_skipped))
    print("Added:")
    print(f_added)
    print("Skipped: {}".format(f_skipped))
    print()
    for clas in sorted(classes_skipped, key=lambda tup: tup[1]):
        print('{0: <45}{1:,}'.format(clas[0],clas[1]))
    print()
    print("COMBINATIONS: {:,}".format(comb_added+comb_skipped))
    print("Rows:")
    print(f'{len(dataset):,}')
    print("Combinations added:")
    print(f'{comb_added:,}')
    print("Combinations skipped:")
    print(f'{comb_skipped:,}')


# %%
def _expand_columns (in_column_names,dataset):
    columns_max_size = [1]*len(in_column_names)
    for row in dataset:
        for j_in_dataset, cell in enumerate(row):
            if isinstance(cell,list) and len(cell)>columns_max_size[j_in_dataset]:
                columns_max_size[j_in_dataset]=len(cell)

    new_in_column_names = []
    for j_in_columns, cell in enumerate(in_column_names):
        numbers = range(0,columns_max_size[j_in_columns])
        new_cell = []
        for i in numbers:
            new_cell.append(in_column_names[j_in_columns]+"_"+str(i))
        new_in_column_names+=new_cell
        
    for i_in_dataset, row in enumerate(dataset):
        new_row = []
        for j_in_dataset, cell in enumerate(row):
            new_cell = [-1]*columns_max_size[j_in_dataset]
            if isinstance(cell,list):
                new_cell[0:len(cell)] = [random.randint(value[0],value[1]) if isinstance(value,tuple) else value for value in cell]
                new_row += new_cell
            elif isinstance(cell,tuple):
                new_cell[0]=random.randint(cell[0],cell[1])
                new_row += new_cell
            else:
                new_cell[0]=cell
                new_row += new_cell
        dataset[i_in_dataset]=new_row

    return new_in_column_names


# %%
def _parse_probe(line):
    line = line.strip()
    for key, rx in probes_sent_dict.items():
        match = rx.search(line)
        if match:
            return key, match.group(key)

    return None, None


# %%
def _parse_entry_class(entry_class):

    entry_class = entry_class.split("|")

    return [entry_class[0],entry_class[1],entry_class[2],entry_class[3]]


# %%
def _parse_value(in_value):
    
    return in_value.replace(" ",'').split('|')


# %%
def _parse_fingerprint(fingerprint,dataset,max_comb,in_classes):

    fingerprint = [line for line in fingerprint if line[0]!="#" and not line.startswith("Fingerprint") and not line.startswith("CPE")]

    entry_classes = []
    probes = []
    for line in fingerprint:
        if line.startswith("Class"):
            line = line.replace("Class",'').replace(" ",'')
            if in_classes is None or line in in_classes:
                entry_classes.append(_parse_entry_class(line))
        else:
            probes.append(line)

    local_template = fingerprint_template.copy()
    for probe in probes:
            
            probe_key, probe_responses = _parse_probe(probe)

            for test in probe_responses.split('%'):

                match = test_parser.search(test)

                if match:
                    test_key = match.group('key')
                    test_value = match.group('value')
                    id = probe_key + "." + test_key

                    if id not in fingerprint_template:
                        continue

                    test_value = _parse_value(test_value)

                    if not isinstance(test_value,list):
                        test_value=[test_value]

                    if id in responses_format_dict:
                        test_value = [responses_format_dict[id](cell) for cell in test_value]

                    local_template[id] = test_value
                else:
                    if test!="":
                        raise Exception("The test does not exist")

    aux = list(local_template.values())

    number_of_options = 1
    for value in aux:
        number_of_options*=len(value)

    if number_of_options > max_comb:
        return 0,len(entry_classes),0,number_of_options*(len(entry_classes)),[(entry[0]+" "+entry[1]+" "+entry[2]+" "+entry[3],number_of_options*(len(entry_classes))) for entry in entry_classes]

    combinations = list(itertools.product(*aux))

    for entry_class in entry_classes:
        for combination in combinations:
            combination = list(combination)
            combination[0] = entry_class[0]
            combination[1] = entry_class[1]
            combination[2] = entry_class[2]
            combination[3] = entry_class[3]
            dataset.append(combination)

    return len(entry_classes),0,number_of_options*len(entry_classes),0,[]

    

# %%
def parse_database(filepath,max_comb,classes,debug):

    with open(filepath, 'r') as database_file:
        dataset = []
        
        fingerprints = database_file.read().split('\n\n')

    column_names = ['Class.vendor','Class.OSfamily','Class.OSgen','Class.device',
                'SEQ.SP','SEQ.GCD','SEQ.ISR','SEQ.TI','SEQ.CI','SEQ.II','SEQ.SS','SEQ.TS',
                'OPS.O1','OPS.O2','OPS.O3','OPS.O4','OPS.O5','OPS.O6',
                'WIN.W1','WIN.W2','WIN.W3','WIN.W4','WIN.W5','WIN.W6',
                'ECN.R','ECN.DF','ECN.T','ECN.TG','ECN.W','ECN.O','ECN.CC','ECN.Q',
                'T1.R','T1.DF','T1.T','T1.TG','T1.S','T1.A','T1.F','T1.RD','T1.Q',
                'T2.R','T2.DF','T2.T','T2.TG','T2.W','T2.S','T2.A','T2.F','T2.O','T2.RD','T2.Q',
                'T3.R','T3.DF','T3.T','T3.TG','T3.W','T3.S','T3.A','T3.F','T3.O','T3.RD','T3.Q',
                'T4.R','T4.DF','T4.T','T4.TG','T4.W','T4.S','T4.A','T4.F','T4.O','T4.RD','T4.Q',
                'T5.R','T5.DF','T5.T','T5.TG','T5.W','T5.S','T5.A','T5.F','T5.O','T5.RD','T5.Q',
                'T6.R','T6.DF','T6.T','T6.TG','T6.W','T6.S','T6.A','T6.F','T6.O','T6.RD','T6.Q',
                'T7.R','T7.DF','T7.T','T7.TG','T7.W','T7.S','T7.A','T7.F','T7.O','T7.RD','T7.Q',
                'U1.R','U1.DF','U1.T','U1.TG','U1.IPL','U1.UN','U1.RIPL','U1.RID','U1.RIPCK','U1.RUCK','U1.RUD',
                'IE.R','IE.DFI','IE.T','IE.TG','IE.CD']

    count=1
    f_added=0
    f_skipped=0
    comb_added=0
    comb_skipped=0
    classes_skipped=[]

    if debug:
            print("Fingerprint number -> ")

    for fingerprint in fingerprints:
    
        aux1, aux2, aux3, aux4, aux5 = _parse_fingerprint(fingerprint.splitlines(),dataset,max_comb,classes)
        f_added+=aux1
        f_skipped+=aux2
        comb_added+=aux3
        comb_skipped+=aux4
        for value in aux5:
            classes_skipped.append(value) 
        count+=1
        
        if debug:
            if count % 300 == 0:
                print("{}  ".format(count),end='')

    if debug:
        print(f'\n{"Fingerprint parser DONE": <200} ')
        _debug_output(dataset,f_added,f_skipped,comb_added,comb_skipped,classes_skipped)

    column_names = _expand_columns(column_names,dataset)

    return dataset, column_names


# %%
def parse_in_classes(filepath):
    with open(filepath, 'r') as database_file:
        classes = database_file.read().split('\n')

        in_classes=[]
        for clas in classes:
            in_classes.append(clas)

    return in_classes
