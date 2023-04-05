# %%
def _parse_label(line,i):
    aux = line.replace("label = ","").replace("\n","").split(":")
    
    result = []
    
    result.append(aux[2])
    result.append(aux[3])
    
    # if len(result) != 4:
    #     raise Exception("Error at line "+str(i)+", label with no compatible lenght\n"+line)
    return result

# %%
def _parse_sig(line,i): 
    aux = line.replace("sig   = ","").replace("\n","").split(":")
    
    result = []
    
    # IP version - not used
    # result.append(aux[0])
    
    # initial TTL
    result.append(int(aux[1]))
    
    # IP options lenght - not used
    #result.append(int(aux[2]))
    
    # MSS
    result.append(aux[3]) 
    # PENDING - in the traffic it will be always included, but in the
    # database sometimes is not -> ¿how to encode this, which means that it can be any value?
    # * -> any
    # numeric value (9 different values, codify as classes?)
    
    wsize,wscale = aux[4].split(",")
    
    # Window Size
    result.append(wsize)
    # PENDING 
    # * -> any
    # numeric value
    # product factor
    
    # Window Scale
    result.append(wscale)
    # PENDING 
    # * -> any
    # numeric value
    
    # TCP options
    result.append(aux[5])
    # PENDING 
    # Predefined set of ORDERED values
    
    # Quirks
    df = 0
    id = 0
    ts = 0
    if 'df' in aux[6]:
        df = 1
    if 'id' in aux[6]:
        id = 1
    if 'ts' in aux[6]:
        ts = 1
    result.append(df)
    result.append(id)
    result.append(ts)
        
    # Payload lenght - not used
    # result.append(aux[7])
    
    # if len(result) != 9:
    #     raise Exception("Error at line "+str(i)+", signature with no compatible lenght\n"+line)
    return result
    
# %%
def parse_database(filepath):

    with open(filepath, 'r') as database_file:
        dataset = []
        
        count=0
        request=False
        response=False
        parsing_label=False
        current_label=None
        current_sig=None
        
        i=0
        while True:
            i += 1
            line = database_file.readline()
            
            if not line:
                break 
            if line == "" or line == "\n" or line.startswith(";"):
                continue
            if line.startswith("[tcp:request]"):
                request=True
                response=False
                parsing_label=False
                continue
            if line.startswith("[tcp:response]"):
                response=True
                request=False
                parsing_label=False
                continue
            
            if parsing_label:
                if line.startswith("sig"):
                    current_sig=_parse_sig(line,i)
                    
                    if request and not response:
                        row = ['request']+current_label+current_sig
                    elif response and not request:
                        row = ['response']+current_label+current_sig
                    else:
                        raise Exception("Error at line "+str(i)+"\n"+line)
                    
                    dataset.append(row)
                    
                    count += 1
                    continue
                elif line.startswith("label"):
                    parsing_label=False
                else:
                    raise Exception("Error at line "+str(i)+"\n"+line)
            
            if line.startswith("label"):
                current_label=_parse_label(line,i)
                parsing_label=True
                continue
            else: 
                raise Exception("Error at line "+str(i)+"\n"+line)

    column_names = ['sig_direction','os','version','initial_ttl',
                    'mss','window_size','window_scaling','tcp_options',
                    'quirk_df','quirk_id','quirk_ts']
    
    # print("Signatures saved: "+str(count))
    # print("Dataset lenght "+str(len(dataset)))

    return dataset,column_names
# %%
