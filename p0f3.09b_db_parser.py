# %%
def _parse_label(line,i):
    result = line.replace("label = ","").replace("\n","").split(":")
    if len(result) != 4:
        raise Exception("Error at line "+str(i)+", label with no compatible lenght\n"+line)
    return result

# %%
def _parse_sig(line,i): 
    aux = line.replace("sig   = ","").replace("\n","").split(":")
    result = aux[0:4]+aux[4].split(",")+aux[5:]
    if len(result) != 9:
        raise Exception("Error at line "+str(i)+", signature with no compatible lenght\n"+line)
    return result
    
# %%
def parse_database(filepath):

    with open(filepath, 'r') as database_file:
        dataset_request = []
        dataset_response = []
        
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
                    row = current_label+current_sig
                    
                    if request and not response:
                        dataset_request.append(row)
                    elif response and not request:
                        dataset_response.append(row)
                    else:
                        raise Exception("Error at line "+str(i)+"\n"+line)
                    
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

    print("Signatures saved: "+str(count))
    print("")
    print("DATASET REQUEST")
    print("Dataset lenght "+str(len(dataset_request)))
    print("")
    print("DATASET RESPONSE")
    print("Dataset lenght "+str(len(dataset_response)))

    return dataset_request, dataset_response

parse_database("./p0f-3.09b.fp")
# %%
