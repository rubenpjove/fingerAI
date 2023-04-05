# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'

import random
import sys
import numpy as np
import re

# %%
def string_to_hex (string):
    try:
        x = int(string, 16)
    except:
        ValueError("Hex value cannot be casted")
    return x

# %%
def hex_value (string):
    if "-" in string:
        values = string.split("-")
        if values[0]==values[1]:
            return string_to_hex(values[0])
        else:
            return (string_to_hex(values[0]),string_to_hex(values[1]))
        # return [string_to_hex(values[0]),string_to_hex(values[1])]
        # return random.randint(string_to_hex(values[0]),string_to_hex(values[1]))
    elif ">" in string : # FEW CASES
        return string_to_hex(string[1:])
        # return (">",string_to_hex(string[1:]))
        # return [string_to_hex(string[1:]),sys.maxsize]
        # return string_to_hex(string[1:])
        #return random.randint(string_to_hex(string[1:]),sys.maxsize)
    elif "<" in string: # NOT EXIST
        return ("<",string_to_hex(string[1:]))
        # return [-1,string_to_hex(string[1:])]
        # return string_to_hex(string[1:])
        # return random.randint(-1,string_to_hex(string[1:]))
    elif string == "":
        return -1
    else:
        return string_to_hex(string)

# %%
def TI_CI_II (string):
    # if string == "Z":
    #     return [1,-1]
    # elif string == "RD":
    #     return [2,-1]
    # elif string == "RI":
    #     return [3,-1]
    # elif string == "BI":
    #     return [4,-1]
    # elif string == "I":
    #     return [5,-1]
    # elif string == "":
    #     return [-1,-1]
    # else:
    #     return [-1,hex_value(string)]
    if string == "Z":
        return "Z"
    elif string == "RD":
        return "RD"
    elif string == "RI":
        return "RI"
    elif string == "BI":
        return "BI"
    elif string == "I":
        return "I"
    elif string == "":
        return ""
    else:
        return hex_value(string)

# %%
def SS (string):
    # if string == "S":
    #     return 1
    # elif string == "O":
    #     return 2
    # elif string == "":
    #     return -1
    # else:
    #     raise ValueError("SS test does not contain a valid value")
    if string == "S":
        return "S"
    elif string == "O":
        return "O"
    elif string == "":
        return ""
    else:
        raise ValueError("SS test does not contain a valid value")

# %%
def TS (string):
    # if string == "U":
    #     return [1,-1]
    # elif string == "-1":
    #     return [2,-1]
    # elif string == "":
    #     return [-1,-1]
    # else:
    #     return [-1,hex_value(string)]
    if string == "U":
        return "U"
    elif string == "-1":
        return "-1"
    elif string == "":
        return ""
    else:
        return hex_value(string)

# %%
def O (string):
    # if string == "":
    #     return [-1,-1,-1,-1,-1,-1]
    # else:
    #     return [string.count("L"),
    #             string.count("N"),
    #             string.count("M"),
    #             string.count("W"),
    #             string.count("T"),
    #             string.count("S")]

    # if string == "":
    #     return -1
    # else:
    #     result = []
    #     for letter in string:
    #         if letter == "L":
    #             result.append(1)
    #         if letter == "N":
    #             result.append(2)
    #         if letter == "M":
    #             result.append(3)
    #         if letter == "W":
    #             result.append(4)
    #         if letter == "T":
    #             result.append(5)
    #         if letter == "S":
    #             result.append(6)
    #     return result
    splitted = re.split("([L|N|M|W|T|S])", string)
    splitted = [i for i in splitted if i != ""]
    
    if string == "":
        return ""
    else:
        result = []
        for i in range(len(splitted)):
            item = splitted[i]
            if item == "L":
                result.append("eol")
            if item == "N":
                result.append("nop")
            if item == "M":
                i += 1
                result.append("mss."+str(string_to_hex(splitted[i])))
            if item == "W":
                i += 1
                result.append("ws."+str(string_to_hex(splitted[i])))
            if item == "T":
                i += 1
                result.append("ts."+splitted[i])
            if item == "S":
                result.append("sok")
    return ','.join(result)

# %%
def Y_N (string):
    # if string == "Y":
    #     return 1
    # elif string == "N":
    #     return 2
    # elif string == "":
    #     return -1
    # else:
    #     raise ValueError("A test with Y/N response does not contain a valid value")
    if string == "Y":
        return "Y"
    elif string == "N":
        return "N"
    elif string == "":
        return ""
    else:
        raise ValueError("A test with Y/N response does not contain a valid value")
    
# %%
def CC (string):
    # if string == "Y":
    #     return 1
    # elif string == "N":
    #     return 2
    # elif string == "S":
    #     return 3
    # elif string == "O":
    #     return 4
    # elif string == "":
    #     return -1
    # else:
    #     raise ValueError("A test with Y/N response does not contain a valid value")
    if string == "Y":
        return "Y"
    elif string == "N":
        return "N"
    elif string == "S":
        return "S"
    elif string == "O":
        return "O"
    elif string == "":
        return ""
    else:
        raise ValueError("A test with Y/N response does not contain a valid value")

# %%
def Q (string):
    # response = [-1,-1]
    # if "R" in string:
    #     response[-1] = 1
    # if "U" in string:
    #     response[1] = 1

    # return response

    return string

# %%
def S (string):
    # if string == "Z":
    #     return 1
    # elif string == "A":
    #     return 2
    # elif string == "A+":
    #     return 3
    # elif string == "O":
    #     return 4
    # elif string == "":
    #     return -1
    # else:
    #     raise ValueError("The test S response does not contain a valid value")
    if string == "Z":
        return "Z"
    elif string == "A":
        return "A"
    elif string == "A+":
        return "A+"
    elif string == "O":
        return "O"
    elif string == "":
        return ""
    else:
        raise ValueError("The test S response does not contain a valid value")

# %%
def A (string):
    # if string == "Z":
    #     return 1
    # elif string == "S":
    #     return 2
    # elif string == "S+":
    #     return 3
    # elif string == "O":
    #     return 4
    # elif string == "":
    #     return -1
    # else:
    #     raise ValueError("The test A response does not contain a valid value")
    if string == "Z":
        return "Z"
    elif string == "S":
        return "S"
    elif string == "S+":
        return "S+"
    elif string == "O":
        return "0"
    elif string == "":
        return ""
    else:
        raise ValueError("The test A response does not contain a valid value")

# %%
def F (string):
    # response = [-1,-1,-1,-1,-1,-1,-1]
    # if "E" in string:
    #     response[-1] = 1
    # if "U" in string:
    #     response[1] = 1
    # if "A" in string:
    #     response[2] = 1
    # if "P" in string:
    #     response[3] = 1
    # if "R" in string:
    #     response[4] = 1
    # if "S" in string:
    #     response[5] = 1
    # if "F" in string:
    #     response[6] = 1

    # return response
    return string

# %%
def RIPL_RID_RUCK (string):
    # if string == "G":
    #     return [1,-1]
    # elif string == "":
    #     return [-1,-1]
    # else:
    #     return [-1,hex_value(string)]
    if string == "G":
        return "G"
    elif string == "":
        return ""
    else:
        return hex_value(string)

# %%
def RIPCK (string):
    # if string == "G":
    #     return 1
    # elif string == "Z":
    #     return 2
    # elif string == "I":
    #     return 3
    # elif string == "":
    #     return -1
    # else:
    #     raise ValueError("The test RIPCK response does not contain a valid value")
    if string == "G":
        return "G"
    elif string == "Z":
        return "Z"
    elif string == "I":
        return "I"
    elif string == "":
        return ""
    else:
        raise ValueError("The test RIPCK response does not contain a valid value")

# %%
def RUD (string):
    # if string == "G":
    #     return 1
    # elif string == "I":
    #     return 2
    # elif string == "":
    #     return -1
    # else:
    #     raise ValueError("The test RUD response does not contain a valid value")
    if string == "G":
        return "G"
    elif string == "I":
        return "I"
    elif string == "":
        return ""
    else:
        raise ValueError("The test RUD response does not contain a valid value")

# %%
def DFI (string):
    # if string == "N":
    #     return 1
    # elif string == "S":
    #     return 2
    # elif string == "Y":
    #     return 3
    # elif string == "O":
    #     return 4
    # elif string == "":
    #     return -1
    # else:
    #     raise ValueError("The test DFI response does not contain a valid value")
    if string == "N":
        return "N"
    elif string == "S":
        return "S"
    elif string == "Y":
        return "Y"
    elif string == "O":
        return "O"
    elif string == "":
        return ""
    else:
        raise ValueError("The test DFI response does not contain a valid value")

# %%
def CD (string):
    # if string == "Z":
    #     return [1,-1]
    # elif string == "S":
    #     return [2,-1]
    # elif string == "O":
    #     return [3,-1]
    # elif string == "":
    #     return [-1,-1]
    # else:
    #     return [-1,hex_value(string)]
    if string == "Z":
        return "Z"
    elif string == "S":
        return "S"
    elif string == "O":
        return "O"
    elif string == "":
        return ""
    else:
        return hex_value(string)