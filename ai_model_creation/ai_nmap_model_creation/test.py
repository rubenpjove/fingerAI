import re

def string_to_hex (string):
    try:
        x = int(string, 16)
    except:
        ValueError("Hex value cannot be casted")
    return x

string = "M5B4NW3NNT11"
result = []

