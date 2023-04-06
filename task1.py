# no imports 

def RepeatingXOREncrypt(key, string):
    
    # [1] get the length of the key
    keyLength = len(key)

    # [2] set the key index and an empty string
    keyIndex = 0
    result = ''

    # [3] itterate through every character in the string
    for char in string:

        # [4] format in hex, XOR, and pad with zeros on the left
        result += format(ord(char) ^ ord(key[keyIndex]), 'x').zfill(2)

        # [5] modulus of index increment
        keyIndex = (keyIndex + 1) % keyLength
    
    # [6] return the result
    return result

if __name__ == "__main__":
    # TASK 1
    result = RepeatingXOREncrypt("01", "0123")
    print(result)

    


