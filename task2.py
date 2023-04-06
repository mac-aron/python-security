from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

def DHandEncrypt(A_Private_Key, B_Private_Key, PlainText):
    
    # [1] load the passed keys into PEM format
    a_private_key_pem = serialization.load_pem_private_key(A_Private_Key, password=None)
    b_private_key_pem = serialization.load_pem_private_key(B_Private_Key, password=None)

    # [2] get the shared keys from each other's public keys
    #     a <exchanges> b
    #     b <exchanges> a
    a_shared_key = a_private_key_pem.exchange(b_private_key_pem.public_key())
    b_shared_key = b_private_key_pem.exchange(a_private_key_pem.public_key())

    # [3] make sure the keys are the same, if not raise exception
    if a_shared_key != b_shared_key:
        raise Exception("[!] Shared keys are not the same")

    # [4] set the key derivation configuration, and derive the key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32, 
        salt=None, 
        info=b'handshake data'
    ).derive(a_shared_key)

    # [5] edge cases (two of them) MUST be considered - when the plaintext is 
    #     longer than the key, repeat the key so that it is at least the size
    #     of the plaintext string (notice the +1 to ensure that the key is 
    #     always longer than the plaintext)
    LPT = len(PlainText)  
    derived_key *= (LPT // len(derived_key) + 1)
    LDK = len(derived_key)

    # [6] use the derived key to encrypt the finite plain text using XOR
    iter = zip(PlainText, derived_key)
    cipher_text = bytes([b1 ^ b2 for b1, b2 in iter])
    
    # [7] get the original key (avoid repeating key, in edge cases)
    original_key = (derived_key * (LPT // LDK + 1))[:LPT]

    # [8] return the original key and the encrypted ciphertext
    return original_key, cipher_text

if __name__ == "__main__":

    A_PRIVATE_KEY = b'-----BEGIN PRIVATE KEY-----\nMIGcAgEAMFMGCSqGSIb3DQEDATBGAkEAlry2DwPC+pK/0QiOicVAtt6ANsfjmD9P\nQrDC6ZkYcrRf0q0RVzMDTnHWk1mRLVvb6av4HOSkIsk1mMogBcqV0wIBAgRCAkBm\nZK4qUqvU6WaPy4fNG9oWIXchxzztxmA7p9BFXbMzn3rHcW84SDwTWXAjkRd35XPV\n/9RAl06sv191BNFFPyg0\n-----END PRIVATE KEY-----\n'
    B_PRIVATE_KEY = b'-----BEGIN PRIVATE KEY-----\nMIGcAgEAMFMGCSqGSIb3DQEDATBGAkEAlry2DwPC+pK/0QiOicVAtt6ANsfjmD9P\nQrDC6ZkYcrRf0q0RVzMDTnHWk1mRLVvb6av4HOSkIsk1mMogBcqV0wIBAgRCAkBn\n9zn/q8GMs7SJjZ+VLlPG89bB83Cn1kDRmGEdUQF3OSZWIdMAVJb1/xaR4NAhlRya\n7jZHBW5DlUF5rrmecN4A\n-----END PRIVATE KEY-----\n'

    PlainText = b"Encrypt me with the derived key!" # 32 bytes
    # PlainText = b"1"
    # PlainText = b"Encrypt me with the derived key!Encrypt me with the derived key!"

    STD_KEY, STD_CIPHER = DHandEncrypt(A_PRIVATE_KEY, B_PRIVATE_KEY, PlainText)
    print(STD_CIPHER)
    # print(STD_KEY)

