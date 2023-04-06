from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
def AES_CTR_Encrypt(key, nonce_counter, data):

    key = bytes.fromhex(key) 
    nonce_counter = bytes.fromhex(nonce_counter)

    # get the block size of ECB encryption
    blockSize = algorithms.AES.block_size
    nonceBlock = nonce_counter.ljust(blockSize, b'\x00')

    # changing the mod to ECB here
    aesCipher = Cipher(algorithms.AES(key), modes.ECB())
    aesEncryptor = aesCipher.encryptor()

    blockCounter = 0
    result = b''

    # divide the data in 16 bytes blocks
    for i in range(0, len(data), blockSize):

        #separation of data
        dataBlock = data[i:i+16]

        # getting the right nonce block
        # as we loop through it, we convert the bock to int, 
        # add the additional block size and counter then transform it back to bytes

        intBlock = int.from_bytes(nonceBlock, 'big')
        nonceBlock = int.to_bytes(intBlock + blockCounter, blockSize, 'big')


        cipherText = aesEncryptor.update(nonceBlock)

        # XOR 
        result = bytes(b ^ c for b, c in zip(dataBlock, cipherText))

    return result

if __name__ == "__main__":
	key = '0000000000000000000000000000000000000000000000000000000000000000'
	nonce_counter = '00000000000000000000000000000000'
	data = b"Hello world!"
	result = AES_CTR_Encrypt(key, nonce_counter, data)
	print(result)