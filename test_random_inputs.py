import random
from AES import aes_encrypt_block

def random_bytes(n):
    return [random.randint(0,255) for _ in range(n)]

for test_index in range(5):
    plaintext = random_bytes(16)
    key = random_bytes(16)
    ciphertext = aes_encrypt_block(plaintext, key)

    print("Random AES Encryption Test #", test_index + 1)
    print("Generated Random Plaintext:")
    print([hex(x) for x in plaintext])
    print()
    print("Generated Random Cipher Key:")
    print([hex(x) for x in key])
    print()
    print("Ciphertext Produced by AES Implementation:")
    print([hex(x) for x in ciphertext])
    print()
    print("End of Test #", test_index + 1)
    print("-" * 60)
