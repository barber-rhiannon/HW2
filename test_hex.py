from AES import aes_encrypt_block

def hex_to_bytes(hex_string):
    return [int(hex_string[i:i+2], 16) for i in range(0, len(hex_string), 2)]

def bytes_to_hex(byte_list):
    return ''.join(f"{b:02x}" for b in byte_list)

plaintext_hex = "00112233445566778899aabbccddeeff"
key_hex =        "000102030405060708090a0b0c0d0e0f"

plaintext_bytes = hex_to_bytes(plaintext_hex)
key_bytes = hex_to_bytes(key_hex)

ciphertext = aes_encrypt_block(plaintext_bytes, key_bytes)

print("Testing AES With Hexadecimal Inputs")
print()
print("Plaintext (hex):")
print(plaintext_hex)
print()
print("Key (hex):")
print(key_hex)
print()
print("Ciphertext Produced by AES Implementation (hex):")
print(bytes_to_hex(ciphertext))
