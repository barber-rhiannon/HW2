from AES import aes_encrypt_block

plaintext = [
    0x00,0x11,0x22,0x33,
    0x44,0x55,0x66,0x77,
    0x88,0x99,0xaa,0xbb,
    0xcc,0xdd,0xee,0xff
]

key = [
    0x00,0x01,0x02,0x03,
    0x04,0x05,0x06,0x07,
    0x08,0x09,0x0a,0x0b,
    0x0c,0x0d,0x0e,0x0f
]

expected_ciphertext = [
    0x69,0xc4,0xe0,0xd8,
    0x6a,0x7b,0x04,0x30,
    0xd8,0xcd,0xb7,0x80,
    0x70,0xb4,0xc5,0x5a
]

ciphertext = aes_encrypt_block(plaintext, key)

print("Testing AES Encryption Using Official NIST Known Answer Test (KAT)")
print()
print("Input Plaintext (16 bytes):")
print([hex(x) for x in plaintext])
print()
print("Input Cipher Key (16 bytes):")
print([hex(x) for x in key])
print()
print("Produced Ciphertext from AES Implementation:")
print([hex(x) for x in ciphertext])
print()
print("Expected Ciphertext According to NIST Standard:")
print([hex(x) for x in expected_ciphertext])
print()
print("Does the produced ciphertext match the NIST expected value?")
print(ciphertext == expected_ciphertext)
