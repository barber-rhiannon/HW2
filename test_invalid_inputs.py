from AES import aes_encrypt_block

def run_test(description, plaintext, key):
    print(description)
    try:
        result = aes_encrypt_block(plaintext, key)
        print("Output Ciphertext:", [hex(x) for x in result])
    except Exception as e:
        print("Error Raised:", str(e))
    print("-" * 60)

run_test(
    "Test: Plaintext shorter than 16 bytes",
    [0x01, 0x02],
    [0x00] * 16
)

run_test(
    "Test: Plaintext longer than 16 bytes",
    [0x00] * 20,
    [0x00] * 16
)

run_test(
    "Test: Key shorter than 16 bytes",
    [0x00] * 16,
    [0x01]
)

run_test(
    "Test: Key longer than 16 bytes",
    [0x00] * 16,
    [0x00] * 20
)

run_test(
    "Test: Values outside valid 0-255 byte range",
    [999] * 16,
    [0x00] * 16
)
