from AES import (
    aes_encrypt_block,
    aes_decrypt_block,
    demonstrate_avalanche_plaintext
)


def test_nist_primary_vector():
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
    expected = [
        0x69,0xc4,0xe0,0xd8,
        0x6a,0x7b,0x04,0x30,
        0xd8,0xcd,0xb7,0x80,
        0x70,0xb4,0xc5,0x5a
    ]
    assert aes_encrypt_block(plaintext, key) == expected


def test_nist_zero_vector():
    expected = [
        0x66,0xe9,0x4b,0xd4,0xef,0x8a,0x2c,0x3b,
        0x88,0x4c,0xfa,0x59,0xca,0x34,0x2b,0x2e
    ]
    assert aes_encrypt_block([0]*16, [0]*16) == expected


def test_regression_incrementing_plaintext():
    plaintext = list(range(16))
    key = [0x00] * 16

    out1 = aes_encrypt_block(plaintext, key)
    out2 = aes_encrypt_block(plaintext, key)

    assert out1 == out2

    assert out1 != plaintext


def test_consistent_repeated_calls():
    plaintext = [0x10] * 16
    key = [0x20] * 16
    out1 = aes_encrypt_block(plaintext, key)
    out2 = aes_encrypt_block(plaintext, key)
    assert out1 == out2

def test_additional_nist_vector():

    # Tests for the required examples in the PDF.

    plaintext_hex = "0123456789abcdeffedcba9876543210"
    plaintext = [int(plaintext_hex[i:i+2], 16) for i in range(0, 32, 2)]
    key_hex = "0f1571c947d9e8590cb7add6af7f6798"
    key = [int(key_hex[i:i+2], 16) for i in range(0, 32, 2)]

    expected_hex = "ff0b844a0853bf7c6934ab4364148fb9"
    expected = [int(expected_hex[i:i+2], 16) for i in range(0, 32, 2)]

    output = aes_encrypt_block(plaintext, key)

    assert output == expected

def test_encrypt_decrypt_roundtrip():
    plaintext = [i for i in range(16)]
    key = [0x55] * 16
    ciphertext = aes_encrypt_block(plaintext, key)
    recovered = aes_decrypt_block(ciphertext, key)
    assert recovered == plaintext


def test_encrypt_decrypt_roundtrip():
    plaintext = [i for i in range(16)]
    key = [0x55] * 16
    ciphertext = aes_encrypt_block(plaintext, key)
    recovered = aes_decrypt_block(ciphertext, key)
    assert recovered == plaintext
