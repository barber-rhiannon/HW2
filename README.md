```
Author: Rhiannon Barber
Date: Nov. 24, 2025
```

# AES Implementation

## Overview
This repository contains a modular implementation of the Advanced Encryption Standard (AES). 
The implementation is written in Python, using the Pycharm IDE, without the use of external libraries (per the instruction PDF). 

---


### `AES.py`
Contains the AES encryption routine and all core transformations.  
Includes:
- State initialization
- SubBytes
- ShiftRows
- MixColumns
- AddRoundKey
- AES Key Expansion
- Final ciphertext construction
- AES Decryption using inverse transformations
- Round-state extraction for observing intermediate AES states
- Avalanche demonstration function for analyzing bit-level diffusion across AES rounds

### `tables.py`
Contains the AES S-box and Rcon tables used for substitution and key expansion. These values are stored separately to maintain clarity and modularity.

### `test_nist.py`
Runs the official AES Known Answer Test (KAT) published by NIST. This verifies that the implementation produces the expected ciphertext for a standard plaintext-key pair.

### `test_random_inputs.py`
Runs several randomized encryption tests to ensure the implementation behaves correctly with arbitrary but valid inputs.

### `test_hex.py`
Allows testing AES encryption using plaintext and key values provided as hexadecimal strings. This is useful for validating the implementation against external AES tools.

### `test_invalid_inputs.py`
Tests how the implementation behaves when provided with invalid input sizes or values. This is helpful for assessing robustness, and for evaluating student submissions.

### 'test_integration.py'
Integration testing suite to test the full functionality of the AES.py script. 

### 'test_unit.py'
Unit testing suite to test the individual functionality of the AES.py script. 

---




