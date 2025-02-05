## Overview of AES-256 Implementation

As part of my deep dive into cryptography and secure computing, I implemented the **Advanced Encryption Standard (AES-256)** algorithm in Python. This project focuses on encrypting and decrypting messages using a **256-bit key**, adhering to the AES encryption standard.

## Implementation details for Plaintext Encryption:
- **Object-Oriented Python Implementation**: Designed an `AES` class that efficiently performs encryption and decryption operations.
- **Key Expansion for 256-bit Key**: Implemented a key schedule to handle the 256-bit key, ensuring correct generation of round keys.
- **Encryption Pipeline**:
  1. Byte Substitution (S-Box)
  2. Row Shuffling (ShiftRows)
  3. Column Mixing (MixColumns)
  4. XOR with Round Key (AddRoundKey)
  5. 14 Rounds of Processing (as per AES-256 standard)
- **Decryption Pipeline**:
  - Implemented the inverse operations to recover the original plaintext.
  - Ensured the correct reversion of MixColumns and ShiftRows.
- **Command-Line Interface**:
  - Encrypt: `python3 AES.py -e message.txt key.txt encrypted.txt`
  - Decrypt: `python3 AES.py -d encrypted.txt key.txt decrypted.txt`
- **Padding Handling**:
  - Managed cases where plaintext length isn’t a multiple of the block size by applying padding.

## Implementation details for Image Encryption using Counter Mode:
- **Modified AES Class**:
  - Added a new method: `ctr_aes_image(self, iv, image_file, enc_image)`.
  - Utilized **AES in CTR mode** to encrypt an image file (`.ppm` format).
  - Ensured the **encrypted image remains viewable**, preserving the image header.
- **Counter Mode Initialization**:
  - Used a **fixed initialization vector (IV)**: ASCII encoding of `'counter-mode-ctr'`.
  - Each plaintext block was XOR-ed with AES-encrypted counter values.
- **Optimized File Handling**:
  - Wrote **encrypted image data directly to the file** to optimize performance.
  - Avoided storing large encrypted image data in memory.
- **Command-Line Execution**:
  - `python3 AES.py -i image.ppm key.txt enc_image.ppm`
- **Security Enhancements**:
  - Unlike ECB mode, **CTR mode prevents patterns from being visible in encrypted images**, ensuring greater confidentiality.

## Implementation details for **ANSI X9.31 Cryptographically Secure PRNG (CSPRNG)**

- **Modified AES Class**:
  - Added a new method: `x931(self, v0, dt, totalNum, outfile)`.
  - Used **AES (instead of the older 3DES standard)** to encrypt **128-bit vectors**.
- **Working Mechanism**:
  - Utilized an **initial seed value (`v0`)** and a **date/time value (`dt`)**.
  - Generated **pseudo-random numbers** based on iterative AES encryption.
- **Fixed Testing Parameters**:
  - `v0` = `'counter-mode-ctr'` (as a **BitVector**).
  - `dt` = `501` (as a **128-bit BitVector**).
  - Produced **five cryptographically secure numbers**.
- **Command-Line Execution**:
  - `python3 AES.py -r 5 key.txt random_numbers.txt`

## Results
Successfully Implemented:
1. **Secure encryption techniques (AES / AES-CTR mode)**
2. **Pseudo-random number generation for cryptographic security (ANSI)**

**Generated Random Numbers**:
  - 331374527193731622526773163027689011175
  - 26263303708022960927873924862754889187
  - 6213881104399286406150948824157995508
  - 317525806849049200816126045738729418009
  - 240080400546264647934751409092776671804

**Plain Image**


<img src="https://github.com/KabirBatra06/AES-Encryption/blob/main/image.jpg" width="500" title="Frame A">

**Encrypted Image** 


<img src="https://github.com/KabirBatra06/AES-Encryption/blob/main/enc_image.jpg" width="500" title="Frame A">


