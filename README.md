# WorkingFixedLengthAES

A simple Java console application that performs AES encryption and decryption using a fixed IV and a derived key from a user-supplied "shift" value. The program also creates fixed-length encoded versions of encrypted messages for simplified representation.

---

##  Features

- AES encryption/decryption with CBC mode and PKCS5 padding.
- Key generation based on user-defined integer "shift".
- Fixed-length display ciphertext for consistent formatting.
- Internal mapping of display ciphertext to actual encrypted string.
- Console-based interface with options to encrypt, decrypt, or exit.

---

##  Technologies Used

- Java SE
- `javax.crypto` for AES cryptography
- Base64 encoding/decoding
- Simple I/O with `Scanner`

---

# How to Run

### 🛠 Prerequisites

- Java JDK 8 or higher
- A terminal/command prompt

###  Compile

```bash
javac WorkingFixedLengthAES.java
