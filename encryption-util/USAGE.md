# Encryption Utility Command Reference

## Supported Algorithms and Modes

| Algorithm          | Modes             | Paddings               | Key Lengths (bits) | IV Required | Notes                      |
|---------------------|-------------------|------------------------|--------------------|-------------|----------------------------|
| AES                | ECB,CBC,CFB,OFB,GCM | PKCS5Padding, PKCS7Padding, NoPadding | 128,192,256 | Yes (except ECB) | GCM requires 12-byte IV    |
| DES                | ECB,CBC,CFB,OFB    | PKCS5Padding, PKCS7Padding, NoPadding | 64          | Yes (except ECB) |                            |
| DESede (3DES)      | ECB,CBC,CFB,OFB    | PKCS5Padding, PKCS7Padding, NoPadding | 128,192     | Yes (except ECB) |                            |
| Blowfish           | ECB,CBC,CFB,OFB    | PKCS5Padding, PKCS7Padding, NoPadding | 32-448 (8 increments) | Yes (except ECB) |                            |
| RC2                | ECB,CBC,CFB,OFB    | PKCS5Padding, PKCS7Padding, NoPadding | 8-1024 (8 increments) | Yes (except ECB) |                            |
| ChaCha20           | N/A               | N/A                    | 256         | Yes          | 12-byte IV required        |
| ChaCha20-Poly1305  | N/A               | N/A                    | 256         | Yes          | 12-byte IV required        |

## Command Structure

```
Encryption:
java -jar EncryptionUtility.jar enc <algorithm> <data> <key> <iv> <mode> <padding> <keyFormat> <ivFormat> <outputFormat>

Decryption:
java -jar EncryptionUtility.jar dec <algorithm> <data> <key> <iv> <mode> <padding> <keyFormat> <ivFormat> <outputFormat>
```

## Valid Combinations

### Symmetric Algorithms
#### AES
| Mode | Padding       | Example Encryption Command                                                                 |
|------|---------------|-------------------------------------------------------------------------------------------|
| ECB | PKCS5Padding | `java -jar EncryptionUtility.jar enc AES "data" <key> '' ECB PKCS5Padding hex hex base64` |
| ECB | PKCS7Padding | `java -jar EncryptionUtility.jar enc AES "data" <key> '' ECB PKCS7Padding hex hex base64` |
| ECB | NoPadding | `java -jar EncryptionUtility.jar enc AES "data" <key> '' ECB NoPadding hex hex base64` |
| CBC | PKCS5Padding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> CBC PKCS5Padding hex hex base64` |
| CBC | PKCS7Padding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> CBC PKCS7Padding hex hex base64` |
| CBC | NoPadding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> CBC NoPadding hex hex base64` |
| CFB | PKCS5Padding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> CFB PKCS5Padding hex hex base64` |
| CFB | PKCS7Padding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> CFB PKCS7Padding hex hex base64` |
| CFB | NoPadding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> CFB NoPadding hex hex base64` |
| OFB | PKCS5Padding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> OFB PKCS5Padding hex hex base64` |
| OFB | PKCS7Padding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> OFB PKCS7Padding hex hex base64` |
| OFB | NoPadding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> OFB NoPadding hex hex base64` |
| GCM | PKCS5Padding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> GCM PKCS5Padding hex hex base64` |
| GCM | PKCS7Padding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> GCM PKCS7Padding hex hex base64` |
| GCM | NoPadding | `java -jar EncryptionUtility.jar enc AES "data" <key> <iv> GCM NoPadding hex hex base64` |

#### DES
| Mode | Padding       | Example Encryption Command                                                                 |
|------|---------------|-------------------------------------------------------------------------------------------|
| ECB | PKCS5Padding | `java -jar EncryptionUtility.jar enc DES "data" <key> '' ECB PKCS5Padding hex hex base64` |
| ECB | PKCS7Padding | `java -jar EncryptionUtility.jar enc DES "data" <key> '' ECB PKCS7Padding hex hex base64` |
| ECB | NoPadding | `java -jar EncryptionUtility.jar enc DES "data" <key> '' ECB NoPadding hex hex base64` |
| CBC | PKCS5Padding | `java -jar EncryptionUtility.jar enc DES "data" <key> <iv> CBC PKCS5Padding hex hex base64` |
| CBC | PKCS7Padding | `java -jar EncryptionUtility.jar enc DES "data" <key> <iv> CBC PKCS7Padding hex hex base64` |
| CBC | NoPadding | `java -jar EncryptionUtility.jar enc DES "data" <key> <iv> CBC NoPadding hex hex base64` |
| CFB | PKCS5Padding | `java -jar EncryptionUtility.jar enc DES "data" <key> <iv> CFB PKCS5Padding hex hex base64` |
| CFB | PKCS7Padding | `java -jar EncryptionUtility.jar enc DES "data" <key> <iv> CFB PKCS7Padding hex hex base64` |
| CFB | NoPadding | `java -jar EncryptionUtility.jar enc DES "data" <key> <iv> CFB NoPadding hex hex base64` |
| OFB | PKCS5Padding | `java -jar EncryptionUtility.jar enc DES "data" <key> <iv> OFB PKCS5Padding hex hex base64` |
| OFB | PKCS7Padding | `java -jar EncryptionUtility.jar enc DES "data" <key> <iv> OFB PKCS7Padding hex hex base64` |
| OFB | NoPadding | `java -jar EncryptionUtility.jar enc DES "data" <key> <iv> OFB NoPadding hex hex base64` |

#### DESede
| Mode | Padding       | Example Encryption Command                                                                 |
|------|---------------|-------------------------------------------------------------------------------------------|
| ECB | PKCS5Padding | `java -jar EncryptionUtility.jar enc DESede "data" <key> '' ECB PKCS5Padding hex hex base64` |
| ECB | PKCS7Padding | `java -jar EncryptionUtility.jar enc DESede "data" <key> '' ECB PKCS7Padding hex hex base64` |
| ECB | NoPadding | `java -jar EncryptionUtility.jar enc DESede "data" <key> '' ECB NoPadding hex hex base64` |
| CBC | PKCS5Padding | `java -jar EncryptionUtility.jar enc DESede "data" <key> <iv> CBC PKCS5Padding hex hex base64` |
| CBC | PKCS7Padding | `java -jar EncryptionUtility.jar enc DESede "data" <key> <iv> CBC PKCS7Padding hex hex base64` |
| CBC | NoPadding | `java -jar EncryptionUtility.jar enc DESede "data" <key> <iv> CBC NoPadding hex hex base64` |
| CFB | PKCS5Padding | `java -jar EncryptionUtility.jar enc DESede "data" <key> <iv> CFB PKCS5Padding hex hex base64` |
| CFB | PKCS7Padding | `java -jar EncryptionUtility.jar enc DESede "data" <key> <iv> CFB PKCS7Padding hex hex base64` |
| CFB | NoPadding | `java -jar EncryptionUtility.jar enc DESede "data" <key> <iv> CFB NoPadding hex hex base64` |
| OFB | PKCS5Padding | `java -jar EncryptionUtility.jar enc DESede "data" <key> <iv> OFB PKCS5Padding hex hex base64` |
| OFB | PKCS7Padding | `java -jar EncryptionUtility.jar enc DESede "data" <key> <iv> OFB PKCS7Padding hex hex base64` |
| OFB | NoPadding | `java -jar EncryptionUtility.jar enc DESede "data" <key> <iv> OFB NoPadding hex hex base64` |

#### Blowfish
| Mode | Padding       | Example Encryption Command                                                                 |
|------|---------------|-------------------------------------------------------------------------------------------|
| ECB | PKCS5Padding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> '' ECB PKCS5Padding hex hex base64` |
| ECB | PKCS7Padding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> '' ECB PKCS7Padding hex hex base64` |
| ECB | NoPadding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> '' ECB NoPadding hex hex base64` |
| CBC | PKCS5Padding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> <iv> CBC PKCS5Padding hex hex base64` |
| CBC | PKCS7Padding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> <iv> CBC PKCS7Padding hex hex base64` |
| CBC | NoPadding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> <iv> CBC NoPadding hex hex base64` |
| CFB | PKCS5Padding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> <iv> CFB PKCS5Padding hex hex base64` |
| CFB | PKCS7Padding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> <iv> CFB PKCS7Padding hex hex base64` |
| CFB | NoPadding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> <iv> CFB NoPadding hex hex base64` |
| OFB | PKCS5Padding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> <iv> OFB PKCS5Padding hex hex base64` |
| OFB | PKCS7Padding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> <iv> OFB PKCS7Padding hex hex base64` |
| OFB | NoPadding | `java -jar EncryptionUtility.jar enc Blowfish "data" <key> <iv> OFB NoPadding hex hex base64` |

#### RC2
| Mode | Padding       | Example Encryption Command                                                                 |
|------|---------------|-------------------------------------------------------------------------------------------|
| ECB | PKCS5Padding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> '' ECB PKCS5Padding hex hex base64` |
| ECB | PKCS7Padding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> '' ECB PKCS7Padding hex hex base64` |
| ECB | NoPadding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> '' ECB NoPadding hex hex base64` |
| CBC | PKCS5Padding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> <iv> CBC PKCS5Padding hex hex base64` |
| CBC | PKCS7Padding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> <iv> CBC PKCS7Padding hex hex base64` |
| CBC | NoPadding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> <iv> CBC NoPadding hex hex base64` |
| CFB | PKCS5Padding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> <iv> CFB PKCS5Padding hex hex base64` |
| CFB | PKCS7Padding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> <iv> CFB PKCS7Padding hex hex base64` |
| CFB | NoPadding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> <iv> CFB NoPadding hex hex base64` |
| OFB | PKCS5Padding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> <iv> OFB PKCS5Padding hex hex base64` |
| OFB | PKCS7Padding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> <iv> OFB PKCS7Padding hex hex base64` |
| OFB | NoPadding | `java -jar EncryptionUtility.jar enc RC2 "data" <key> <iv> OFB NoPadding hex hex base64` |

### Stream Ciphers
#### ChaCha20
- **Modes**: N/A
- **Paddings**: N/A
- Example Encryption:
  `java -jar EncryptionUtility.jar enc ChaCha20 "plaintext" <256-bit-key> <12-byte-iv> '' '' hex hex base64`
  
- Example Decryption:
  `java -jar EncryptionUtility.jar dec ChaCha20 "ciphertext" <256-bit-key> <12-byte-iv> '' '' hex hex plain`

#### ChaCha20-Poly1305
- **Modes**: N/A
- **Paddings**: N/A
- Example Encryption:
  `java -jar EncryptionUtility.jar enc ChaCha20-Poly1305 "plaintext" <256-bit-key> <12-byte-iv> '' '' hex hex base64`
  
- Example Decryption:
  `java -jar EncryptionUtility.jar dec ChaCha20-Poly1305 "ciphertext" <256-bit-key> <12-byte-iv> '' '' hex hex plain`

## Special Notes
1. IV is required for all modes except ECB
2. Key lengths must match algorithm requirements
3. Use hex/base64 for binary data representation
4. ChaCha20 variants don't use padding or mode parameters
