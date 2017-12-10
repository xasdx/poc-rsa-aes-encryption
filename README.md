# poc-rsa-aes-encryption

> POC demonstrating a hybrid encryption strategy using RSA and AES standards

The algorithm uses a randomly generated AES key to encrypt the plaintext, then encrypts the AES symmetric key with an RSA public key. Finally it assembles an object containing the base64 encoded version of the ciphertext and encrypted symmetric key.
