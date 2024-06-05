# post_quantum

[![plugin version](https://img.shields.io/pub/v/post_quantum?label=pub)](https://pub.dev/packages/post_quantum)
[![likes](https://img.shields.io/pub/likes/post_quantum?logo=dart)](https://pub.dev/packages/post_quantum/score)
[![pub points](https://img.shields.io/pub/points/post_quantum?logo=dart&color=teal)](https://pub.dev/packages/post_quantum/score)
[![popularity](https://img.shields.io/pub/popularity/post_quantum?logo=dart)](https://pub.dev/packages/post_quantum/score)
[![Coverage Status](https://coveralls.io/repos/github/tomasagata/post_quantum/badge.svg)](https://coveralls.io/github/tomasagata/post_quantum)

Dart implementation of NIST's post-quantum algorithm candidates.

## Features

This library includes the following algorithms:
- __Kyber__, a post-quantum Key Encapsulation Mechanism.
- __Dilithium__, a post quantum Signature scheme.

## Usage

### Key Encapsulation with Kyber

```dart
// Instantiate Kyber KEM.
var kyber = Kyber.kem512();

// Define a key generation seed.
var seed = base64Decode("AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8AAQIDBAUGBwgJCgsMDQ4PAAECAwQFBgcICQoLDA0ODw==");

// Generate keys from seed.
var (pk, sk) = kyber.generateKeys(seed);

// Define a KEM nonce.
var nonce = base64Decode("Dw8ODg0NDAwLCwoKCQkICAcHBgYFBQQEAwMCAgEBAAA=");

// Encapsulate nonce and retrieve cipher and shared key.
var (cipher, sharedKey1) = kyber.encapsulate(pk, nonce);

// Or decapsulate the cipher and retrieve the shared key.
var sharedKey2 = kyber.decapsulate(cipher, sk);

```

### Encryption and decryption with the internal Kyber PKE

```dart
// Instantiate Kyber's internal PKE.
var kyber = KyberPKE.pke512();

// Define a key generation seed.
var seed = base64Decode("AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8=");

// Generate keys from seed.
var (pk, sk) = kyber.generateKeys(seed);

// Set the message.
var msg = base64Decode("Dw4NDAsKCQgHBgUEAwIBAA8ODQwLCgkIBwYFBAMCAQA=");

// Define an encryption randomizer.
var coins = base64Decode("Dw8ODg0NDAwLCwoKCQkICAcHBgYFBQQEAwMCAgEBAAA=");

// Encrypt the message with the public key.
var cipher = kyber.encrypt(pk, msg, coins);

// Decrypt the cipher with the private key.
var decryptedMsg = kyber.decrypt(sk, cipher);
```

### Signing and validating with Dilithium

```dart
// Instantiate Dilithium.
var dilithium = Dilithium.level2();

// Define a key generation seed.
var seed = base64Decode("AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8=");

// Generate keys from seed.
var (pk, sk) = dilithium.generateKeys(seed);

// Set the message.
var msg = base64Decode("Dw4NDAsKCQgHBgUEAwIBAA8ODQwLCgkIBwYFBAMCAQA=");

// Sign the message with the private key.
var signature = dilithium.sign(sk, msg);

// Verify the signature with the public key.
var isValid = dilithium.verify(pk, msg, signature);
```

## Disclaimer

This library has not been reviewed by security specialists, and therefore should not be treated as cryptographically secure.

## Acknowledgements

This implementation is based on the python implementation written by Giacomo Pope. Please [go and check and support all of his projects](https://github.com/giacomopope).
