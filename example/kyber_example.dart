import 'dart:convert';

import 'package:post_quantum/post_quantum.dart';

void main() {

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


  print("Encapsulated shared key: \n${base64Encode(sharedKey1)}\n");
  print("Decapsulated shared key: \n${base64Encode(sharedKey2)}\n");
}
