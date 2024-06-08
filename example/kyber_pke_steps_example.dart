import 'dart:convert';

import 'package:post_quantum/post_quantum.dart';

void main() {

  // Create observers for key generation, encapsulation and decapsulation.
  var keygenObs = StepObserver();
  var encryptObs = StepObserver();
  var decryptObs = StepObserver();

  // Instantiate Kyber's internal PKE.
  var kyber = KyberPKE.pke512();

  // Define a key generation seed.
  var seed = base64Decode("AAECAwQFBgcICQoLDA0ODwABAgMEBQYHCAkKCwwNDg8=");

  // Generate keys from seed.
  var (pk, sk) = kyber.generateKeys(seed, observer: keygenObs);

  // Set the message.
  var msg = base64Decode("Dw4NDAsKCQgHBgUEAwIBAA8ODQwLCgkIBwYFBAMCAQA=");

  // Define an encryption randomizer.
  var coins = base64Decode("Dw8ODg0NDAwLCwoKCQkICAcHBgYFBQQEAwMCAgEBAAA=");

  // Encrypt the message with the public key.
  var cipher = kyber.encrypt(pk, msg, coins, observer: encryptObs);

  // Decrypt the cipher with the private key.
  var decryptedMsg = kyber.decrypt(sk, cipher, observer: decryptObs);


  print("Original message: \n${base64Encode(msg)}\n");
  print("Decrypted message: \n${base64Encode(decryptedMsg)}\n");

  print("Key generation");
  keygenObs.prettyPrint();

  print("\nEncapsulation");
  encryptObs.prettyPrint();

  print("\nDecapsulation");
  decryptObs.prettyPrint();
}