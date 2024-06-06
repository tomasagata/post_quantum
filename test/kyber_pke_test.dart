import 'dart:convert';
import 'dart:io';

import 'package:post_quantum/post_quantum.dart';
import 'package:test/test.dart';


void main() {
  group('KyberPKE 512-bit tests', () {
    final kyber512 = KyberPKE.pke512();
    final testData = jsonDecode(
      File("test/test_data/kyber_pke/pregenerated_pke512.json").readAsStringSync()
    );

    test('Creating keys with given seed returns expected pre-generated keys', () {
      var seed = base64Decode(testData["seed"]!);
      var (pk, sk) = kyber512.generateKeys(seed);
      var preGeneratedPK  = testData["pk"]!;
      var preGeneratedSK  = testData["sk"]!;

      expect(pk.base64, preGeneratedPK);
      expect(sk.base64, preGeneratedSK);
    });

    test('Generating cipher with given seed and nonce returns expected flow parameters', () {
      var seed = base64Decode(testData["seed"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var (pk, sk) = kyber512.generateKeys(seed);
      var cipher = kyber512.encrypt(pk, originalMsg, coins);
      var decryptedMsg = kyber512.decrypt(sk, cipher);

      expect(cipher.base64, testData["cipher"]);
      expect(base64Encode(decryptedMsg), testData["decrypted_msg"]);
    });

    test('Deserialized keys are equal to generated keys', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var seed = base64Decode(testData["seed"]);

      var pk = PKEPublicKey.deserialize(pkBytes, 2);
      var sk = PKEPrivateKey.deserialize(skBytes, 2);
      var (genPk, genSk) = kyber512.generateKeys(seed);

      expect(pk, genPk);
      expect(sk, genSk);
    });

    test('Deserialized cipher is equal to generated one', () {
      var seed = base64Decode(testData["seed"]);
      var cipherBytes = base64Decode(testData["cipher"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var (pk, _) = kyber512.generateKeys(seed);
      var deserializedCipher = PKECypher.deserialize(cipherBytes, 2);
      var generatedCipher = kyber512.encrypt(pk, originalMsg, coins);

      expect(deserializedCipher, generatedCipher);
    });

    test('Generating cipher with given keys returns expected flow parameters', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var pk = PKEPublicKey.deserialize(pkBytes, 2);
      var sk = PKEPrivateKey.deserialize(skBytes, 2);
      var cipher = kyber512.encrypt(pk, originalMsg, coins);
      var decryptedMsg = kyber512.decrypt(sk, cipher);

      expect(cipher.base64, testData["cipher"]);
      expect(base64Encode(decryptedMsg), testData["decrypted_msg"]);
    });

    test('Decrypting given cipher with given keys returns expected flow parameters', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var pk = PKEPublicKey.deserialize(pkBytes, 2);
      var sk = PKEPrivateKey.deserialize(skBytes, 2);
      var cipher = kyber512.encrypt(pk, originalMsg, coins);
      var decryptedMsg = kyber512.decrypt(sk, cipher);

      expect(cipher.base64, testData["cipher"]);
      expect(base64Encode(decryptedMsg), testData["decrypted_msg"]);
    });
  });

  group('KyberPKE 768-bit tests', () {
    final kyber768 = KyberPKE.pke768();
    final testData = jsonDecode(
      File("test/test_data/kyber_pke/pregenerated_pke768.json").readAsStringSync()
    );

    test('Creating keys with given seed returns expected pre-generated keys', () {
      var seed = base64Decode(testData["seed"]!);
      var (pk, sk) = kyber768.generateKeys(seed);
      var preGeneratedPK  = testData["pk"]!;
      var preGeneratedSK  = testData["sk"]!;

      expect(pk.base64, preGeneratedPK);
      expect(sk.base64, preGeneratedSK);
    });

    test('Generating cipher with given seed and nonce returns expected flow parameters', () {
      var seed = base64Decode(testData["seed"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var (pk, sk) = kyber768.generateKeys(seed);
      var cipher = kyber768.encrypt(pk, originalMsg, coins);
      var decryptedMsg = kyber768.decrypt(sk, cipher);

      expect(cipher.base64, testData["cipher"]);
      expect(base64Encode(decryptedMsg), testData["decrypted_msg"]);
    });

    test('Deserialized keys are equal to generated keys', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var seed = base64Decode(testData["seed"]);

      var pk = PKEPublicKey.deserialize(pkBytes, 3);
      var sk = PKEPrivateKey.deserialize(skBytes, 3);
      var (genPk, genSk) = kyber768.generateKeys(seed);

      expect(pk, genPk);
      expect(sk, genSk);
    });

    test('Deserialized cipher is equal to generated one', () {
      var seed = base64Decode(testData["seed"]);
      var cipherBytes = base64Decode(testData["cipher"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var (pk, _) = kyber768.generateKeys(seed);
      var deserializedCipher = PKECypher.deserialize(cipherBytes, 3);
      var generatedCipher = kyber768.encrypt(pk, originalMsg, coins);

      expect(deserializedCipher, generatedCipher);
    });

    test('Generating cipher with given keys returns expected flow parameters', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var pk = PKEPublicKey.deserialize(pkBytes, 3);
      var sk = PKEPrivateKey.deserialize(skBytes, 3);
      var cipher = kyber768.encrypt(pk, originalMsg, coins);
      var decryptedMsg = kyber768.decrypt(sk, cipher);

      expect(cipher.base64, testData["cipher"]);
      expect(base64Encode(decryptedMsg), testData["decrypted_msg"]);
    });

    test('Decrypting given cipher with given keys returns expected flow parameters', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var pk = PKEPublicKey.deserialize(pkBytes, 3);
      var sk = PKEPrivateKey.deserialize(skBytes, 3);
      var cipher = kyber768.encrypt(pk, originalMsg, coins);
      var decryptedMsg = kyber768.decrypt(sk, cipher);

      expect(cipher.base64, testData["cipher"]);
      expect(base64Encode(decryptedMsg), testData["decrypted_msg"]);
    });
  });

  group('KyberPKE 1024-bit tests', () {
    final kyber1024 = KyberPKE.pke1024();
    final testData = jsonDecode(
      File("test/test_data/kyber_pke/pregenerated_pke1024.json").readAsStringSync()
    );

    test('Creating keys with given seed returns expected pre-generated keys', () {
      var seed = base64Decode(testData["seed"]!);
      var (pk, sk) = kyber1024.generateKeys(seed);
      var preGeneratedPK  = testData["pk"]!;
      var preGeneratedSK  = testData["sk"]!;

      expect(pk.base64, preGeneratedPK);
      expect(sk.base64, preGeneratedSK);
    });

    test('Generating cipher with given seed and nonce returns expected flow parameters', () {
      var seed = base64Decode(testData["seed"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var (pk, sk) = kyber1024.generateKeys(seed);
      var cipher = kyber1024.encrypt(pk, originalMsg, coins);
      var decryptedMsg = kyber1024.decrypt(sk, cipher);

      expect(cipher.base64, testData["cipher"]);
      expect(base64Encode(decryptedMsg), testData["decrypted_msg"]);
    });

    test('Deserialized keys are equal to generated keys', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var seed = base64Decode(testData["seed"]);

      var pk = PKEPublicKey.deserialize(pkBytes, 4);
      var sk = PKEPrivateKey.deserialize(skBytes, 4);
      var (genPk, genSk) = kyber1024.generateKeys(seed);

      expect(pk, genPk);
      expect(sk, genSk);
    });

    test('Deserialized cipher is equal to generated one', () {
      var seed = base64Decode(testData["seed"]);
      var cipherBytes = base64Decode(testData["cipher"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var (pk, _) = kyber1024.generateKeys(seed);
      var deserializedCipher = PKECypher.deserialize(cipherBytes, 4);
      var generatedCipher = kyber1024.encrypt(pk, originalMsg, coins);

      expect(deserializedCipher, generatedCipher);
    });

    test('Generating cipher with given keys returns expected flow parameters', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var pk = PKEPublicKey.deserialize(pkBytes, 4);
      var sk = PKEPrivateKey.deserialize(skBytes, 4);
      var cipher = kyber1024.encrypt(pk, originalMsg, coins);
      var decryptedMsg = kyber1024.decrypt(sk, cipher);

      expect(cipher.base64, testData["cipher"]);
      expect(base64Encode(decryptedMsg), testData["decrypted_msg"]);
    });

    test('Decrypting given cipher with given keys returns expected flow parameters', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var originalMsg = base64Decode(testData["original_msg"]);
      var coins = base64Decode(testData["coins"]);

      var pk = PKEPublicKey.deserialize(pkBytes, 4);
      var sk = PKEPrivateKey.deserialize(skBytes, 4);
      var cipher = kyber1024.encrypt(pk, originalMsg, coins);
      var decryptedMsg = kyber1024.decrypt(sk, cipher);

      expect(cipher.base64, testData["cipher"]);
      expect(base64Encode(decryptedMsg), testData["decrypted_msg"]);
    });
  });
}
