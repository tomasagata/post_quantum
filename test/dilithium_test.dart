import 'dart:convert';
import 'dart:io';

import 'package:post_quantum/post_quantum.dart';
import 'package:test/test.dart';


void main() {
  group('Dilithium 2 tests', () {
    final dilithium2 = Dilithium.level2();
    final testData = jsonDecode(
      File("test/test_data/dilithium/pregenerated_d2.json").readAsStringSync()
    );

    test('Creating keys with given seed returns expected pre-generated keys', () {
      var seed = base64Decode(testData["seed"]!);
      var (pk, sk) = dilithium2.generateKeys(seed);
      var preGeneratedPK  = testData["pk"]!;
      var preGeneratedSK  = testData["sk"]!;

      expect(pk.base64, preGeneratedPK);
      expect(sk.base64, preGeneratedSK);
    });

    test('Signing with given seed and nonce returns expected pre-generated signature', () {
      var seed = base64Decode(testData["seed"]);
      var message = base64Decode(testData["message"]);

      var (pk, sk) = dilithium2.generateKeys(seed);
      var sig = dilithium2.sign(sk, message);
      expect(sig.base64, testData["sig"]);

      var isValid = dilithium2.verify(pk, message, sig);
      expect(isValid, testData["is_valid"]);
    });

    test('Deserialized keys are equal to generated keys', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var seed = base64Decode(testData["seed"]);

      var pk = DilithiumPublicKey.deserialize(pkBytes, 2);
      var sk = DilithiumPrivateKey.deserialize(skBytes, 2);
      var (genPk, genSk) = dilithium2.generateKeys(seed);

      expect(pk, genPk);
      expect(sk, genSk);
    });

    test('Deserialized signature is equal to generated one', () {
      var seed = base64Decode(testData["seed"]);
      var message = base64Decode(testData["message"]);
      var sigBytes = base64Decode(testData["sig"]);

      var (_, sk) = dilithium2.generateKeys(seed);
      var deserializedSignature = DilithiumSignature
          .deserialize(sigBytes, 2);
      var generatedSignature = dilithium2.sign(sk, message);

      expect(deserializedSignature, generatedSignature);
    });

    test('Signing with given keys returns expected pre-generated signature', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var message = base64Decode(testData["message"]);

      var pk = DilithiumPublicKey.deserialize(pkBytes, 2);
      var sk = DilithiumPrivateKey.deserialize(skBytes, 2);
      var sig = dilithium2.sign(sk, message);
      expect(sig.base64, testData["sig"]);

      var isValid = dilithium2.verify(pk, message, sig);
      expect(isValid, testData["is_valid"]);
    });
  });

  group('Dilithium 3 tests', () {
    final dilithium3 = Dilithium.level3();
    final testData = jsonDecode(
      File("test/test_data/dilithium/pregenerated_d3.json").readAsStringSync()
    );

    test('Creating keys with given seed returns expected pre-generated keys', () {
      var seed = base64Decode(testData["seed"]!);
      var (pk, sk) = dilithium3.generateKeys(seed);
      var preGeneratedPK  = testData["pk"]!;
      var preGeneratedSK  = testData["sk"]!;

      expect(pk.base64, preGeneratedPK);
      expect(sk.base64, preGeneratedSK);
    });

    test('Signing with given seed and nonce returns expected pre-generated signature', () {
      var seed = base64Decode(testData["seed"]);
      var message = base64Decode(testData["message"]);

      var (pk, sk) = dilithium3.generateKeys(seed);
      var sig = dilithium3.sign(sk, message);
      expect(sig.base64, testData["sig"]);

      var isValid = dilithium3.verify(pk, message, sig);
      expect(isValid, testData["is_valid"]);
    });

    test('Deserialized keys are equal to generated keys', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var seed = base64Decode(testData["seed"]);

      var pk = DilithiumPublicKey.deserialize(pkBytes, 3);
      var sk = DilithiumPrivateKey.deserialize(skBytes, 3);
      var (genPk, genSk) = dilithium3.generateKeys(seed);

      expect(pk, genPk);
      expect(sk, genSk);
    });

    test('Deserialized signature is equal to generated one', () {
      var seed = base64Decode(testData["seed"]);
      var message = base64Decode(testData["message"]);
      var sigBytes = base64Decode(testData["sig"]);

      var (_, sk) = dilithium3.generateKeys(seed);
      var deserializedSignature = DilithiumSignature
          .deserialize(sigBytes, 3);
      var generatedSignature = dilithium3.sign(sk, message);

      expect(deserializedSignature, generatedSignature);
    });

    test('Signing with given keys returns expected pre-generated signature', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var message = base64Decode(testData["message"]);

      var pk = DilithiumPublicKey.deserialize(pkBytes, 3);
      var sk = DilithiumPrivateKey.deserialize(skBytes, 3);
      var sig = dilithium3.sign(sk, message);
      expect(sig.base64, testData["sig"]);

      var isValid = dilithium3.verify(pk, message, sig);
      expect(isValid, testData["is_valid"]);
    });
  });

  group('Dilithium 5 tests', () {
    final dilithium5 = Dilithium.level5();
    final testData = jsonDecode(
      File("test/test_data/dilithium/pregenerated_d5.json").readAsStringSync()
    );

    test('Creating keys with given seed returns expected pre-generated keys', () {
      var seed = base64Decode(testData["seed"]!);
      var (pk, sk) = dilithium5.generateKeys(seed);
      var preGeneratedPK  = testData["pk"]!;
      var preGeneratedSK  = testData["sk"]!;

      expect(pk.base64, preGeneratedPK);
      expect(sk.base64, preGeneratedSK);
    });

    test('Signing with given seed and nonce returns expected pre-generated signature', () {
      var seed = base64Decode(testData["seed"]);
      var message = base64Decode(testData["message"]);

      var (pk, sk) = dilithium5.generateKeys(seed);
      var sig = dilithium5.sign(sk, message);
      expect(sig.base64, testData["sig"]);

      var isValid = dilithium5.verify(pk, message, sig);
      expect(isValid, testData["is_valid"]);
    });

    test('Deserialized keys are equal to generated keys', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var seed = base64Decode(testData["seed"]);

      var pk = DilithiumPublicKey.deserialize(pkBytes, 5);
      var sk = DilithiumPrivateKey.deserialize(skBytes, 5);
      var (genPk, genSk) = dilithium5.generateKeys(seed);

      expect(pk, genPk);
      expect(sk, genSk);
    });

    test('Deserialized signature is equal to generated one', () {
      var seed = base64Decode(testData["seed"]);
      var message = base64Decode(testData["message"]);
      var sigBytes = base64Decode(testData["sig"]);

      var (_, sk) = dilithium5.generateKeys(seed);
      var deserializedSignature = DilithiumSignature
          .deserialize(sigBytes, 5);
      var generatedSignature = dilithium5.sign(sk, message);

      expect(deserializedSignature, generatedSignature);
    });

    test('Signing with given keys returns expected pre-generated signature', () {
      var pkBytes = base64Decode(testData["pk"]);
      var skBytes = base64Decode(testData["sk"]);
      var message = base64Decode(testData["message"]);

      var pk = DilithiumPublicKey.deserialize(pkBytes, 5);
      var sk = DilithiumPrivateKey.deserialize(skBytes, 5);
      var sig = dilithium5.sign(sk, message);
      expect(sig.base64, testData["sig"]);

      var isValid = dilithium5.verify(pk, message, sig);
      expect(isValid, testData["is_valid"]);
    });
  });
}
