import 'dart:convert';
import 'dart:io';

import 'package:crystals_pqc/crystals_pqc.dart';
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
  });
}
