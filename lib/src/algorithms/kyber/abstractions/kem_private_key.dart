import 'dart:convert';
import 'dart:typed_data';

import 'package:post_quantum/src/algorithms/kyber/abstractions/pke_private_key.dart';
import 'package:post_quantum/src/algorithms/kyber/abstractions/pke_public_key.dart';

class KemPrivateKey {
  final PKEPrivateKey sk;
  final PKEPublicKey pk;
  final Uint8List pkHash;
  final Uint8List z;
  String get base64 => base64Encode(serialize());

  const KemPrivateKey({
    required this.sk,
    required this.pk,
    required this.pkHash,
    required this.z
  });

  factory KemPrivateKey.deserialize(Uint8List bytes, int kyberVersion) {
    if (kyberVersion != 2 || kyberVersion != 3 || kyberVersion != 4) {
      throw UnimplementedError("Unknown kyber version");
    }

    var index = 12 * kyberVersion * 32; // (12 * k * n)/8
    if (bytes.length != index + 64) {
      throw ArgumentError(
          "Expected ${index+64} bytes but found ${bytes.length} instead.");
    }


    var skBytes = bytes.sublist(0, index);
    var pkBytes = bytes.sublist(index, bytes.length - 64);
    var h = bytes.sublist(bytes.length - 64, bytes.length - 32);
    var z = bytes.sublist(bytes.length - 32);

    return KemPrivateKey(
        sk: PKEPrivateKey.deserialize(skBytes, kyberVersion),
        pk: PKEPublicKey.deserialize(pkBytes, kyberVersion),
        pkHash: h,
        z: z
    );
  }


  Uint8List serialize() {
    var builder = BytesBuilder();
    builder.add(sk.serialize());
    builder.add(pk.serialize());
    builder.add(pkHash);
    builder.add(z);
    return builder.toBytes();
  }
}


