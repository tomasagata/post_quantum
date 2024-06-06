import 'dart:convert';
import 'dart:typed_data';

import 'package:post_quantum/src/core/ntt/ntt_helper_kyber.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring_matrix.dart';

class PKECypher {

  // -------------- CONSTRUCTORS --------------
  PKECypher({
    required this.u,
    required this.v,
    required this.du,
    required this.dv
  });

  factory PKECypher.deserialize(
      Uint8List byteArray, int kyberVersion) {
    int du, dv;
    switch (kyberVersion) {
      case 2:
        du = 10;
        dv = 4;
        break;
      case 3:
        du = 10;
        dv = 4;
        break;
      case 4:
        du = 11;
        dv = 5;
        break;
      default:
        throw UnimplementedError("Unknown kyber security level.");
    }

    var sizeU = (du * kyberVersion * 256 / 8).round();
    var serializedU = byteArray.sublist(0, sizeU);
    var serializedV = byteArray.sublist(sizeU);

    var u = PolynomialMatrix
        .deserialize(serializedU, kyberVersion, 1, du, 256, 3329,
          helper: KyberNTTHelper()
        ).decompress(du);
    var v = PolynomialRing
        .deserialize(serializedV, dv, 256, 3329,
          helper: KyberNTTHelper()
        ).decompress(dv);

    return PKECypher(u: u, v: v, du: du, dv: dv);
  }




  // -------------- PARAMETERS --------------
  PolynomialMatrix u;
  PolynomialRing v;
  int du;
  int dv;





  // -------------- PUBLIC API --------------

  String get base64 => base64Encode(serialize());

  Uint8List serialize() {
    // COMPRESS AND SERIALIZE
    var serializedU = u.compress(du).serialize(du);
    var serializedV = v.compress(dv).serialize(dv);

    // SERIALIZED_CYPHER = SERIALIZED_U || SERIALIZED_V
    var serializedCypher = BytesBuilder();
    serializedCypher.add(serializedU);
    serializedCypher.add(serializedV);

    return serializedCypher.toBytes();
  }

  /// Compares two ciphers.
  ///
  /// WARNING: This is NOT cryptographically safe.
  /// In order to comply with the specification, a constant time
  /// implementation is required. This is not it. Please if you know
  /// how to implement it and would like to help out, push a commit to
  /// the repository.
  @override
  bool operator ==(covariant PKECypher other) {
    Uint8List thisCipher = serialize();
    Uint8List otherCipher = other.serialize();

    if ( thisCipher.length != otherCipher.length ) {
      // A constant time implementation should not return early.
      // It should always run in the same amount of time.
      return false;
    }

    for (int i=0; i<thisCipher.length; i++) {
      if (thisCipher[i] != otherCipher[i]) {
        return false;
      }
    }

    return true;
  }

}