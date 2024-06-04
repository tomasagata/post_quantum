import 'dart:convert';
import 'dart:typed_data';

import 'package:post_quantum/src/core/polynomials/polynomial_ring_matrix.dart';

class PKEPublicKey {

  // ------------ CONSTRUCTORS ------------
  factory PKEPublicKey(PolynomialMatrix t, Uint8List rho) {
    return PKEPublicKey._internal(t, rho);
  }

  factory PKEPublicKey.deserialize(Uint8List byteArray, int kyberVersion) {
    var rho = byteArray.sublist(byteArray.length - 32);
    var serializedT = byteArray.sublist(0, byteArray.length - 32);
    var t = PolynomialMatrix.deserialize(
        serializedT, kyberVersion, 1, 12, 256, 3329, isNtt: true);
    return PKEPublicKey._internal(t, rho);
  }

  PKEPublicKey._internal(this.t, this.rho);




  // ------------ INSTANCE VARIABLES ------------
  PolynomialMatrix t;
  Uint8List rho;



  // ------------ PUBLIC API ------------

  String get base64 => base64Encode(serialize());

  Uint8List serialize() {
    var result = BytesBuilder();
    result.add(t.serialize(12));
    result.add(rho);
    return result.toBytes();
  }

}