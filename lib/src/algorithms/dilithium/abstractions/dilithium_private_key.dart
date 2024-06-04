import 'dart:convert';
import 'dart:typed_data';

import 'package:post_quantum/src/core/ntt/ntt_helper_dilithium.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring_matrix.dart';

class DilithiumPrivateKey {
  Uint8List rho;
  Uint8List K;
  Uint8List tr;
  PolynomialMatrix s1;
  PolynomialMatrix s2;
  PolynomialMatrix t0;

  DilithiumPrivateKey(this.rho, this.K, this.tr, this.s1, this.s2, this.t0);

  factory DilithiumPrivateKey.deserialize(Uint8List bytes, int dilithiumVersion) {
    int l, k, eta, sWordSize;

    if(dilithiumVersion == 2) {
      l = 4;
      k = 4;
      eta = 2;
      sWordSize = 3;
    } else if (dilithiumVersion == 3) {
      l = 5;
      k = 6;
      eta = 4;
      sWordSize = 4;
    } else if (dilithiumVersion == 5) {
      l = 7;
      k = 8;
      eta = 2;
      sWordSize = 3;
    } else {
      throw ArgumentError("Invalid dilithium version selected");
    }

    if(bytes.length != (3 * 32) + (l*sWordSize*32) + (k*sWordSize*32) + (k*13*32)) {
      throw ArgumentError("Dilithium private key size mismatch");
    }


    int offset = 0;

    // sizeof(rho) = 32
    var rho = bytes.sublist(0, 32);
    offset += 32;

    // sizeof(K) = 32
    var K = bytes.sublist(32, 64);
    offset += 32;

    // sizeof(tr) = 32
    var tr = bytes.sublist(64, 96);
    offset += 32;

    // sizeof(bytes(s1)) = l * (sWordSize * 256 / 8)
    var s1 = _deserializeS(
        bytes.sublist(offset, offset + (l * sWordSize * 32)), l, eta, sWordSize
    );
    offset += l * sWordSize * 32;

    // sizeof(bytes(s2)) = k * (sWordSize * 256 / 8)
    var s2 = _deserializeS(
        bytes.sublist(offset, offset + (k * sWordSize * 32)), k, eta, sWordSize
    );
    offset += k * sWordSize * 32;

    // sizeof(bytes(t0)) = k * (13 * 256 / 8)
    var t0 = _deserializeT0(bytes.sublist(offset), k);

    return DilithiumPrivateKey(rho, K, tr, s1, s2, t0);
  }


  static PolynomialMatrix _deserializeS(Uint8List bytes,
      int rows, int eta, int wordSize) {
    PolynomialMatrix s;

    s = PolynomialMatrix.deserialize(
        bytes, rows, 1, wordSize, 256, 8380417, helper: DilithiumNTTHelper()
    );

    s.mapCoefficients((coef) => eta - coef, inPlace: true);

    return s;
  }

  static PolynomialMatrix _deserializeT0(Uint8List bytes, int l) {
    var t0 = PolynomialMatrix.deserialize(
        bytes, l, 1, 13, 256, 8380417, modulusType: Modulus.centered, helper: DilithiumNTTHelper()
    );

    t0.mapCoefficients((coef) => (1 << 12) - coef, inPlace: true);

    return t0;
  }


  Uint8List _serializeS(PolynomialMatrix s, int eta, int wordSize) {
    var sCopy = s.mapCoefficients((coef) => eta - coef);
    return sCopy.serialize(wordSize);
  }

  Uint8List _serializeT0() {
    var t0Prime = t0.mapCoefficients(
            (coef) => (1 << 12) - coef
    );
    return t0Prime.serialize(13);
  }



  String get base64 => base64Encode(serialize());

  Uint8List serialize() {
    int l = s1.rows, eta, sWordSize;
    if (l == 4 || l == 7) { // Dilithium level 2 or 5
      eta = 2;
      sWordSize = 3;
    } else if (l == 5) { // level 3
      eta = 4;
      sWordSize = 4;
    } else { // unknown level
      throw ArgumentError("Unknown Dilithium level");
    }

    var result = BytesBuilder();
    result.add(rho);
    result.add(K);
    result.add(tr);
    result.add( _serializeS(s1, eta, sWordSize) );
    result.add( _serializeS(s2, eta, sWordSize) );
    result.add( _serializeT0() );
    return result.toBytes();
  }

}