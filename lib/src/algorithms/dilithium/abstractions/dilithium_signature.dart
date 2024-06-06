import 'dart:convert';
import 'dart:typed_data';

import 'package:post_quantum/src/core/ntt/ntt_helper_dilithium.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring_matrix.dart';

class DilithiumSignature {
  Uint8List cTilde;
  PolynomialMatrix z;
  PolynomialMatrix h;
  static int n = 256;
  static int q = 8380417;


  DilithiumSignature(this.cTilde, this.z, this.h);

  factory DilithiumSignature.deserialize(Uint8List bytes, int dilithiumVersion) {
    int l, k, gamma1, omega, zWordSize;

    if(dilithiumVersion == 2) {
      l = 4;
      k = 4;
      gamma1 = 1 << 17;
      omega = 80;
      zWordSize = 18;
    } else if (dilithiumVersion == 3) {
      l = 5;
      k = 6;
      gamma1 = 1 << 19;
      omega = 55;
      zWordSize = 20;
    } else if (dilithiumVersion == 5) {
      l = 7;
      k = 8;
      gamma1 = 1 << 19;
      omega = 75;
      zWordSize = 20;
    } else {
      throw ArgumentError("Invalid dilithium version selected");
    }

    if(bytes.length != 32 + (l*zWordSize*32) + (omega + k)) {
      throw ArgumentError("Dilithium signature size mismatch");
    }

    int offset = 0;

    // sizeof(cTilde) = 32
    var cTilde = bytes.sublist(0, 32);
    offset += 32;

    // sizeof(z) = l * zWordSize * 256 / 8
    var z = _deserializeZ(
        bytes.sublist(offset, offset + (l*zWordSize*32)), l, gamma1, zWordSize
    );
    offset += l * zWordSize * 32;

    // sizeof(h) = omega + k
    var h = _deserializeH(
        bytes.sublist(offset, offset + (omega + k)), k, omega
    );

    return DilithiumSignature(cTilde, z, h);
  }

  static PolynomialMatrix _deserializeZ(Uint8List bytes, int l, int gamma1, int wordSize) {
    PolynomialMatrix z;

    z = PolynomialMatrix.deserialize(
        bytes, l, 1, wordSize, 256, 8380417, helper: DilithiumNTTHelper()
    );

    z.mapCoefficients((coef) => gamma1 - coef, inPlace: true);

    return z;
  }

  static PolynomialMatrix _deserializeH(Uint8List bytes, int K, int omega) {
    var polynomials = <PolynomialRing>[];

    int k = 0;
    for(int i = 0; i < K; ++i) {
      var poly = PolynomialRing.zeros(n, q, helper: DilithiumNTTHelper());

      if(bytes[omega + i] < k || bytes[omega + i] > omega) {
        throw ArgumentError("Signature is invalid or corrupted");
      }

      for(int j = k; j < bytes[omega + i]; ++j) {
        /* Coefficients are ordered for strong unforgeability */
        if(j > k && bytes[j] <= bytes[j-1]) {
          throw ArgumentError("Signature is invalid or corrupted");
        }
        poly.coefficients[bytes[j]] = 1;
      }

      polynomials.add(poly);
      k = bytes[omega + i];
    }

    /* Extra indices are zero for strong unforgeability */
    for(int j = k; j < omega; ++j) {
      if(bytes[j] == 1){
        throw ArgumentError("Signature is invalid or corrupted");
      }
    }

    return PolynomialMatrix.fromList(polynomials, K, 1);
  }


  Uint8List _serializeZ(int gamma1, int wordSize) {
    var zPrime = z.mapCoefficients((coef) => gamma1 - coef);

    return zPrime.serialize(wordSize);
  }

  Uint8List _serializeH(int K, int omega) {
    var hBytes = Uint8List(omega + K);

    int k = 0;
    for(int i = 0; i < K; ++i) {
      for(int j = 0; j < 256; ++j) {
        if(h.elementMatrix[i][0].coefficients[j] != 0) {
          hBytes[k++] = j;
        }
      }

      hBytes[omega + i] = k;
    }

    return hBytes;
  }
  
  
  String get base64 => base64Encode(serialize());

  Uint8List serialize() {
    int l = z.rows, k = h.rows, gamma1, omega, zWordSize;

    if(l == 4) { // Dilithium level 2
      gamma1 = 1 << 17;
      omega = 80;
      zWordSize = 18;
    } else if (l == 5) { // Dilithium level 3
      gamma1 = 1 << 19;
      omega = 55;
      zWordSize = 20;
    } else if (l == 7) { // Dilithium level 5
      gamma1 = 1 << 19;
      omega = 75;
      zWordSize = 20;
    } else { // unknown level
      throw ArgumentError("Invalid dilithium version selected");
    }

    var result = BytesBuilder();
    result.add(cTilde);
    result.add( _serializeZ(gamma1, zWordSize) );
    result.add( _serializeH(k, omega) );
    return result.toBytes();
  }

  @override
  bool operator ==(covariant DilithiumSignature other) {
    for (int i=0; i<cTilde.length; i++) {
      if (cTilde[i] != other.cTilde[i]) return false;
    }

    return z == other.z && h == other.h;
  }
}