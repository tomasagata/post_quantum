import 'dart:typed_data';

import 'package:post_quantum/src/algorithms/dilithium/primitives/prf.dart';
import 'package:post_quantum/src/core/bit_packing/bit_packing_helper.dart';
import 'package:post_quantum/src/core/factories/polynomial_factory.dart';
import 'package:post_quantum/src/core/ntt/ntt_helper_dilithium.dart';
import 'package:hashlib/hashlib.dart';

import 'package:post_quantum/src/core/polynomials/polynomial_ring.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring_matrix.dart';

import '../primitives/xof.dart';


class DilithiumKeyGenerator {

  // ------------ CONSTRUCTORS ------------

  /// Creates a Dilithium Key Generator helper.
  ///
  /// [eta1] is the size of "small" coefficients used in the private key.
  /// [eta2] is the size of "small" coefficients used in the noise vectors.
  /// [k] is the size of the public and private keys.
  DilithiumKeyGenerator({
    required this.n,
    required this.q,
    required this.d,
    required this.k,
    required this.l,
    required this.eta,
    required this.etaBound,
    required this.tau,
    required this.gamma1,
  }) :
    polyFactory = PolynomialFactory(n: n, q: q, helper: DilithiumNTTHelper());





  // ------------ PARAMETERS ------------
  int n;
  int q;
  int d;
  int k;
  int l;
  int eta;
  int etaBound;
  int tau;
  int gamma1;
  PolynomialFactory polyFactory;




  // ------------ KYBER PRIMITIVES ------------

  Uint8List _h(Uint8List message, int outputSizeInBytes) {
    return shake256.of(outputSizeInBytes).convert(message).bytes;
  }

  /// Sample Documentation
  XOF _xof(Uint8List seed, int j, int i) {
    BytesBuilder message = BytesBuilder();
    message.add(seed);
    message.addByte(j);
    message.addByte(i);
    return XOF(message.toBytes());
  }

  /// Hashes the XOR(seed, nonce) in SHAKE256 and returns
  /// 2000 bytes of digest.
  ///
  /// PRF takes in a 256-bit (32-byte) [seed] and a
  /// [nonce] and returns a 2000-byte SHAKE256 hash.
  PRF _prf(Uint8List seed, int nonce) {
    BytesBuilder message = BytesBuilder();
    message.add(seed);
    message.addByte(nonce);
    message.addByte(0);
    return PRF(message.toBytes());
  }








  // ------------ COEFFICIENT SAMPLING ------------


  /// Samples [n] coefficients modulo [q] from an infinitely long [stream].
  ///
  /// Coefficients are sampled uniformly using rejection sampling.
  /// [q] must be less or equal to 2^24, as coefficients can only
  /// allocate 3 bytes.
  PolynomialRing _sampleUniform(XOF stream, {bool isNtt = false}) {

    List<int> coefficients = [];
    while(true) {

      // Read 3 bytes and get a little endian number from it
      var bytes = BytesBuilder();
      bytes.add(stream.read(3));
      bytes.addByte(0);
      var num = ByteData.sublistView(bytes.toBytes())
          .getUint32(0, Endian.little);

      num &= 0x7FFFFF;

      if (num >= q) {
        continue;
      }
      coefficients.add(num);
      if (coefficients.length == n) return polyFactory.ring(coefficients, isNtt: isNtt);
    }
  }


  PolynomialRing _sampleErrorPolynomial(Uint8List rhoPrime, int i) {
    var stream = _prf(rhoPrime, i);

    List<int> coefficients = [];
    while (true) {
      int j = stream.read(1)[0];

      List<int> nums = [j & 0x0F, j >> 4];

      for (var num in nums){
        if(num < etaBound) {
          if (eta == 2) num %= 5;
          coefficients.add(eta - num);
        }
        if(coefficients.length == n) {
          return polyFactory.ring(coefficients);
        }
      }

    }
  }

  /// Generates a rows*columns matrix of uniform samples.
  PolynomialMatrix _sampleMatrix(Uint8List rho, int rows, int columns, {bool isNtt = false}) {
    List<PolynomialRing> polynomials = [];
    for (var i=0; i<rows; i++) {
      for (var j=0; j<columns; j++) {
        polynomials.add(
            _sampleUniform( _xof(rho, j, i), isNtt: isNtt)
        );
      }
    }
    return polyFactory.matrix(polynomials, rows, columns);
  }

  PolynomialRing _sampleMaskPolynomial(Uint8List rhoPrime, int i, int kappa) {
    int bitCount = _wordSize(gamma1);
    int totalBytes = 32 * bitCount; // (256 / 8) * bitCount

    // Create the nonce in a 2-byte little endian representation.
    ByteData littleEndianNonce = ByteData(2)
      ..setUint16(0, kappa + i, Endian.little);

    BytesBuilder seed = BytesBuilder();
    seed.add(rhoPrime);
    seed.add(littleEndianNonce.buffer.asUint8List());
    
    Uint8List bytes = Uint8List.fromList( _h(seed.toBytes(), totalBytes) );

    List<int> numbers = BitPackingHelper.intsFromBytes(bytes, bitCount);

    List<int> coefs = [];
    for (int i=0; i<n; i++) {
      coefs.add(
        gamma1 - numbers[i]
      );
    }

    return polyFactory.ring(coefs);
  }





  // ------------ HELPER METHODS ------------


  /// Calculates the word size of an integer [num].
  int _wordSize(int num) {
    if(num == 0) {
      return 1;
    }

    int bits = 0;
    while (num > 0) {
      num = num >>> 1;
      bits++;
    }
    return bits;
  }






  // ------------ INTERNAL API ------------


  PolynomialMatrix expandA(Uint8List rho, {bool isNtt = false}) {
    return _sampleMatrix(rho, k, l, isNtt: isNtt);
  }


  (PolynomialMatrix s1, PolynomialMatrix s2) expandS(Uint8List rhoPrime) {
    List<PolynomialRing> s1Polynomials = [];
    List<PolynomialRing> s2Polynomials = [];

    for (int i=0; i<l; i++) {
      s1Polynomials.add(_sampleErrorPolynomial(rhoPrime, i));
    }
    for (int i=l; i<(l+k); i++) {
      s2Polynomials.add(_sampleErrorPolynomial(rhoPrime, i));
    }

    return (
      polyFactory.vector(s1Polynomials),
      polyFactory.vector(s2Polynomials)
    );
  }







  // ------------ PUBLIC METHODS ------------

  PolynomialRing sampleInBall(Uint8List seed) {
    // Create an infinite stream of SHAKE256(seed)
    PRF stream = PRF(seed);

    Uint8List signBytes = stream.read(8);

    // As not all platforms support 64-bit integers, create a list
    // simulating a little-endian u64int
    List<int> signIntArray = signBytes.toList();

    List<int> coefficients = List.filled(n, 0);

    int offset = 0;
    int signInt = signIntArray[offset];
    for (int i=256-tau, iter=0; i<n; i++, iter++) {
      if (iter != 0 && iter % 8 == 0){
        offset++;
        signInt = signIntArray[offset];
      }

      int j;
      while(true) {
        j = stream.read(1)[0];
        if (j <= i) break;
      }
      coefficients[i] = coefficients[j];
      coefficients[j] = 1 - 2*(signInt & 1);
      signInt >>= 1;
    }
    
    return polyFactory.ring(coefficients);
  }

  PolynomialMatrix expandMask(Uint8List rhoPrime, int kappa) {
    List<PolynomialRing> polynomials = [];
    for (int i=0; i<l; i++) {
      polynomials.add(
        _sampleMaskPolynomial(rhoPrime, i, kappa)
      );
    }

    return polyFactory.vector(polynomials);
  }


}