import 'dart:typed_data';

import 'package:post_quantum/src/core/factories/polynomial_factory.dart';
import 'package:post_quantum/src/core/ntt/ntt_helper_kyber.dart';
import 'package:post_quantum/src/core/primitives/prf.dart';
import 'package:post_quantum/src/core/primitives/xof.dart';

import 'package:post_quantum/src/core/polynomials/polynomial_ring.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring_matrix.dart';

class KeyGenerator {

  // ------------ CONSTRUCTORS ------------

  /// Creates a Kyber Key Generator helper.
  ///
  /// [eta1] is the size of "small" coefficients used in the private key.
  /// [eta2] is the size of "small" coefficients used in the noise vectors.
  /// [k] is the size of the public and private keys.
  KeyGenerator({
    required this.n,
    required this.k,
    required this.q,
    required this.eta1,
    required this.eta2
  }) :
    polyFactory = PolynomialFactory(n: n, q: q, helper: KyberNTTHelper());





  // ------------ PARAMETERS ------------
  int n;
  int k;
  int q;
  int eta1;
  int eta2;
  PolynomialFactory polyFactory;





  // ------------ KYBER PRIMITIVES ------------

  /// Sample Documentation
  XOF _xof(Uint8List seed, int j, int i) {
    BytesBuilder message = BytesBuilder();
    message.add(seed);
    message.addByte(j);
    message.addByte(i);
    return XOF(message.toBytes());
  }


  /// Appends the seed and nonce values and returns
  /// its SHAKE256 hash.
  ///
  /// PRF takes in a 256-bit (32-byte) [seed] and a
  /// [nonce] and returns an extensible SHAKE256 hash.
  PRF _prf(Uint8List seed, int nonce) {
    BytesBuilder message = BytesBuilder();
    message.add(seed);
    message.addByte(nonce);
    return PRF(message.toBytes());
  }








  // ------------ COEFFICIENT SAMPLING ------------

  /// Samples coefficients from a Centered
  /// Binomial Distribution and returns a Polynomial.
  ///
  /// Takes in a 2*[eta]*[n] bits (2*[eta]*[n]/8 bytes)
  /// array of bytes "[a]" and returns a Polynomial with
  /// [n] coefficients.
  PolynomialRing _cbd(Uint8List a, int eta) {
    assert( a.length == (2*eta*n/8).round() );

    // Returns a list of 2*n*eta bits
    List<int> bitArray = _getBitArrayFromByteArray(a);
    assert( bitArray.length == 2*n*eta );

    // Group bits in groups of eta and add them as if they were ints
    // Example: eta = 2, bits = [0, 1, 0, 0, 1, 1],
    // groups = [[0, 1], [0, 0], [1, 1]]
    // result = [(0 + 1), (0 + 0), (1 + 1)] = [1, 0, 2]
    // Returns a list of 2*n integers
    List<int> groupResults = _groupAndSumNumbers(bitArray, eta);
    assert( groupResults.length == 2*n );

    List<int> coefficients = [];
    for (var i=0; i<2*n; i=i+2) {
      coefficients.add( groupResults[i] - groupResults[i+1] );
    }
    assert( coefficients.length == n );

    return polyFactory.ring( coefficients, modulusType: Modulus.centered );
  }

  // Polynomial sampling
  PolynomialRing _sampleUniform(XOF stream, {bool isNtt = false}) {
    List<int> coefficients = [];

    while(true) {
      var bytes = stream.read(3);
      int num1 = bytes[0] + (256 * (bytes[1] % 16));
      int num2 = (bytes[1] >> 4) + (16 * bytes[2]);

      for (var num in [num1, num2]) {
        if (num >= q) continue;
        coefficients.add(num);
        if (coefficients.length == n) {
          return polyFactory.ring(coefficients, isNtt: isNtt);
        }
      }
    }
  }


  PolynomialMatrix _sampleNoise(
      Uint8List sigma,
      int eta,
      int offset,
      int k
  ) {
    List<PolynomialRing> flattenedPolynomials = [];
    for (var i=0; i<k; i++) {
      var inputBytes = _prf(sigma, i + offset).read(64*eta);
      var poly = _cbd(inputBytes, eta);

      flattenedPolynomials.add(poly);
    }
    return polyFactory.vector(flattenedPolynomials);
  }

  /// Generates a k*k matrix of samples
  PolynomialMatrix _sampleMatrix(Uint8List rho, {bool isNtt = false}) {
    List<PolynomialRing> polynomials = [];
    for (var i=0; i<k; i++) {
      for (var j=0; j<k; j++) {
        polynomials.add(
            _sampleUniform( _xof(rho, j, i), isNtt: isNtt )
        );
      }
    }
    return polyFactory.matrix(polynomials, k, k);
  }





  // ------------ HELPER METHODS ------------


  /// Takes in a byte array of size x and returns its binary
  /// representation as a bit array of size 8*x
  List<int> _getBitArrayFromByteArray(Uint8List byteArray) {
    List<int> bitArray = [];
    for (var byte in byteArray) {
      List<int> bits = [];
      for (var bit=0; bit<8; bit++) {
        bits.add((byte >> bit) % 2);
      }
      bitArray.addAll(bits);
    }
    return bitArray;
  }

  /// Splits numbers into groups of [groupAmount] and adds the result.
  List<int> _groupAndSumNumbers(List<int> numbers, int groupAmount) {
    if (numbers.length % groupAmount != 0) {
      throw ArgumentError();
    }

    List<int> results = [];
    for (var i=0; i<numbers.length; i+=groupAmount) {
      var sum = 0;
      for (var j=0; j<groupAmount; j++) {
        sum += numbers[i + j];
      }
      results.add(sum);
    }
    return results;
  }





  // ------------ PUBLIC METHODS ------------

  PolynomialMatrix expandA(Uint8List rho, {bool isNtt = false}) {
    return _sampleMatrix(rho, isNtt: isNtt);
  }

  PolynomialMatrix expandS(Uint8List sigma) {
    return _sampleNoise(sigma, eta1, 0, k);
  }

  PolynomialMatrix expandE(Uint8List sigma) {
    return _sampleNoise(sigma, eta1, k, k);
  }

  /// Sample documentation
  (PolynomialMatrix r, PolynomialMatrix e1, PolynomialRing e2)
      generateNoiseVectors(Uint8List seed) {
    // PolynomialRing moduloPolynomial = PolynomialRing.zeros(q);
    // moduloPolynomial.set(coefficient: 1, atDegree: 256);
    // moduloPolynomial.set(coefficient: 1, atDegree: 0);
    
    PolynomialMatrix r = _sampleNoise(seed, eta1, 0, k);//.modulo(moduloPolynomial);
    PolynomialMatrix e1 = _sampleNoise(seed, eta2, k, k);
    PolynomialRing e2 = _sampleNoise(seed, eta2, 2*k, 1).toRing();

    return (r, e1, e2);
  }

}