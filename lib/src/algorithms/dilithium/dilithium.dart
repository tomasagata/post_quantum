import 'dart:typed_data';

import 'package:crystals_pqc/src/algorithms/dilithium/abstractions/dilithium_private_key.dart';
import 'package:crystals_pqc/src/algorithms/dilithium/abstractions/dilithium_public_key.dart';
import 'package:crystals_pqc/src/algorithms/dilithium/abstractions/dilithium_signature.dart';
import 'package:crystals_pqc/src/algorithms/dilithium/generators/dilithium_key_generator.dart';
import 'package:crystals_pqc/src/core/factories/polynomial_factory.dart';
import 'package:crystals_pqc/src/core/ntt/ntt_helper_dilithium.dart';
import 'package:crystals_pqc/src/core/polynomials/polynomial_ring.dart';
import 'package:crystals_pqc/src/core/polynomials/polynomial_ring_matrix.dart';
import 'package:hashlib/hashlib.dart';

class Dilithium {

  /// Creates a new generic Dilithium implementation
  ///
  /// A generic Dilithium implementation receives the following parameters:
  /// - __[n]__: Maximum degree of the used polynomials
  /// - __[k]__: Number of polynomials per vector
  /// - __[q]__: Modulus for numbers
  /// - __[eta_1], [eta_2]__: Size of "small" coefficients used in the private key and noise vectors.
  /// - __[du], [dv]__: How many bits to retain per coefficient of __u__ and __v__. Kyber will compress
  /// the cypher according to these two variables.
  Dilithium({
    required this.n,
    required this.q,
    required this.d,
    required this.k,
    required this.l,
    required int eta,
    required int etaBound,
    required int tau,
    required this.omega,
    required this.gamma1,
    required this.gamma2
  }) :
    beta = tau * eta,
    polyFactory = PolynomialFactory(n: n, q: q, helper: DilithiumNTTHelper()),
    keyGenerator = DilithiumKeyGenerator(
      n: n,
      q: q,
      d: d,
      k: k,
      l: l,
      eta: eta,
      etaBound: etaBound,
      tau: tau,
      gamma1: gamma1,
    );



  factory Dilithium.level2() {
    return Dilithium(
      n: 256,
      q: 8380417,
      d: 13,
      k: 4,
      l: 4,
      eta: 2,
      etaBound: 15,
      tau: 39,
      omega: 80,
      gamma1: 131072,
      gamma2: 95232
    );
  }

  factory Dilithium.level3() {
    return Dilithium(
      n: 256,
      q: 8380417,
      d: 13,
      k: 6,
      l: 5,
      eta: 4,
      etaBound: 9,
      tau: 49,
      omega: 55,
      gamma1: 524288,
      gamma2: 261888
    );
  }

  factory Dilithium.level5() {
    return Dilithium(
      n: 256,
      q: 8380417,
      d: 13,
      k: 8,
      l: 7,
      eta: 2,
      etaBound: 15,
      tau: 60,
      omega: 75,
      gamma1: 524288,
      gamma2: 261888
    );
  }



  // -------- MODEL PARAMETERS --------
  int n;
  int q;
  int d;
  int k;
  int l;
  int omega;
  int gamma1;
  int gamma2;
  int beta;
  DilithiumKeyGenerator keyGenerator;
  PolynomialFactory polyFactory;



  // ----------- KYBER MATHEMATICAL PRIMITIVES -------------

  Uint8List _h(Uint8List message, int outputSizeInBytes) {
    return shake256.of(outputSizeInBytes).convert(message).bytes;
  }






  // ----------- INTERNAL METHODS -------------

  /// Joins two byte arrays A and B together.
  ///
  /// returns <code>A || B</code>
  Uint8List _join(Uint8List A, Uint8List B) {
    var result = BytesBuilder();
    result.add(A);
    result.add(B);
    return result.toBytes();
  }

  /// Receives a number [x] and returns a number [x]' in (-q/2; q/2]
  /// when [q] is even or in [-(q-1)/2; (q-1)/2] when [q] is odd.
  ///
  /// [x]' still holds that [x]' mod [q] = [x] mod [q].
  int _reduceModulus(int x, int a) {
    int r = x % a;
    if (r > (a >> 1)) r -= a;
    return r;
  }

  (int r1, int r0) _decompose(int r, int alpha, int q) {
    r = r % q;
    var r0 = _reduceModulus(r, alpha);
    var r1 = r - r0;
    if(r1 == q - 1) return (0, r0 - 1);
    r1 = r1 ~/ alpha;
    return (r1, r0);
  }

  PolynomialMatrix _makeHint(PolynomialMatrix v1, PolynomialMatrix v2, int alpha) {
    if (v1.shape != v2.shape){
      throw ArgumentError("Vectors v1 and v2 must share the same shape");
    }

    int rows = v1.rows;
    int columns = v1.columns;

    List<PolynomialRing> hintPolynomials = [];
    List<PolynomialRing> polynomialsV1 = v1.polynomials;
    List<PolynomialRing> polynomialsV2 = v2.polynomials;
    for (int i=0; i<rows * columns; i++) {
      if (polynomialsV1[i].n != polynomialsV2[i].n) {
        throw StateError("n dimension mismatch.");
      }

      List<int> coefs = [];
      for (int j=0; j<polynomialsV1[i].n; j++) {
        int z0 = polynomialsV1[i].coefficients[j];
        int r1 = polynomialsV2[i].coefficients[j];
        int hint = 0;

        int gamma2 = (alpha >> 1);
        bool condition1 = z0 <= gamma2;
        bool condition2 = z0 > (q - gamma2);
        bool condition3 = z0 == (q - gamma2) && r1 == 0;
        if (condition1 || condition2 || condition3){
          hint = 0;
        } else {
          hint = 1;
        }

        coefs.add(hint);
      }

      hintPolynomials.add(polyFactory.ring(coefs));
    }

    return polyFactory.matrix(hintPolynomials, rows, columns);
  }

  int _sumHint(PolynomialMatrix hint) {
    int sum = 0;
    for (var poly in hint.polynomials) {
      for (var coef in poly.coefficients) {
        sum += coef;
      }
    }
    return sum;
  }

  PolynomialMatrix _useHint(
      PolynomialMatrix v1, PolynomialMatrix v2, int alpha) {
    if (v1.shape != v2.shape){
      throw ArgumentError("Vectors v1 and v2 must share the same shape");
    }

    int rows = v1.rows;
    int columns = v1.columns;

    List<PolynomialRing> resultingPolynomials = [];
    List<PolynomialRing> polynomialsV1 = v1.polynomials;
    List<PolynomialRing> polynomialsV2 = v2.polynomials;
    for (int i=0; i<rows * columns; i++) {
      if (polynomialsV1[i].n != polynomialsV2[i].n) {
        throw StateError("n dimension mismatch.");
      }

      List<int> coefs = [];
      for (int j=0; j<polynomialsV1[i].n; j++) {
        int h = polynomialsV1[i].coefficients[j];
        int r = polynomialsV2[i].coefficients[j];

        var m = (q-1) ~/ alpha;
        var (r1, r0) = _decompose(r, alpha, q);
        if (h != 1) {
          coefs.add(r1);
          continue;
        }
        if (r0 <= 0) {
          coefs.add((r1 - 1) % m);
          continue;
        }
        coefs.add((r1 + 1) % m);
      }

      resultingPolynomials.add(polyFactory.ring(coefs));
    }

    return polyFactory.matrix(resultingPolynomials, rows, columns);
  }

  bool _hashesMatch(Uint8List h1, Uint8List h2) {
    if (h1.length != h2.length) return false;

    for (int i=0; i<h1.length; i++) {
      if (h1[i] != h2[i]) {
        return false;
      }
    }
    return true;
  }

  Uint8List _serializeW(PolynomialMatrix w) {
    Uint8List wBytes;
    if (gamma2 == 95232) { // Level 2
      wBytes = w.serialize(6);
    } else if(gamma2 == 261888) { // Level 3 & 5
      wBytes = w.serialize(4);
    } else {
      throw ArgumentError("Expected gamma2 to be (q-1)/88 or (q-1)/32");
    }
    return wBytes;
  }




  // ----------- PUBLIC KEM API -------------

  /// A Dilithium keypair is derived deterministically from a
  /// 32-octet seed.
  (DilithiumPublicKey pk, DilithiumPrivateKey sk) generateKeys(Uint8List seed) {
    if( seed.length != 32 ) {
      throw ArgumentError("Seed must be 32 bytes in length");
    }

    // Generate PKE keys for decryption and encryption of cyphers.
    var (pk, sk) = keyGenerator.generateKeys(seed);

    return (pk, sk);
  }



  /// Kyber encapsulation takes a public key and a 32-octet seed
  /// and deterministically generates a shared secret and ciphertext
  /// for the public key.
  DilithiumSignature sign(DilithiumPrivateKey sk, Uint8List message, {bool randomized = false}) {
    var A = keyGenerator.expandA(sk.rho, isNtt: true);

    var mu = _h( _join(sk.tr, message), 64);
    var kappa = 0;

    Uint8List rhoPrime;
    if (randomized) {
      rhoPrime = randomBytes(64);
    } else {
      rhoPrime = _h( _join(sk.K, mu), 64);
    }

    var s1Hat = sk.s1.copy().toNtt();
    var s2Hat = sk.s2.copy().toNtt();
    var t0Hat = sk.t0.copy().toNtt();

    var alpha = gamma2 << 1;
    while (true) {
      var y = keyGenerator.expandMask(rhoPrime, kappa);
      var yHat = y.copy().toNtt();

      // Increment the nonce
      kappa += l;

      var w = A.multiply(yHat).fromNtt();

      // Decompose w into its high and low bits.
      var (w1, w0) = w.decompose(alpha);

      Uint8List w1Bytes = _serializeW(w1);

      var cTilde = _h( _join(mu, w1Bytes), 32);
      var c = keyGenerator.sampleInBall(cTilde);
      c.toNtt();

      var z = y.plus(s1Hat.scale(c).fromNtt());
      if (z.checkNormBound(gamma1 - beta)) continue;

      var w0MinusCS2 = w0.minus(s2Hat.scale(c).fromNtt());
      if (w0MinusCS2.checkNormBound(gamma2 - beta)) continue;

      var cT0 = t0Hat.scale(c).fromNtt();
      if (cT0.checkNormBound(gamma2)) continue;

      var w0MinusCS2PlusCT0 = w0MinusCS2.plus(cT0);
      var h = _makeHint(w0MinusCS2PlusCT0, w1, alpha);

      if (_sumHint(h) > omega) continue;

      return DilithiumSignature(cTilde, z, h);
    }
  }



  /// Kyber decapsulation takes the received cypher text from the other
  /// end and your public key, private key and 32-byte z value and
  /// returns a shared secret.
  ///
  /// - If decapsulation was successful, returns the shared key calculated in the
  /// encapsulation step.
  /// - If decapsulation was unsuccessful, returns an invalid shared key created
  /// with the given 32-byte z value calculated in the key-generation step.
  bool verify(DilithiumPublicKey pk, Uint8List message, DilithiumSignature signature) {

    var rho = Uint8List.fromList(pk.rho);
    var t1 = pk.t1.copy();

    var cTilde = Uint8List.fromList(signature.cTilde);
    var z = signature.z.copy();
    var h = signature.h.copy();

    if ( _sumHint(h) > omega ) return false;

    if ( z.checkNormBound(gamma1 - beta) ) return false;

    var A = keyGenerator.expandA(rho, isNtt: true);
    
    var tr = _h(pk.serialize(), 32);
    var mu = _h( _join(tr, message), 64);
    var c = keyGenerator.sampleInBall(cTilde);

    c.toNtt();
    z.toNtt();

    t1 = t1.scaleInt(1 << d);
    t1.toNtt();

    var azMinusCt1 = A.multiply(z).minus(t1.scale(c));
    azMinusCt1.fromNtt();

    var wPrime = _useHint(h, azMinusCt1, 2*gamma2);
    Uint8List wPrimeBytes = _serializeW(wPrime);

    return _hashesMatch(cTilde, _h( _join(mu, wPrimeBytes), 32));
  }

}


