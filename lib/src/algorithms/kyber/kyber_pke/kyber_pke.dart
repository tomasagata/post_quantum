import 'dart:typed_data';

import 'package:hashlib/hashlib.dart';
import 'package:post_quantum/src/core/observer/null_step_observer.dart';
import 'package:post_quantum/src/core/observer/step_observer.dart';

import '../abstractions/pke_cipher.dart';
import '../abstractions/pke_private_key.dart';
import '../abstractions/pke_public_key.dart';
import '../generators/key_generator.dart';

import 'package:post_quantum/src/core/polynomials/polynomial_ring.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring_matrix.dart';

class KyberPKE {

  // -------------- CONSTRUCTORS --------------

  /// Creates a new custom Kyber PKE implementation
  ///
  /// Any kyber implementation receives the following parameters:
  /// - __[n]__: Maximum degree of the used polynomials
  /// - __[k]__: Number of polynomials per vector
  /// - __[q]__: Modulus for numbers
  /// - __[eta_1], [eta_2]__: Size of "small" coefficients used in the private key and noise vectors.
  /// - __[du], [dv]__: How many bits to retain per coefficient of __u__ and __v__. Kyber will compress
  /// the cypher according to these two variables.
  factory KyberPKE({
    required int n,
    required int k,
    required int q,
    required int eta1,
    required int eta2,
    required int du,
    required int dv,
  }) {
    var keyGenerator = KeyGenerator(n: n, k: k, q: q, eta1: eta1, eta2: eta2);
    return KyberPKE._internal(n: n, k: k, q: q, du: du, dv: dv, keyGenerator: keyGenerator);
  }

  factory KyberPKE.pke512() {
    return KyberPKE(
        n: 256, k: 2, q: 3329, eta1: 3, eta2: 2, du: 10, dv: 4
    );
  }

  factory KyberPKE.pke768() {
    return KyberPKE(
        n: 256, k: 3, q: 3329, eta1: 2, eta2: 2, du: 10, dv: 4
    );
  }

  factory KyberPKE.pke1024() {
    return KyberPKE(
        n: 256, k: 4, q: 3329, eta1: 2, eta2: 2, du: 11, dv: 5
    );
  }

  KyberPKE._internal({
    required this.n,
    required this.k,
    required this.q,
    required this.du,
    required this.dv,
    required this.keyGenerator
  });




  // -------------- PARAMETERS --------------
  int n;
  int k;
  int q;
  int du;
  int dv;
  KeyGenerator keyGenerator;




  // --------------- PRIMITIVES --------------

  /// G primitive from Kyber specification.
  ///
  /// G takes in a 256-bit (32-byte) seed and returns
  /// its SHA3-512 hash split in two.
  (Uint8List lower32Bytes, Uint8List upper32Bytes) _g(Uint8List seed) {
    var bytes = sha3_512.convert(seed).bytes;
    return (bytes.sublist(0, 32), bytes.sublist(32));
  }




  // -------------- PUBLIC PKE API --------------

  (PKEPublicKey pk, PKEPrivateKey sk) generateKeys(Uint8List seed, {
    StepObserver observer = const NullStepObserver()
  }) {
    if( seed.length != 32 ) {
      throw ArgumentError("Seed must be 32 bytes in length");
    }

    var (rho, sigma) = _g(seed);

    var A = keyGenerator.expandA(rho, isNtt: true);
    observer.addStep(
      title: "Generating Matrix A",
      description: "Taking in the given seed and generating matrix A in"
          "NTT form.",
      parameters: {"seed": seed},
      results: {"A": A.copy()}
    );

    var s = keyGenerator.expandS(sigma);
    s.toNtt();
    observer.addStep(
      title: "Generating vector S",
      description: "Taking in the given seed and generating vector S in"
          "NTT form.",
      parameters: {"seed": seed},
      results: {"s": s.copy()}
    );

    var e = keyGenerator.expandE(sigma);
    e.toNtt();
    observer.addStep(
        title: "Generating vector e",
        description: "Taking in the given seed and generating vector e in"
            "NTT form.",
        parameters: {"seed": seed},
        results: {"e": e.copy()}
    );

    var t = A.multiply(s, skipReduce: true);
    t = t.toMontgomery();
    t = t.plus(e, skipReduce: true);
    observer.addStep(
        title: "Generating vector t",
        description: "Calculating vector t by doing (A*s)+e.",
        parameters: {"seed": seed},
        results: {"t": t.copy()}
    );

    t.reduceCoefficients();
    s.reduceCoefficients();

    return (PKEPublicKey(t, rho), PKEPrivateKey(s));
  }



  PKECypher encrypt(PKEPublicKey pk, Uint8List msg, Uint8List coins, {
    StepObserver observer = const NullStepObserver()
  }) {
    if( msg.length != 32 ) {
      throw ArgumentError("Message must be 32 bytes in length");
    }

    PolynomialMatrix t = pk.t.copy();
    PolynomialMatrix A = keyGenerator.expandA(pk.rho, isNtt: true);

    var (r, e1, e2) = keyGenerator.generateNoiseVectors(coins);
    r.toNtt();
    observer.addStep(
        title: "Generating noise vectors",
        description: "Generating vectors r, e1 and ring e2 "
            "from \"coins\" randomizer",
        parameters: {"coins": coins},
        results: {
          "r": r.copy(),
          "e1": e1.copy(),
          "e2": e2.copy()
        }
    );

    var msgPolynomial = PolynomialRing.deserialize(msg, 1, n, q).decompress(1);
    observer.addStep(
        title: "Transforming message into polynomial",
        description: "Decomposing each bit of the message into a "
            "polynomial coefficient and multiplying it by q/2",
        parameters: {"msg": msg},
        results: {"msg_poly": msgPolynomial}
    );

    PolynomialMatrix u = A.transpose()
        .multiply(r)
        .fromNtt()
        .plus(e1);

    observer.addStep(
        title: "Calculating matrix u",
        description: "Obtaining matrix by calculating (A*r)+e1.",
        parameters: {"A": A.copy(), "r": r.copy()},
        results: {"u": u.copy()}
    );

    PolynomialRing v = t.transpose() // 1xn
        .multiply(r) // nx1
        .fromNtt()
        .toRing() // 1x1 -> Unwraps into single PolynomialRing
        .plus(e2)
        .plus(msgPolynomial);

    observer.addStep(
        title: "Calculating ring v",
        description: "Obtaining matrix by calculating (t*r)+e2+msg",
        parameters: {
          "t": t.copy(),
          "r": r.copy(),
          "e2": e2.copy(),
          "msg_poly": msgPolynomial.copy()
        },
        results: {"v": v.copy()}
    );

    return PKECypher(u: u, v: v, du: du, dv: dv);
  }


  Uint8List decrypt(PKEPrivateKey sk, PKECypher cypher, {
    StepObserver observer = const NullStepObserver()
  }) {
    var sTransposed = sk.s.copy().transpose();
    var uHat = cypher.u.copy().toNtt();
    var v = cypher.v.copy();

    var msgPolynomial = sTransposed
                            .multiply(uHat)
                            .fromNtt()
                            .toRing();

    msgPolynomial = v.minus(msgPolynomial);
    observer.addStep(
        title: "Decrypting message polynomial",
        description: "Decrypt message polynomial by calculating v - (s*u)",
        parameters: {"v": v, "s": sTransposed, "u": uHat},
        results: {"msg_poly": msgPolynomial.copy()}
    );

    return msgPolynomial.compress(1).serialize(1);
  }


}