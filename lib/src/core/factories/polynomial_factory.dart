import 'package:post_quantum/src/core/ntt/ntt_helper.dart';
import 'package:post_quantum/src/core/ntt/ntt_helper_dilithium.dart';
import 'package:post_quantum/src/core/ntt/ntt_helper_kyber.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring_matrix.dart';

class PolynomialFactory {
  int n;
  int q;
  NTTHelper helper;


  PolynomialFactory({
    required this.n,
    required this.q,
    required this.helper
  });

  factory PolynomialFactory.kyber() {
    return PolynomialFactory(
        n: 256,
        q: 3329,
        helper: KyberNTTHelper()
    );
  }

  factory PolynomialFactory.dilithium() {
    return PolynomialFactory(
      n: 256,
      q: 8380417,
      helper: DilithiumNTTHelper()
    );
  }



  PolynomialRing ring(
      List<int> coefficients, {
        bool isNtt = false,
        Modulus modulusType = Modulus.regular
  }) {
    return PolynomialRing.from(
        coefficients, n, q,
        helper: helper,
        modulusType: modulusType,
        isNtt: isNtt);
  }

  PolynomialMatrix vector(List<PolynomialRing> polynomials) {
    return PolynomialMatrix.vector(polynomials);
  }

  PolynomialMatrix matrix(List<PolynomialRing> polynomials, int rows, int columns) {
    return PolynomialMatrix.fromList(polynomials, rows, columns);
  }
}