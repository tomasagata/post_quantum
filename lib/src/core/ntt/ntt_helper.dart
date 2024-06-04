import 'package:post_quantum/src/core/polynomials/polynomial_ring.dart';

abstract class NTTHelper {

  int montgomeryReduce(int a);

  PolynomialRing toMontgomery(PolynomialRing ring);

  PolynomialRing fromMontgomery(PolynomialRing ring);

  int nttMultiply(int a, int b);

  PolynomialRing toNtt(PolynomialRing ring);

  PolynomialRing fromNtt(PolynomialRing ring);

  List<int> nttCoefficientMultiplication(
      List<int> coefficients, List<int> coefficients2);

}