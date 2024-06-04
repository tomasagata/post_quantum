import 'package:post_quantum/src/core/ntt/ntt_helper.dart';
import 'package:post_quantum/src/core/polynomials/polynomial_ring.dart';

class KyberNTTHelper implements NTTHelper{
  int q;
  int qInv;        // Multiplicative inverse of q mod 2^32
  int montR;       // 2^32 mod q
  int montR2;      // (2^32)^2 mod q = 2^64 mod q
  int montRInv;    // 1/(2^32) mod q
  int montMask;    // (1 << 32) - 1
  List<int> zetas; // Check https://www.nayuki.io/page/montgomery-reduction-algorithm
  int f;           // (2^64 / 256) mod q


  KyberNTTHelper._({
    required this.q,
    required this.qInv,
    required this.montR,
    required this.montR2,
    required this.montRInv,
    required this.montMask,
    required this.zetas,
    required this.f
  });

  factory KyberNTTHelper() {
    return KyberNTTHelper._(
      q: 3329,
      qInv: 3327,
      montR: 2285,
      montR2: 1353,
      montRInv: 169,
      montMask: 0xFFFF,
      zetas: [
        2285, 2571, 2970, 1812, 1493, 1422,  287,  202, 3158,  622, 1577,  182,  962, 2127, 1855, 1468,
         573, 2004,  264,  383, 2500, 1458, 1727, 3199, 2648, 1017,  732,  608, 1787,  411, 3124, 1758,
        1223,  652, 2777, 1015, 2036, 1491, 3047, 1785,  516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
        2476, 3239, 3058,  830,  107, 1908, 3082, 2378, 2931,  961, 1821, 2604,  448, 2264,  677, 2054,
        2226,  430,  555,  843, 2078,  871, 1550,  105,  422,  587,  177, 3094, 3038, 2869, 1574, 1653,
        3083,  778, 1159, 3182, 2552, 1483, 2727, 1119, 1739,  644, 2457,  349,  418,  329, 3173, 3254,
         817, 1097,  603,  610, 1322, 2044, 1864,  384, 2114, 3193, 1218, 1994, 2455,  220, 2142, 1670,
        2144, 1799, 2051,  794, 1819, 2475, 2459,  478, 3221, 3021,  996,  991,  958, 1869, 1522, 1628
      ],
      f: 1441
    );
  }


  @override
  int montgomeryReduce(int a) {
    int u = (a*qInv) & montMask;
    int t = a + u*q;
    t = t >> 16;
    if (t >= q) {
      t-=q;
    }
    if (t < 0) {
      t+=q;
    }
    return t;
  }

  @override
  PolynomialRing toMontgomery(PolynomialRing ring) {
    List<int> nttCoefficients = [];
    for (var c in ring.coefficients) {
      nttCoefficients.add( nttMultiply(montR2, c) );
    }
    ring.coefficients = nttCoefficients;

    return ring;
  }

  @override
  PolynomialRing fromMontgomery(PolynomialRing ring) {
    List<int> normalizedCoefficients = [];
    for (var c in ring.coefficients) {
      normalizedCoefficients.add( montgomeryReduce(c) );
    }
    ring.coefficients = normalizedCoefficients;

    return ring;
  }

  @override
  int nttMultiply(int a, int b) {
    int c = a * b;
    return montgomeryReduce(c);
  }

  @override
  PolynomialRing toNtt(PolynomialRing ring) {
    if (ring.isNtt) {
      throw ArgumentError("Cannot NTT an already NTTed polynomial.");
    }

    int k = 0, l = 128;
    List<int> coefs = ring.coefficients;

    // while ( l > (128/zetas.length).floor() ) {
    while (l > 1) {
      int start = 0;

      while (start < 256) {
        k++;
        int zeta = zetas[k];
        int j = start;

        for(; j < start + l; j++) {
          int t = nttMultiply(zeta, coefs[j+l]);
          coefs[j+l] = coefs[j] - t;
          coefs[j]   = coefs[j] + t;
        }
        start = l + j;
      }
      l >>= 1;
    }

    ring.isNtt = true;
    return ring;
  }

  @override
  PolynomialRing fromNtt(PolynomialRing ring) {
    if (!ring.isNtt) {
      throw ArgumentError("Cannot normalize a non-NTT polynomial.");
    }

    int k = zetas.length, l = (256 / zetas.length).floor();
    List<int> coefs = ring.coefficients;

    while (l < 256) {
      int start = 0;

      while (start < 256) {
        k--;
        int zeta = -zetas[k];
        int j = start;

        for (; j < start + l; j++) {
          int t = coefs[j];
          coefs[j]   = t + coefs[j+l];
          coefs[j+l] = t - coefs[j+l];
          coefs[j+l] = nttMultiply(zeta, coefs[j+l]);
        }
        start = l + j;
      }
      l <<= 1;
    }

    for (int j=0; j<256; j++) {
      coefs[j] = nttMultiply(coefs[j], f);
    }

    ring.isNtt = false;
    return ring;
  }

  @override
  List<int> nttCoefficientMultiplication(
      List<int> coefficients, List<int> coefficients2) {
    if (coefficients.length != coefficients2.length) {
      throw ArgumentError("Coefficients must be of the same length");
    }

    List<int> newCoefs = [];
    for (int i=0; i<64; i++) {
      var (r0, r1) = nttBaseMultiplication(
          coefficients[4*i+0],  coefficients[4*i+1],
          coefficients2[4*i+0], coefficients2[4*i+1],
          zetas[64+i]);
      var (r2, r3) = nttBaseMultiplication(
          coefficients[4*i+2],  coefficients[4*i+3],
          coefficients2[4*i+2], coefficients2[4*i+3],
          -zetas[64+i]);
      newCoefs.addAll([r0, r1, r2, r3]);
    }
    return newCoefs;
  }

  (int r0, int r1) nttBaseMultiplication(a0, a1, b0, b1, zeta) {
    int r0 = nttMultiply(a1, b1);
    r0 = nttMultiply(r0, zeta);
    r0 += nttMultiply(a0, b0);
    int r1 = nttMultiply(a0, b1);
    r1 += nttMultiply(a1, b0);
    return (r0, r1);
  }

}