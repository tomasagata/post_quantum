import 'package:crystals_pqc/src/core/ntt/ntt_helper.dart';
import 'package:crystals_pqc/src/core/polynomials/polynomial_ring.dart';

class DilithiumNTTHelper implements NTTHelper {
  int q;
  int qInv;        // Multiplicative inverse of q mod 2^32
  int montR;       // 2^32 mod q
  int montR2;      // (2^32)^2 mod q = 2^64 mod q
  int montRInv;    // 1/(2^32) mod q
  int montMask;    // (1 << 32) - 1
  List<int> zetas; // Check https://www.nayuki.io/page/montgomery-reduction-algorithm
  int f;           // (2^64 / 256) mod q


  DilithiumNTTHelper._({
    required this.q,
    required this.qInv,
    required this.montR,
    required this.montR2,
    required this.montRInv,
    required this.montMask,
    required this.zetas,
    required this.f
  });

  // factory NTTHelper.kyber() {
  //   return NTTHelper(
  //     q: 3329,
  //     qInv: 3327,
  //     montR: 2285,
  //     montR2: 1353,
  //     montRInv: 169,
  //     montMask: 0xFFFF,
  //     zetas: [
  //       2285, 2571, 2970, 1812, 1493, 1422,  287,  202, 3158,  622, 1577,  182,  962, 2127, 1855, 1468,
  //        573, 2004,  264,  383, 2500, 1458, 1727, 3199, 2648, 1017,  732,  608, 1787,  411, 3124, 1758,
  //       1223,  652, 2777, 1015, 2036, 1491, 3047, 1785,  516, 3321, 3009, 2663, 1711, 2167,  126, 1469,
  //       2476, 3239, 3058,  830,  107, 1908, 3082, 2378, 2931,  961, 1821, 2604,  448, 2264,  677, 2054,
  //       2226,  430,  555,  843, 2078,  871, 1550,  105,  422,  587,  177, 3094, 3038, 2869, 1574, 1653,
  //       3083,  778, 1159, 3182, 2552, 1483, 2727, 1119, 1739,  644, 2457,  349,  418,  329, 3173, 3254,
  //        817, 1097,  603,  610, 1322, 2044, 1864,  384, 2114, 3193, 1218, 1994, 2455,  220, 2142, 1670,
  //       2144, 1799, 2051,  794, 1819, 2475, 2459,  478, 3221, 3021,  996,  991,  958, 1869, 1522, 1628
  //     ],
  //     f: 1441
  //   );
  // }

  factory DilithiumNTTHelper() {
    return DilithiumNTTHelper._(
      q: 8380417,
      qInv: 58728449,
      montR: 4193792,
      montR2: 2365951,
      montRInv: 8265825,
      montMask: 0xFFFFFFFF,
      zetas: [
        4193792,   25847, 5771523, 7861508,  237124, 7602457, 7504169,  466468, 1826347,
        2353451, 8021166, 6288512, 3119733, 5495562, 3111497, 2680103, 2725464, 1024112,
        7300517, 3585928, 7830929, 7260833, 2619752, 6271868, 6262231, 4520680, 6980856,
        5102745, 1757237, 8360995, 4010497,  280005, 2706023,   95776, 3077325, 3530437,
        6718724, 4788269, 5842901, 3915439, 4519302, 5336701, 3574422, 5512770, 3539968,
        8079950, 2348700, 7841118, 6681150, 6736599, 3505694, 4558682, 3507263, 6239768,
        6779997, 3699596,  811944,  531354,  954230, 3881043, 3900724, 5823537, 2071892,
        5582638, 4450022, 6851714, 4702672, 5339162, 6927966, 3475950, 2176455, 6795196,
        7122806, 1939314, 4296819, 7380215, 5190273, 5223087, 4747489,  126922, 3412210,
        7396998, 2147896, 2715295, 5412772, 4686924, 7969390, 5903370, 7709315, 7151892,
        8357436, 7072248, 7998430, 1349076, 1852771, 6949987, 5037034,  264944,  508951,
        3097992,   44288, 7280319,  904516, 3958618, 4656075, 8371839, 1653064, 5130689,
        2389356, 8169440,  759969, 7063561,  189548, 4827145, 3159746, 6529015, 5971092,
        8202977, 1315589, 1341330, 1285669, 6795489, 7567685, 6940675, 5361315, 4499357,
        4751448, 3839961, 2091667, 3407706, 2316500, 3817976, 5037939, 2244091, 5933984,
        4817955,  266997, 2434439, 7144689, 3513181, 4860065, 4621053, 7183191, 5187039,
         900702, 1859098,  909542,  819034,  495491, 6767243, 8337157, 7857917, 7725090,
        5257975, 2031748, 3207046, 4823422, 7855319, 7611795, 4784579,  342297,  286988,
        5942594, 4108315, 3437287, 5038140, 1735879,  203044, 2842341, 2691481, 5790267,
        1265009, 4055324, 1247620, 2486353, 1595974, 4613401, 1250494, 2635921, 4832145,
        5386378, 1869119, 1903435, 7329447, 7047359, 1237275, 5062207, 6950192, 7929317,
        1312455, 3306115, 6417775, 7100756, 1917081, 5834105, 7005614, 1500165,  777191,
        2235880, 3406031, 7838005, 5548557, 6709241, 6533464, 5796124, 4656147,  594136,
        4603424, 6366809, 2432395, 2454455, 8215696, 1957272, 3369112,  185531, 7173032,
        5196991,  162844, 1616392, 3014001,  810149, 1652634, 4686184, 6581310, 5341501,
        3523897, 3866901,  269760, 2213111, 7404533, 1717735,  472078, 7953734, 1723600,
        6577327, 1910376, 6712985, 7276084, 8119771, 4546524, 5441381, 6144432, 7959518,
        6094090,  183443, 7403526, 1612842, 4834730, 7826001, 3919660, 8332111, 7018208,
        3937738, 1400424, 7534263, 1976782
      ],
      f: 41978
    );
  }



  @override
  int montgomeryReduce(int a) {
    var t = (a*qInv) & montMask;
    t = (a - t*q) >> 32;
    if (t <= -(q >> 1) ) {
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

    while ( l > 0 ) {
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

    int k = 256, l = 1;
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
    
    List<int> coefs = List.generate(coefficients.length, (i) =>
      nttMultiply(coefficients[i], coefficients2[i])
    );
    return coefs;
  }

}