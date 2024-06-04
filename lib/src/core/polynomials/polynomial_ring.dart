import 'dart:typed_data';

import 'package:post_quantum/src/core/bit_packing/bit_packing_helper.dart';
import 'package:post_quantum/src/core/ntt/ntt_helper.dart';

enum Modulus { regular, centered }

class PolynomialRing {
  List<int> coefficients;
  int q;
  int n;
  bool isNtt;
  NTTHelper? helper;
  Modulus modulusType;


  // --------- CONSTRUCTORS ---------
  /// Creates a new polynomial from a coefficient list.
  ///
  /// The coefficient list does not need to be normalized.
  /// If [skipModulo] is set, the coefficients will be treated as-is.
  factory PolynomialRing.from(
      List<int> coefficientList,
      int n,
      int q, {
        bool isNtt = false,
        Modulus modulusType = Modulus.regular,
        NTTHelper? helper,
        bool skipReduce = false
      }) {
    var normalizedCoefficients = _normalize(coefficientList, n);

    if(modulusType == Modulus.regular && skipReduce == false){
      normalizedCoefficients = _moduloCoefs(normalizedCoefficients, q);
    }

    return PolynomialRing._internal(normalizedCoefficients, n, q, isNtt, helper: helper, modulusType: modulusType);
  }

  factory PolynomialRing.zeros(
      int n,
      int q, {
        bool isNtt = false,
        Modulus modulusType = Modulus.regular,
        NTTHelper? helper
      }) {
    return PolynomialRing._internal(List.filled(n, 0), n, q, isNtt, helper: helper, modulusType: modulusType);
  }

  factory PolynomialRing.deserialize(
      Uint8List byteArray,
      int wordSize,
      int n,
      int q, {
        bool isNtt = false,
        Modulus modulusType = Modulus.regular,
        NTTHelper? helper,
        Endian endianness = Endian.little
      }) {
    var coefficients = BitPackingHelper.intsFromBytes(byteArray, wordSize);

    if(coefficients.length != n) {
      throw ArgumentError("Polynomial size n=$n was given but "
          "${coefficients.length} coefficients were found");
    }

    return PolynomialRing.from(coefficients, n, q, isNtt: isNtt, helper: helper, modulusType: modulusType);
  }

  PolynomialRing._internal(
      this.coefficients,
      this.n,
      this.q,
      this.isNtt, {
        this.helper,
        this.modulusType = Modulus.regular
  });




  // --------- INTERNAL METHODS ---------

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


  bool _checkNormBound(int n, int bound, int q) {
    int x;
    x = n % q;
    x = ((q - 1) >> 1) - x;
    x = x ^ (x >> 31);
    x = ((q - 1) >> 1) - x;
    return x >= bound;
  }

  /// Creates a new normalized list of coefficients
  static List<int> _normalize(List<int> coefficientList, int n) {
    if (coefficientList.length > n){
      throw ArgumentError("Coefficient list length cannot be greater than n");
    }

    List<int> coefficients = List.filled(n, 0);
    for (int i = 0; i < n && i < coefficientList.length; i++) {
      coefficients[i] = coefficientList[i];
    }
    return coefficients;
  }

  static List<int> _moduloCoefs(List<int> coefficients, int q) {
    var results = <int>[];
    for (var coef in coefficients) {
      results.add(coef.remainder(q));
    }
    return results;
  }





  // --------- INTERNAL METHODS ---------

  /// Compress [x] mod [q] down into [d] bits.
  ///
  /// Result is a number y, where 0 <= y < 2^d
  int _compress(int x, int d, int q) {
    var compressionLimit = 1<<d; // 2^d
    return ( (compressionLimit / q) * x ).round().remainder(compressionLimit);
  }

  /// Decompress [y] back to an [x]' mod [q]
  ///
  /// x' follows that abs(x' - x) <= Round( (q/2)^(d+1) )
  int _decompress(int y, int d, int q) {
    var compressionLimit = 1<<d; //2^d
    return ( (q / compressionLimit) * y ).round();
  }

  /// Divides [coefficients] by X^n + 1 and returns the remainder as a list of
  /// coefficients.
  ///
  /// For an explanation regarding the algorithm check out
  /// https://www.geeksforgeeks.org/division-algorithm-for-polynomials/
  List<int> _modulo(List<int> coefficients) {
    if(coefficients.length <= n) {
      return coefficients;
    }

    // g(X) = 1 * X^n + 1 * X^0 = X^n + 1
    List<int> denominator = List.filled(n+1, 0);
    denominator[n] = 1;
    denominator[0] = 1;


    List<int> numerator = List.from(coefficients);

    while (numerator.length >= denominator.length) {
      double factor = numerator.last / denominator.last;
      for (int i = 0; i < denominator.length; i++) {
        numerator[numerator.length - i - 1] = (numerator[numerator.length - i - 1] - factor * denominator[denominator.length - i - 1]).round();
      }
      numerator.removeLast();
    }

    return numerator;
  }







  // --------- PUBLIC METHODS ---------

  /// Adds this polynomial to g and returns a new polynomial
  ///
  /// For an in-depth explanation on the algorithm, please check out
  /// https://www.geeksforgeeks.org/program-add-two-polynomials/
  PolynomialRing plus(PolynomialRing g, {bool skipReduce = false}) {
    if (g.q != q) throw ArgumentError("g cannot have a different modulus q");
    if (g.n != n) throw ArgumentError("g cannot have a different n");
    if (g.isNtt != isNtt) throw ArgumentError("Polynomials must be in either both ntt or neither to be added");

    List<int> resultingCoefficients = List.filled(n, 0);
    for (int i=0; i<n; i++){
      int temp = coefficients[i] + g.coefficients[i];
      if (temp >= q){
        temp -= q;
      }
      resultingCoefficients[i] = temp;
    }

    return PolynomialRing.from(
        resultingCoefficients, n, q,
        isNtt: isNtt,
        helper: helper,
        skipReduce: skipReduce);
  }

  /// Multiplies this polynomial by a and returns the result as a new polynomial.
  PolynomialRing multiplyInt(int a) {
    List<int> resultingCoefficients = List.filled(coefficients.length, 0);

    for (int i=0; i < coefficients.length; i++) {
      resultingCoefficients[i] += coefficients[i] * a;
      resultingCoefficients[i] %= q;
    }

    return PolynomialRing.from(resultingCoefficients, n, q, isNtt: isNtt, helper: helper);
  }

  /// Multiplies this polynomial by g and returns the result as a new polynomial.
  ///
  /// For an in-depth explanation on the algorithm, please check out
  /// https://www.geeksforgeeks.org/multiply-two-polynomials-2/
  PolynomialRing multiply(PolynomialRing g, {bool skipReduce = false}) {
    if (g.q != q) throw ArgumentError("g cannot have a different modulus q");
    if (g.n != n) throw ArgumentError("g cannot have a different n");

    if (isNtt && g.isNtt) {
      var res = nttMultiply(g, skipReduce: skipReduce);
      return res;
    } else if (!isNtt && !g.isNtt) {
      return schoolbookMultiply(g);
    }

    throw ArgumentError("Both or neither polynomials must be in NTT form before multiplication");
  }

  PolynomialRing nttMultiply(PolynomialRing g, {bool skipReduce = false}) {
    if (helper == null) {
      throw StateError("Can only perform ntt reduction when parent element has an NTT Helper");
    }
    if (!isNtt || !g.isNtt) {
      throw StateError("Can only multiply using NTT if both polynomials are in NTT form");
    }

    List<int> newCoefs = helper!.nttCoefficientMultiplication(coefficients, g.coefficients);
    return PolynomialRing.from(newCoefs, n, q, isNtt: true, helper: helper, skipReduce: skipReduce);
  }

  PolynomialRing schoolbookMultiply(PolynomialRing g) {
    int resultingDegree = 2*(n-1);
    List<int> resultingCoefficients = List.filled(resultingDegree + 1, 0);

    for (int i=0; i < coefficients.length; i++) {
      for (int j=0; j < g.coefficients.length; j++) {
        resultingCoefficients[i + j] += coefficients[i] * g.coefficients[j];
        resultingCoefficients[i + j] %= q;
      }
    }

    return PolynomialRing.from(_modulo(resultingCoefficients), n, q, isNtt: false, helper: helper);
  }

  PolynomialRing toNtt() {
    if (helper == null) {
      throw StateError("Can only perform NTT transform when parent element has an NTT Helper");
    }
    return helper!.toNtt(this);
  }

  PolynomialRing fromNtt() {
    if (helper == null) {
      throw StateError("Can only perform NTT transform when parent element has an NTT Helper");
    }
    return helper!.fromNtt(this);
  }

  /// Compresses this polynomial from modulo [q] down to [d] bits.
  ///
  /// Achieves compression by individually compressing its coefficients
  PolynomialRing compress(int d) {
    List<int> compressedCoefficients = [];
    for (var coef in coefficients) {
      compressedCoefficients.add(_compress(coef, d, q));
    }
    return PolynomialRing.from(compressedCoefficients, n, q, isNtt: isNtt, helper: helper);
  }

  /// Decompresses this polynomial from [d] bits to modulo [q].
  ///
  /// Achieves decompression by individually decompressing its coefficients
  PolynomialRing decompress(int d) {
    List<int> decompressedCoefficients = [];
    for (var coef in coefficients) {
      decompressedCoefficients.add(_decompress(coef, d, q));
    }
    return PolynomialRing.from(decompressedCoefficients, n, q, isNtt: isNtt, helper: helper);
  }

  PolynomialRing minus(PolynomialRing g) {
    if (g.q != q) throw ArgumentError("g cannot have a different modulus q");
    if (g.n != n) throw ArgumentError("g cannot have a different n");
    if (g.isNtt != isNtt) throw ArgumentError("Polynomials must be in either both ntt or neither to be subtracted");

    List<int> resultingCoefficients = List.filled(n, 0);
    for (int i=0; i < n; i++) {
      resultingCoefficients[i] = (coefficients[i] - g.coefficients[i]) % q;
    }

    return PolynomialRing.from(resultingCoefficients, n, q, isNtt: isNtt, helper: helper);
  }

  (PolynomialRing p1, PolynomialRing p0) power2Round(int d) {
    var power2 = 1 << d;
    var p1Coefs = <int>[];
    var p0Coefs = <int>[];
    for (var r in coefficients){
      r = r % q;
      var r0 = _reduceModulus(r, power2);
      p1Coefs.add((r - r0) >> d);
      p0Coefs.add(r0);
    }

    return (
        PolynomialRing.from(p1Coefs, n, q, isNtt: isNtt, helper: helper),
        PolynomialRing.from(p0Coefs, n, q, modulusType: Modulus.centered, isNtt: isNtt, helper: helper)
    );
  }

  (PolynomialRing p1, PolynomialRing p0) decompose(int alpha) {
    var p1Coefs = <int>[];
    var p0Coefs = <int>[];
    for (var r in coefficients){
      var (r1, r0) = _decompose(r, alpha, q);
      p1Coefs.add(r1);
      p0Coefs.add(r0);
    }

    return (
    PolynomialRing.from(p1Coefs, n, q, isNtt: isNtt, helper: helper),
    PolynomialRing.from(p0Coefs, n, q, modulusType: Modulus.centered, isNtt: isNtt, helper: helper)
    );
  }

  Uint8List serialize(int w) {
    return BitPackingHelper.bytesFromInts(coefficients, w);
  }

  @override
  String toString() {
    return "Poly[$n]($coefficients)";
  }

  bool checkNormBound(int bound) {
    for (int c in coefficients) {
      if (_checkNormBound(c, bound, q)) return true;
    }
    return false;
  }

  PolynomialRing copy() {
    List<int> copiedCoefficients = [...coefficients];
    return PolynomialRing.from(
        copiedCoefficients,
        n,
        q,
        modulusType: modulusType,
        isNtt: isNtt,
        helper: helper
    );
  }

  PolynomialRing map(
      int Function(int coef) toElement, {
      bool inPlace = false
  }) {
    List<int> coeffs = coefficients;
    if(!inPlace) {
      coeffs = List.from(coefficients);
    }

    for (int i=0; i<coeffs.length; i++) {
      coeffs[i] = toElement(coeffs[i]);
    }

    if(inPlace) {
      return this;
    }
    return PolynomialRing._internal(coeffs, n, q, isNtt,
        modulusType: modulusType, helper: helper);
  }

  PolynomialRing toMontgomery() {
    if (helper == null) {
      throw StateError(
          "Can only perform Montgomery reduction "
              "when parent element has an NTT Helper");
    }
    return helper!.toMontgomery(this);
  }

  PolynomialRing reduceCoefficients() {
    for (int i=0; i<coefficients.length; i++) {
      coefficients[i] = coefficients[i] % q;
    }

    return this;
  }

}