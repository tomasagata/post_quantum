import 'dart:typed_data';

class BitPackingHelper {

  static List<int> intsFromBytes(Uint8List bytes, int bitSize) {
    List<int> numbers = List.filled((bytes.length * 8 / bitSize).floor(), 0);
    int numberBitsLeft = bitSize;
    int bytesBitsLeft = 8;
    int numIndex = 0;
    int byteIndex = 0;
    int mask = (1 << bitSize) - 1;

    while (byteIndex < bytes.length) {
      numbers[numIndex] |= (
          (bytes[byteIndex] >> (8 - bytesBitsLeft)) << (bitSize - numberBitsLeft)
      ) & mask;

      int numberBitsUsed = numberBitsLeft > bytesBitsLeft ? bytesBitsLeft : numberBitsLeft;
      numberBitsLeft -= numberBitsUsed;
      bytesBitsLeft -= numberBitsUsed;

      if(bytesBitsLeft == 0) {
        byteIndex++;
        bytesBitsLeft = 8;
      }

      if(numberBitsLeft == 0) {
        numIndex++;
        numberBitsLeft = bitSize;
      }
    }

    return numbers;
  }

  static Uint8List bytesFromInts(List<int> numbers, int bitSize) {
    Uint8List bytes = Uint8List((numbers.length * bitSize / 8).ceil());
    int numberBitsLeft = bitSize;
    int bytesBitsLeft = 8;
    int numIndex = 0;
    int byteIndex = 0;

    while (numIndex < numbers.length) {
      bytes[byteIndex] |= (
          ( numbers[numIndex] >> (bitSize - numberBitsLeft) ) << (8 - bytesBitsLeft)
      ) & 0xFF;

      int byteBitsUsed = numberBitsLeft > bytesBitsLeft ? bytesBitsLeft : numberBitsLeft;
      numberBitsLeft -= byteBitsUsed;
      bytesBitsLeft -= byteBitsUsed;

      if(bytesBitsLeft == 0) {
        byteIndex++;
        bytesBitsLeft = 8;
      }

      if(numberBitsLeft == 0) {
        numIndex++;
        numberBitsLeft = bitSize;
      }
    }

    return bytes;
  }

}