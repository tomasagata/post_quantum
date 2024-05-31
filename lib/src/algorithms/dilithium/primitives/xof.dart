import 'dart:typed_data';

import 'package:hashlib/hashlib.dart';

/// Wrapper for an eXtensible Output Function that takes in a message
/// and generates an infinite output SHAKE128 hash.
class XOF {
  factory XOF(Uint8List message) {
    var hashSink = const Shake128(0).createSink();
    hashSink.add(message);

    // Update the final block
    if (hashSink.pos == hashSink.blockLength) {
      hashSink.$update();
      hashSink.pos = 0;
    }

    // Setting the signature bytes
    hashSink.buffer[hashSink.pos] ^= hashSink.paddingByte;
    hashSink.buffer[hashSink.blockLength - 1] ^= 0x80;
    hashSink.$update();

    return XOF._internal(hashSink);
  }

  XOF._internal(this._hashSink);

  final BlockHashSink _hashSink;

  int _offset = 0;

  /// Reads [bytes] from the (infinitely long) digest.
  Uint8List read(int bytes) {
    var digestBytes = Uint8List(bytes);
    for (int i = 0; i < bytes; i++, _offset++) {
      if (_offset == _hashSink.blockLength) {
        _hashSink.$update(_hashSink.buffer);
        _offset = 0;
      }
      digestBytes[i] = _hashSink.buffer[_offset];
    }
    return digestBytes;
  }
}