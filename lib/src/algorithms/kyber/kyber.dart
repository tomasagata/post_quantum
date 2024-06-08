import 'dart:typed_data';

import 'package:post_quantum/src/algorithms/kyber/abstractions/kem_private_key.dart';
import 'package:post_quantum/src/algorithms/kyber/abstractions/kem_public_key.dart';
import 'package:hashlib/hashlib.dart';
import 'package:post_quantum/src/core/observer/null_step_observer.dart';
import 'package:post_quantum/src/core/observer/step_observer.dart';

import 'abstractions/pke_cipher.dart';
import 'kyber_pke/kyber_pke.dart';

class Kyber {

  /// Creates a new generic Kyber implementation
  ///
  /// A generic kyber implementation receives the following parameters:
  /// - __[n]__: Maximum degree of the used polynomials
  /// - __[k]__: Number of polynomials per vector
  /// - __[q]__: Modulus for numbers
  /// - __[eta_1], [eta_2]__: Size of "small" coefficients used in the private key and noise vectors.
  /// - __[du], [dv]__: How many bits to retain per coefficient of __u__ and __v__. Kyber will compress
  /// the cypher according to these two variables.
  Kyber({
    required this.n,
    required this.k,
    required this.q,
    required this.innerPKE
  });

  // WIP
  //
  // factory Kyber.custom({
  //   required int n,
  //   required int k,
  //   required int q,
  //   required int eta_1,
  //   required int eta_2,
  //   required int du,
  //   required int dv
  // }) {
  //   return Kyber(
  //       n: n, k: k, q: q,
  //       innerPKE: KyberPKE(
  //           n: n, k: k, q: q, eta1: eta_1, eta2: eta_2, du: du, dv: dv
  //       )
  //   );
  // }

  factory Kyber.kem512() {
    return Kyber(
        n: 256, k: 2, q: 3329,
        innerPKE: KyberPKE(
            n: 256, k: 2, q: 3329, eta1: 3, eta2: 2, du: 10, dv: 4
        )
    );
  }

  factory Kyber.kem768() {
    return Kyber(
        n: 256, k: 2, q: 3329,
        innerPKE: KyberPKE(
            n: 256, k: 3, q: 3329, eta1: 2, eta2: 2, du: 10, dv: 4
        )
    );
  }

  factory Kyber.kem1024() {
    return Kyber(
        n: 256, k: 2, q: 3329,
        innerPKE: KyberPKE(
            n: 256, k: 4, q: 3329, eta1: 2, eta2: 2, du: 11, dv: 5
        )
    );
  }



  // -------- MODEL PARAMETERS --------
  int n;
  int k;
  int q;
  KyberPKE innerPKE;



  // ----------- KYBER MATHEMATICAL PRIMITIVES -------------

  /// H primitive from Kyber specification.
  ///
  /// Takes in a variable length byte array and returns its SHA3_256 hash.
  Uint8List _h(Uint8List message) {
    return sha3_256.convert(message).bytes;
  }

  /// KDF primitive from Kyber specification.
  ///
  /// Takes in a variable length byte array and returns a 32 byte SHAKE256 hash.
  Uint8List _kdf(Uint8List message) {
    return shake256.of(32).convert(message).bytes;
  }

  /// G primitive from Kyber specification.
  ///
  /// G takes in a variable length seed and returns
  /// its SHA3-512 hash split in two.
  (Uint8List lower32Bytes, Uint8List upper32Bytes) _g(Uint8List seed) {
    var bytes = sha3_512.convert(seed).bytes;
    return (bytes.sublist(0, 32), bytes.sublist(32));
  }

  /// Joins two byte arrays A and B together.
  ///
  /// returns <code>A || B</code>
  Uint8List _join(Uint8List A, Uint8List B) {
    var result = BytesBuilder();
    result.add(A);
    result.add(B);
    return result.toBytes();
  }







  // ----------- PUBLIC KEM API -------------

  /// A Kyber keypair is derived deterministically from a
  /// 64-octet seed.
  (KemPublicKey pk, KemPrivateKey sk) generateKeys(Uint8List seed, {
    StepObserver observer = const NullStepObserver()
  }) {
    if( seed.length != 64 ) {
      throw ArgumentError("Seed must be 64 bytes in length");
    }

    // This z will be used only when decryption has failed.
    var z = seed.sublist(32);

    // Generate PKE keys for decryption and encryption of cyphers.
    var (pkPke, skPke) = innerPKE.generateKeys(seed.sublist(0, 32));
    observer.addStep(
      title: "Generate Kyber's internal PKE keys",
      description: "Using given seed to generate kyber encryption keys.",
      parameters: {"seed": seed},
      results: {"pk_pke": pkPke, "sk_pke": skPke}
    );

    var pk = KemPublicKey(publicKey: pkPke);
    observer.addStep(
      title: "Generate Kyber public key",
      description: "Using Kyber's internal PKE public key to "
        "generate a KEM public key.",
      parameters: {"pk_pke": pkPke},
      results: {"pk": pk}
    );

    var pkHash = _h(pkPke.serialize());
    var sk = KemPrivateKey(
        sk: skPke,
        pk: pkPke,
        pkHash: pkHash,
        z: z
    );
    observer.addStep(
        title: "Generate Kyber private key",
        description: "Using Kyber's internal PKE public key, private key and"
            " seed to generate a KEM secret key.",
        parameters: {
          "sk_pke": skPke,
          "pk_pke": pkPke,
          "pk_pke_hash": pkHash,
          "z": z
        },
        results: {"sk": pk}
    );

    return (pk, sk);
  }



  /// Kyber encapsulation takes a public key and a 32-octet seed
  /// and deterministically generates a shared secret and ciphertext
  /// for the public key.
  (PKECypher cipher, Uint8List sharedSecret) encapsulate(
      KemPublicKey pk, Uint8List nonce, {
        StepObserver observer = const NullStepObserver()
  }) {
    if( nonce.length != 32 ) {
      throw ArgumentError("Nonce must be 32 bytes in length");
    }

    // Calculate hashes.
    var nonceHash = _h(nonce);
    var publicKeyHash = _h(pk.serialize());
    observer.addStep(
      title: "Calculate pk and nonce hashes",
      description: "Calculating the SHA3-256 hash of both the nonce "
          "and the public key.",
      parameters: {"pk": pk, "nonce": nonce},
      results: {"pk_hash": publicKeyHash, "nonce_hash": nonceHash}
    );

    // Calculate seeds.
    var (sharedSecretSeed, encryptionRandomizer) = _g(
        _join(nonceHash, publicKeyHash) );
    observer.addStep(
      title: "Calculate shared secret seed and encryption randomizer",
      description: "Appending the bytes of the nonce and pk hashes and SHA3-256"
          "ing them again, generating a shared secret seed and an encryption "
          "randomizer.",
      parameters: {
        "nonce_hash": nonceHash,
        "ph_hash": publicKeyHash
      },
      results: {
        "shared_secret_seed": sharedSecretSeed,
        "encr_rand": encryptionRandomizer
      }
    );

    // Encrypt the nonce hash.
    var cipher = innerPKE.encrypt(
        pk.publicKey, nonceHash, encryptionRandomizer);
    observer.addStep(
      title: "Obtain ciphertext",
      description: "Encrypting nonce hash and retrieving ciphertext.",
      parameters: {"nonce_hash": nonceHash, "encr_rand":encryptionRandomizer},
      results: {"cipher": cipher}
    );

    // Calculate cipher hash.
    var cipherHash = _h(cipher.serialize());
    observer.addStep(
      title: "Hash ciphertext",
      description: "SHA3-256ing the ciphertext.",
      parameters: {"cipher": cipher},
      results: {"cipher_hash": cipherHash}
    );

    // Calculate shared secret.
    var sharedSecret = _kdf( _join(sharedSecretSeed, cipherHash) );
    observer.addStep(
      title: "Calculate shared secret",
      description: "Obtaining shared secret by SHAKE256ing the shared secret "
          "seed and the ciphertext hash.",
      parameters: {
        "shared_secret_seed": sharedSecretSeed,
        "cipher_hash": cipherHash},
      results: {
        "shared_secret": sharedSecret}
    );

    return (cipher, sharedSecret);
  }



  /// Kyber decapsulation takes the received cypher text from the other
  /// end and your public key, private key and 32-byte z value and
  /// returns a shared secret.
  ///
  /// - If decapsulation was successful, returns the shared key calculated in the
  /// encapsulation step.
  /// - If decapsulation was unsuccessful, returns an invalid shared key created
  /// with the given 32-byte z value calculated in the key-generation step.
  Uint8List decapsulate(PKECypher cipher, KemPrivateKey sk, {
    StepObserver observer = const NullStepObserver()
  }) {

    // Get attributes from private key
    var skPke = sk.sk;
    var pkPke = sk.pk;
    var pkHash = sk.pkHash;
    var z = sk.z;

    // Decrypt the nonce's hash used in the encapsulation step.
    // This will be used to recreate the cipher.
    var nonceHash = innerPKE.decrypt(skPke, cipher);
    observer.addStep(
      title: "Decrypt ciphertext",
      description: "Decrypting the ciphertext with the private key and "
          "retrieving the original nonce hash.",
      parameters: {"cipher": cipher, "sk_pke": skPke},
      results: {"nonce_hash": nonceHash}
    );

    // Recreate the cipher.
    // This is done to check if received and recreated cipher are the same.
    // If they do not match, a transmission or decryption error has occurred.
    var (sharedSecretSeed2, pkeSeed2) = _g( _join(nonceHash, pkHash) );
    var recreatedCipher = innerPKE.encrypt(pkPke, nonceHash, pkeSeed2);
    observer.addStep(
        title: "Recreate cipher",
        description: "Using the nonce and public key to recreate "
            "the ciphertext.",
        parameters: {"pk_hash": pkHash, "nonce_hash": nonceHash},
        results: {"recreated_cipher": recreatedCipher}
    );

    // Calculate the received cipher hash.
    var cipherHash = _h(cipher.serialize());
    observer.addStep(
        title: "Calculate the received cipher's hash",
        description: "SHA3-256ing the received ciphertext.",
        parameters: {"cipher": cipher},
        results: {"cipher_hash": cipherHash}
    );

    // Calculate the shared secret using received cipher.
    var sharedSecret = _kdf( _join(sharedSecretSeed2, cipherHash) );
    observer.addStep(
        title: "Calculate shared secret",
        description: "Obtaining the shared secret seed by using the nonce hash. "
            "By SHAKE256ing this and the received ciphertext hash, we obtain "
            "the shared secret.",
        parameters: {
          "shared_secret_seed": sharedSecretSeed2,
          "cipher_hash": cipherHash},
        results: {
          "shared_secret": sharedSecret}
    );

    // Create a constant time invalid shared secret to return when decryption
    // fails in order to avoid timing attacks.
    var failedSharedSecret = _kdf( _join(z, cipherHash) );
    observer.addStep(
        title: "Create throwaway shared secret",
        description: "Creating throwaway shared secret if received cipher "
            "and recreated one do not match.",
        parameters: {"z": z, "cipher_hash": cipherHash},
        results: {"failed_shared_secret": failedSharedSecret}
    );

    // If the received and recreated ciphers are equal,
    // this means that decryption was successful.
    //
    // WARNING: The implementation of this should be in constant time to
    // avoid timing attacks.
    if(cipher == recreatedCipher) {
      return sharedSecret;
    }
    return failedSharedSecret;
  }

}


