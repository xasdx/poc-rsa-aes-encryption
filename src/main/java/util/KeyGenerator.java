package util;

import org.bouncycastle.util.encoders.Base64;

import java.security.KeyPairGenerator;

/**
 * Key pair generator, providing a portable, base64 formatted pair.
 */
public class KeyGenerator {

  private final KeyPairGenerator generator;

  private KeyGenerator(KeyPairGenerator generator) {
    this.generator = generator;
  }

  public static KeyGenerator of(String algorithm, int bits) throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm);
    generator.initialize(bits);
    return new KeyGenerator(generator);
  }

  public KeyPair generate() {
    java.security.KeyPair keyPair = generator.genKeyPair();
    return new KeyPair(
      Base64.toBase64String(keyPair.getPrivate().getEncoded()),
      Base64.toBase64String(keyPair.getPublic().getEncoded())
    );
  }
}
