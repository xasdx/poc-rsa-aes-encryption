import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSA {

  public static final String RSA = "RSA";

  private final KeyFactory keyFactory;
  private final KeyPairGenerator generator;
  private final Cipher cipher;

  public RSA(Cipher cipher, KeyFactory keyFactory, KeyPairGenerator keyPairGenerator) {
    this.cipher = cipher;
    this.keyFactory = keyFactory;
    this.generator = keyPairGenerator;
  }

  public RSAPublicKey parsePublicKey(String key) throws Exception {
    return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(Base64.decode(key)));
  }

  public RSAPrivateKey parsePrivateKey(String key) throws Exception {
    return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(Base64.decode(key)));
  }

  public KeyPair generateKeyPair() {
    java.security.KeyPair keyPair = generator.genKeyPair();
    return new KeyPair(
      Base64.toBase64String(keyPair.getPrivate().getEncoded()),
      Base64.toBase64String(keyPair.getPublic().getEncoded())
    );
  }

  public byte[] encrypt(Key key, byte[] data) throws Exception {
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(data);
  }

  public byte[] decrypt(Key key, byte[] data) throws Exception {
    cipher.init(Cipher.DECRYPT_MODE, key);
    return cipher.doFinal(data);
  }
}
