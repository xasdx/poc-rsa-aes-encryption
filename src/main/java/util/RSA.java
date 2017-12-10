package util;

import org.bouncycastle.util.encoders.Base64;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class RSA {

  private final KeyFactory keyFactory;
  private final Cipher cipher;

  public RSA(KeyFactory keyFactory, Cipher cipher) {
    this.keyFactory = keyFactory;
    this.cipher = cipher;
  }

  public RSAPublicKey parsePublicKey(String key) throws Exception {
    return (RSAPublicKey) keyFactory.generatePublic(new X509EncodedKeySpec(parsePEM(key)));
  }

  public RSAPrivateKey parsePrivateKey(String key) throws Exception {
    return (RSAPrivateKey) keyFactory.generatePrivate(new PKCS8EncodedKeySpec(parsePEM(key)));
  }

  public byte[] encrypt(Key key, byte[] data) throws Exception {
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return cipher.doFinal(data);
  }

  public byte[] decrypt(Key key, byte[] data) throws Exception {
    cipher.init(Cipher.DECRYPT_MODE, key);
    return cipher.doFinal(data);
  }

  private byte[] parsePEM(String pem) {
    return Base64.decode(cleanUpPEM(pem));
  }

  private String cleanUpPEM(String pem) {
    return pem
      .replace("-----BEGIN PUBLIC KEY-----", "")
      .replace("-----END PUBLIC KEY-----", "")
      .replace("-----BEGIN RSA PRIVATE KEY-----", "")
      .replace("-----END RSA PRIVATE KEY-----", "")
      .replace("\n", "");
  }
}
