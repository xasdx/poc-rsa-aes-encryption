package util;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class AES {

  private static final int AES_KEY_SIZE = 128;
  private static final String KEY_AES = "AES";

  private final KeyGenerator keyGenerator;
  private final Cipher cipher;

  public AES(KeyGenerator keyGenerator, Cipher cipher) {
    keyGenerator.init(AES_KEY_SIZE);
    this.keyGenerator = keyGenerator;
    this.cipher = cipher;
  }

  public Key generateKey() {
    return keyGenerator.generateKey();
  }

  public Key parseKey(byte[] key) {
    return new SecretKeySpec(key, KEY_AES);
  }

  public byte[][] encrypt(Key key, byte[] data) throws Exception {
    cipher.init(Cipher.ENCRYPT_MODE, key);
    return new byte[][]{cipher.getIV(), cipher.doFinal(data)};
  }

  public byte[] decrypt(Key key, byte[] iv, byte[] data) throws Exception {
    cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));
    return cipher.doFinal(data);
  }
}
