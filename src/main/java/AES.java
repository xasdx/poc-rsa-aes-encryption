import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;

public class AES {

  public static final String AES = "AES";

  private final KeyGenerator keyGenerator;
  private final Cipher cipher;

  public AES(Cipher cipher, KeyGenerator keyGenerator) {
    this.cipher = cipher;
    this.keyGenerator = keyGenerator;
  }

  public Key generateKey() {
    return keyGenerator.generateKey();
  }

  public Key parseKey(byte[] key) {
    return new SecretKeySpec(key, AES);
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
