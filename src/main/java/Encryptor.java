import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Base64;
import util.AES;
import util.RSA;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.Key;
import java.security.KeyFactory;
import java.security.Security;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Encryptor {

  private static final String ALGORITHM_RSA = "RSA/None/PKCS1Padding";
  private static final String ALGORITHM_AES = "AES/CBC/PKCS7Padding";
  private static final String KEY_RSA = "RSA";
  private static final String KEY_AES = "AES";

  private final RSA utilRSA;
  private final AES utilAES;

  public Encryptor() throws Exception {
    Security.addProvider(new BouncyCastleProvider());

    KeyFactory keyFactoryRSA = KeyFactory.getInstance(KEY_RSA);
    KeyGenerator keyGeneratorAES = KeyGenerator.getInstance(KEY_AES);
    Cipher cipherRSA = Cipher.getInstance(ALGORITHM_RSA);
    Cipher cipherAES = Cipher.getInstance(ALGORITHM_AES);

    utilRSA = new RSA(keyFactoryRSA, cipherRSA);
    utilAES = new AES(keyGeneratorAES, cipherAES);
  }

  public Model encrypt(String plainContent, String keyRSAPublic) throws Exception {

    Key keyAES = utilAES.generateKey();
    RSAPublicKey pkRSA = utilRSA.parsePublicKey(keyRSAPublic);

    byte[][] encAESResult = utilAES.encrypt(keyAES, plainContent.getBytes());
    byte[] ivAES = encAESResult[0];
    byte[] encryptedContent = encAESResult[1];
    byte[] encryptedAESKey = utilRSA.encrypt(pkRSA, keyAES.getEncoded());

    String encodedAESKey = Base64.toBase64String(encryptedAESKey);
    String encodedIv = Base64.toBase64String(ivAES);
    String encodedContent = Base64.toBase64String(encryptedContent);

    return new Model(encodedAESKey, encodedIv, encodedContent);
  }

  public String decrypt(Model model, String keyRSAPrivate) throws Exception {

    RSAPrivateKey skRSA = utilRSA.parsePrivateKey(keyRSAPrivate);

    byte[] rawAESKey = Base64.decode(model.getKeyAES());
    byte[] rawIvAES = Base64.decode(model.getIvAES());
    byte[] rawContent = Base64.decode(model.getPayload());

    byte[] decryptedAESKey = utilRSA.decrypt(skRSA, rawAESKey);
    Key keyAES = utilAES.parseKey(decryptedAESKey);

    byte[] plainText = utilAES.decrypt(keyAES, rawIvAES, rawContent);

    return new String(plainText);
  }
}
