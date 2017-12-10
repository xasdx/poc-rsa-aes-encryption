import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.Security;

public class Main {

  private static final String ALGORITHM_RSA = "RSA/None/PKCS1Padding";
  private static final String ALGORITHM_AES = "AES/CBC/PKCS7Padding";
  private static final int AES_KEY_SIZE = 128;
  private static final int RSA_KEY_SIZE = 4096;

  private static final String EXPORT_FILE_NAME = "model.txt";

  private static final String PLAIN_TEXT_CONTENT = "Two households, both alike in dignity,\n"
    + "In fair Verona, where we lay our scene,\n"
    + "From ancient grudge break to new mutiny,\n"
    + "Where civil blood makes civil hands unclean.\n"
    + "From forth the fatal loins of these two foes\n"
    + "A pair of star-cross'd lovers take their life;\n"
    + "Whose misadventured piteous overthrows\n"
    + "Do with their death bury their parents' strife.\n"
    + "The fearful passage of their death-mark'd love,\n"
    + "And the continuance of their parents' rage,\n"
    + "Which, but their children's end, nought could remove,\n"
    + "Is now the two hours' traffic of our stage;\n"
    + "The which if you with patient ears attend,\n"
    + "What here shall miss, our toil shall strive to mend.";

  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  public static void main(String... args) throws Exception {

    RSA rsa = assembleRSAEncryptor();
    AES aes = assembleAESEncryptor();

    Encryptor encryptor = new Encryptor(rsa, aes);
    KeyPair keyPair = rsa.generateKeyPair();

    Model encryptedData = encryptor.encrypt(PLAIN_TEXT_CONTENT, keyPair.getPublicKey());

    encryptedData.printConsole();
    encryptedData.exportToFile(EXPORT_FILE_NAME);

    String plainText = encryptor.decrypt(encryptedData, keyPair.getPrivateKey());

    if (!PLAIN_TEXT_CONTENT.equals(plainText)) {
      throw new RuntimeException("The decrypted content does not match the original.");
    }
  }

  private static RSA assembleRSAEncryptor() throws Exception {

    KeyPairGenerator rsaKeyGenerator = KeyPairGenerator.getInstance(RSA.RSA);
    rsaKeyGenerator.initialize(RSA_KEY_SIZE);

    return new RSA(
      Cipher.getInstance(ALGORITHM_RSA),
      KeyFactory.getInstance(RSA.RSA),
      rsaKeyGenerator
    );
  }

  private static AES assembleAESEncryptor() throws Exception {

    KeyGenerator aesKeyGenerator = KeyGenerator.getInstance(AES.AES);
    aesKeyGenerator.init(AES_KEY_SIZE);

    return new AES(
      Cipher.getInstance(ALGORITHM_AES),
      aesKeyGenerator
    );
  }
}
