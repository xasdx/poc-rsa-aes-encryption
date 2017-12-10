import util.KeyGenerator;
import util.KeyPair;

public class Main {

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

  public static void main(String... args) throws Exception {

    KeyPair keyPair = KeyGenerator.of("RSA", 4096).generate();

    Encryptor app = new Encryptor();

    Model encryptedData = app.encrypt(PLAIN_TEXT_CONTENT, keyPair.getPublicKey());

    encryptedData.printConsole();
    encryptedData.exportToFile(EXPORT_FILE_NAME);

    String plainText = app.decrypt(encryptedData, keyPair.getPrivateKey());

    if (!PLAIN_TEXT_CONTENT.equals(plainText)) {
      throw new RuntimeException("The decrypted content does not match the original.");
    }
  }
}
