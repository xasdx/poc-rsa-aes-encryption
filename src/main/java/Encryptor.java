import org.bouncycastle.util.encoders.Base64;

import java.security.Key;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class Encryptor {

  private final RSA rsa;
  private final AES aes;

  public Encryptor(RSA rsaUtil, AES aesUtil) {
    this.rsa = rsaUtil;
    this.aes = aesUtil;
  }

  public Model encrypt(String plainContent, String keyRSAPublic) throws Exception {

    Key keyAES = aes.generateKey();
    RSAPublicKey pkRSA = rsa.parsePublicKey(keyRSAPublic);

    byte[][] encAESResult = aes.encrypt(keyAES, plainContent.getBytes());
    byte[] ivAES = encAESResult[0];
    byte[] encryptedContent = encAESResult[1];
    byte[] encryptedAESKey = rsa.encrypt(pkRSA, keyAES.getEncoded());

    String encodedAESKey = Base64.toBase64String(encryptedAESKey);
    String encodedIv = Base64.toBase64String(ivAES);
    String encodedContent = Base64.toBase64String(encryptedContent);

    return new Model(encodedAESKey, encodedIv, encodedContent);
  }

  public String decrypt(Model model, String keyRSAPrivate) throws Exception {

    RSAPrivateKey skRSA = rsa.parsePrivateKey(keyRSAPrivate);

    byte[] rawAESKey = Base64.decode(model.getKeyAES());
    byte[] rawIvAES = Base64.decode(model.getIvAES());
    byte[] rawContent = Base64.decode(model.getPayload());

    byte[] decryptedAESKey = rsa.decrypt(skRSA, rawAESKey);
    Key keyAES = aes.parseKey(decryptedAESKey);

    byte[] plainText = aes.decrypt(keyAES, rawIvAES, rawContent);

    return new String(plainText);
  }
}
