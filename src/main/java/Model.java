import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class Model {

  private final String keyAES;
  private final String ivAES;
  private final String payload;

  public Model(String keyAES, String ivAES, String payload) {
    this.keyAES = keyAES;
    this.ivAES = ivAES;
    this.payload = payload;
  }

  public String getKeyAES() {
    return keyAES;
  }

  public String getIvAES() {
    return ivAES;
  }

  public String getPayload() {
    return payload;
  }

  @Override
  public String toString() {
    return getKeyAES() + "\n" + getIvAES() + "\n" + getPayload();
  }

  public void printConsole() {
    System.out.println(this);
  }

  public void exportToFile(String fileName) throws IOException {
    Files.write(Paths.get(fileName), Arrays.asList(this.toString().split("\n")));
  }
}
