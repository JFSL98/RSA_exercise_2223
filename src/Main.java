import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.util.Arrays;

public class Main {
    static final int KEY_SIZE = 2048;

    // Read File
    public static byte[] readFileBytes(String pathName) throws IOException {
        Path filePath = Path.of(pathName);
        return Files.readAllBytes(filePath);
    }

    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("No arguments provided.");
            return;
        }

        RSAUtils rsa = new RSAUtils();
        String pathname = args[0];

        try {
            // Generate Key Pairs
            KeyPair pair = rsa.generateRSAKeyPair(KEY_SIZE);
            PublicKey publicKey = pair.getPublic();
            PrivateKey privateKey = pair.getPrivate();


            // Read File Bytes
            byte[] fileBytes = readFileBytes(pathname);

            // Sign
            byte[] signature = rsa.signFile(fileBytes, privateKey);

            // Verify
            boolean isCorrect = rsa.isFileSignatureValid(fileBytes, publicKey, signature);
            System.out.println("Signature is correct: " + isCorrect);
            if (!isCorrect) {
                System.out.println("Error verifying file.");
                return;
            }

            // Encrypt file
            byte[] encryptedFile = rsa.encryptData(fileBytes, publicKey);

            // Decrypt file
            byte[] decryptedFile = rsa.decryptData(encryptedFile, privateKey);

            System.out.println("File encrypted and decrypted successfully: " + Arrays.equals(fileBytes, decryptedFile));

        } catch (NoSuchAlgorithmException | IOException | SignatureException | InvalidKeyException |
                 NoSuchPaddingException | IllegalBlockSizeException | BadPaddingException e) {
            throw new RuntimeException(e);
        }
    }
}