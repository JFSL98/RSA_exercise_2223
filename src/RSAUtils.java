import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.security.*;

public class RSAUtils {
    private static final String RSA_ALGORITHM = "RSA";
    private static final String RSA_SIGNATURE_ALGORITHM = "SHA256withRSA";

    public KeyPair generateRSAKeyPair(int keysize) throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance(RSA_ALGORITHM);
        generator.initialize(keysize);
        return generator.generateKeyPair();
    }

    public byte[] signFile(byte[] fileBytes, PrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        if (fileBytes == null) {
            throw new IllegalArgumentException("File bytes must not be null.");
        }

        Signature privateSignature = Signature.getInstance(RSA_SIGNATURE_ALGORITHM);
        privateSignature.initSign(privateKey);
        privateSignature.update(fileBytes);
        return privateSignature.sign();
    }

    public boolean isFileSignatureValid(byte[] fileBytes, PublicKey publicKey, byte[] signature) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        if (fileBytes == null) {
            throw new IllegalArgumentException("File bytes must not be null.");
        }

        Signature publicSignature = Signature.getInstance(RSA_SIGNATURE_ALGORITHM);
        publicSignature.initVerify(publicKey);
        publicSignature.update(fileBytes);
        return publicSignature.verify(signature);
    }

    public byte[] encryptData(byte[] fileBytes, PublicKey publicKey) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if (fileBytes == null) {
            throw new IllegalArgumentException("File bytes must not be null.");
        }

        Cipher encryptCipher = Cipher.getInstance(RSA_ALGORITHM);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return encryptCipher.doFinal(fileBytes);
    }

    public byte[] decryptData(byte[] fileBytes, PrivateKey privateKey) throws NoSuchPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, BadPaddingException, InvalidKeyException {
        if (fileBytes == null) {
            throw new IllegalArgumentException("File bytes must not be null.");
        }

        Cipher decryptCipher = Cipher.getInstance(RSA_ALGORITHM);
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        return decryptCipher.doFinal(fileBytes);
    }
}
