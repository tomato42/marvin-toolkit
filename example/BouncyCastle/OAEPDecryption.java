import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.FileSystems;
import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.FileInputStream;
import javax.crypto.Cipher;
import java.security.Security;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.BadPaddingException;
import java.util.Arrays;

public class OAEPDecryption {
    public static void main(String[] args) throws Exception {
        System.out.println(args[0]);
        // Add BouncyCastle as a security provider
        Security.addProvider(new BouncyCastleProvider());

        // Load your private key in PKCS#8 format (replace with your key data)
        Path path = FileSystems.getDefault().getPath(args[0]);
        byte[] privateKeyData = Files.readAllBytes(path);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyData);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "BC");
        PrivateKey privateKey = keyFactory.generatePrivate(privateKeySpec);

        // Initialize the Cipher for decryption
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPwithSHA1andMGF1Padding", "BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        FileInputStream ciphersFile = new FileInputStream(args[1]);

        BufferedWriter timesFile = new BufferedWriter(new FileWriter(args[2]));

        timesFile.write("raw times\n");

        while (ciphersFile.available() != 0) {
            byte[] ciphertext = new byte[Integer.parseInt(args[3])];

            int ret = ciphersFile.read(ciphertext);

            // Decrypt the ciphertext
            long startTime = System.nanoTime();

            try {
                byte[] decryptedData = cipher.doFinal(ciphertext);
            } catch (BadPaddingException e) {}

            long elapsed = System.nanoTime() - startTime;

            // Convert the decrypted data to a string or perform any necessary processing
            //String plaintext = new String(decryptedData, "ASCII");
            //System.out.println("Decrypted Plaintext: " + plaintext);
            timesFile.write(Long.toString(elapsed) + "\n");
        }

        timesFile.close();
    }
}

