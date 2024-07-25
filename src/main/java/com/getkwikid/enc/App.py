package com.getkwikid.enc;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.io.pem.PemReader;
import java.security.spec.X509EncodedKeySpec;

import java.io.StringReader;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Security;


public class App {

private static PublicKey loadPemPublicKey(String pemPublicKey) throws Exception {
        PemReader pemReader = null;
        try {
            pemReader = new PemReader(new StringReader(pemPublicKey));
            byte[] pemBytes = pemReader.readPemObject().getContent();

            X509EncodedKeySpec spec = new X509EncodedKeySpec(pemBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(spec);
        } finally {
            if (pemReader != null) {
                pemReader.close();
            }
        }
    }

    public static void main(String[] args) {
        try {
            // Load the public key
	    
	    String pemPublicKey = "-----BEGIN PUBLIC KEY-----\nMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAsIwVStQi6aSMLBZu3vhafOR5NTMNp+TXPwyk/6VoaSQfDnZaSQPYhdt4a8X215KwXwpIL1eBJOH2NW8jp5AO4WauHWEwEggJvPaC8FgzZtDhjYexOk+/yaDbY7U9BofJSU76VIBxRoN7YmAknAKrpfn0ukXPPuUx5Ny/cy85nunqo5M8Acf2VVwSGZQMBZFSm3yxYOdS4laDlM+s1w+5wLDMjYSgIMm76rpVdO3hs2n2dSAYM6XMOaqNDwHdZk6n8lPgivYVXjTz7KU9eqkFnecWvn2ugRI7hgrplZxS020k0QBeYd0AH7zJZKS3Xo5VycL01UO/WYOQvB7v8lge7TiQZ3CCrnuykqcJ/r5DMLO/cKQAeZi+LQ95FQg39joO8G7bfO7+a3Gs8Re3mRW7AA8x1aEn7XZMOUu4l4IfNvwh20V4cz3xvGXdr9ZLFvgX5593MxCDBjkiaynzG8gmLVTIoaItPy+khwO/vjfWka0L3yvT3l55R4H/KRKxlHaY58HVdLbuWrUoH/4gbkYFYFC+rejBW5wbE0FJmWIkEXLKsTlXcsn6eAzi4BRxidQ/4rIEf8qWpSFzJobivBnWe4bpBA19g3N47PDpD5xS6uj7ODSBhEn22UnsiDaGV+RhsXYA/xqaJCjB6+W7CN00Lowr87sUoT4VAK8wrOk4D5sCAwEAAQ==\n-----END PUBLIC KEY-----";
            PublicKey publicKey = loadPemPublicKey(pemPublicKey);

            // Step 1: Generate a 16-byte Session Key
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(128); // 192 and 256 bits may require installation of the Java Cryptography Extension (JCE) Unlimited Strength
            SecretKey sessionKey = keyGenerator.generateKey();

            // Step 2: RSA Encrypt the Session Key
            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] encryptedSessionKey = rsaCipher.doFinal(sessionKey.getEncoded());

            // Base64-encode the encrypted session key
            String encryptedKeyBase64 = Base64.getEncoder().encodeToString(encryptedSessionKey);

            // Step 3: Encrypt the Data with AES/CBC/PKCS5Padding
            Cipher aesCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            // Generate IV
            byte[] iv = new byte[16];
            SecureRandom random = new SecureRandom();
            random.nextBytes(iv);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);

            aesCipher.init(Cipher.ENCRYPT_MODE, sessionKey, ivSpec);

            String requestData = "{\"MWIClientCode\":584162,\"InfinityId\":\"SUDHANSHU700\",\"FileID\":\"6\",\"ReferenceNumber\":\"12321345\"}";  // Your actual request data
            byte[] encryptedData = aesCipher.doFinal(requestData.getBytes(StandardCharsets.UTF_8));

            // Step 4: Prepare the final request data
            String ivBase64 = Base64.getEncoder().encodeToString(iv);
            String encryptedDataBase64 = Base64.getEncoder().encodeToString(encryptedData);

            // Constructing the final request JSON (using string formatting here for simplicity)
            String requestPayload = String.format(
                    "{\"requestId\":\"some_request_id\",\"service\":\"some_service\",\"encryptedKey\":\"%s\",\"oaepHashingAlgorithm\":\"NONE\",\"iv\":\"%s\",\"encryptedData\":\"%s\",\"clientInfo\":\"some_client_info\",\"optionalParam\":\"some_optional_params\"}",
                    encryptedKeyBase64, ivBase64, encryptedDataBase64
            );

            // Print the payload or initiate your network request here
            System.out.println(requestPayload);

        } catch (Exception e) {
            e.printStackTrace(); // Proper exception handling should be here
        }
    }
}

