package com.dearta.security.rsa;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by sepp on 03.10.15.
 */
public class WebRsa {
    public static final String ALGORITHM = "RSA";
    public static final String MODE = "ECB";
    public static final String PADDING = "PKCS1Padding";
    public static final String ALG_MODE_PAD = ALGORITHM + "/" + MODE +"/" +PADDING;

    public static final int KEYSIZE = 1024;
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public WebRsa(String privateKeyFileNAme, String publicKeyFileName) throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
        loadKeys(privateKeyFileNAme, publicKeyFileName);
    }

    public byte[] encrypt(String text) {
        byte[] cipherText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALG_MODE_PAD);
            // encrypt the plain text using the public key
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            cipherText = cipher.doFinal(text.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        }


        return Base64.getEncoder().encode(cipherText);
    }

    public String decrypt(byte[] encrypted) {
        byte[] dectyptedText = null;
        try {
            // get an RSA cipher object and print the provider
            final Cipher cipher = Cipher.getInstance(ALG_MODE_PAD);

            // decrypt the text using the private key
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            dectyptedText = cipher.doFinal(Base64.getDecoder().decode(encrypted));

        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return new String(dectyptedText);
    }



    public static void generateKeyFiles(String publicKeyFileName, String privateKeyFileNAme) {
        try {
            final KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);
            keyGen.initialize(KEYSIZE);
            final KeyPair key = keyGen.generateKeyPair();

            File privateKeyFile = new File(privateKeyFileNAme);
            File publicKeyFile = new File(publicKeyFileName);

            // Create files to store public and private key
            if (privateKeyFile.getParentFile() != null) {
                privateKeyFile.getParentFile().mkdirs();
            }
            privateKeyFile.createNewFile();

            if (publicKeyFile.getParentFile() != null) {
                publicKeyFile.getParentFile().mkdirs();
            }
            publicKeyFile.createNewFile();

            // Saving the Public key in a file
            ObjectOutputStream publicKeyOS = new ObjectOutputStream(
                    new FileOutputStream(publicKeyFile));
            publicKeyOS.writeObject(key.getPublic());
            publicKeyOS.close();

            // Saving the Private key in a file
            ObjectOutputStream privateKeyOS = new ObjectOutputStream(
                    new FileOutputStream(privateKeyFile));
            privateKeyOS.writeObject(key.getPrivate());
            privateKeyOS.close();
        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    public void loadKeys(String publicKeyFileName, String privateKeyFileNAme) throws IOException, ClassNotFoundException {

        ObjectInputStream inputStream = new ObjectInputStream(new FileInputStream(publicKeyFileName));
        publicKey = (PublicKey) inputStream.readObject();

        inputStream = new ObjectInputStream(new FileInputStream(privateKeyFileNAme));
        privateKey = (PrivateKey) inputStream.readObject();

    }

    public Map<String,Object> getPublicKey() {

        String[] split = publicKey.toString().split("modulus: ");
        String[] split1 = split[1].split("public exponent:");

        String modulus = split1[0].trim();
        String exponent = split1[1].trim();
        BigInteger modulusDec = new BigInteger(modulus, 10);

        Map<String, Object> pubKeyAsMap = new HashMap<String, Object>();

        pubKeyAsMap.put("modulusDec", modulusDec);
        pubKeyAsMap.put("modulusHex", modulusDec.toString(16));
        pubKeyAsMap.put("exponent", new Integer(exponent));

        return pubKeyAsMap;
    }
}
