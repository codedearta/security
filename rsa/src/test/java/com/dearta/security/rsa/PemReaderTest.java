package com.dearta.security.rsa;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.Test;

import javax.crypto.Cipher;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;
import java.util.Enumeration;

public class PemReaderTest {

    @Test
    public void LoadPem() throws IOException, GeneralSecurityException {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        PrivateKey privateKey = load2("private.pem");

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);

        File file = new File("../cypher.dat");
        FileInputStream fis = new FileInputStream(file);
        byte[] cypherData = new byte[(int) file.length()];
        fis.read(cypherData);
        fis.close();

        byte[] plainText = cipher.doFinal(cypherData);
        System.out.println("plain text: " + new String(plainText));
    }

    public PrivateKey load2(String filename) throws IOException, NoSuchProviderException {
        String key = readString(loadResourceFile(filename));
        String privKeyPEM = key.replace(
                "-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "").replace("\n", "");

        byte[] encodedPrivateKey = Base64.getDecoder().decode(privKeyPEM);

        try {
            ASN1Sequence primitive = (ASN1Sequence) ASN1Sequence
                    .fromByteArray(encodedPrivateKey);
            Enumeration<?> e = primitive.getObjects();
            BigInteger v = ((ASN1Integer) e.nextElement()).getValue();

            int version = v.intValue();
            if (version != 0 && version != 1) {
                throw new IllegalArgumentException("wrong version for RSA private key");
            }

            BigInteger modulus = ((ASN1Integer) e.nextElement()).getValue();
            BigInteger publicExponent = ((ASN1Integer) e.nextElement()).getValue();
            BigInteger privateExponent = ((ASN1Integer) e.nextElement()).getValue();

            RSAPrivateKeySpec spec = new RSAPrivateKeySpec(modulus, privateExponent);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            PrivateKey pk = kf.generatePrivate(spec);

            return pk;
        } catch (IOException e2) {
            throw new IllegalStateException();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (InvalidKeySpecException e) {
            throw new IllegalStateException(e);
        }
    }

    private InputStream loadResourceFile(String fileName){
        ClassLoader classloader = Thread.currentThread().getContextClassLoader();
        return classloader.getResourceAsStream(fileName);
    }

    private String readString(InputStream inputStream) throws IOException {

        BufferedReader reader = new BufferedReader(new InputStreamReader(inputStream));
        StringBuilder out = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            out.append(line);
        }
        reader.close();

        return out.toString();
    }

}
