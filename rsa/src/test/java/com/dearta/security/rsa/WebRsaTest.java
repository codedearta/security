package com.dearta.security.rsa;

import org.junit.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.MatcherAssert.assertThat;



// http://www-cs-students.stanford.edu/~tjw/jsbn/
// http://www.codeproject.com/Articles/198646/Javascript-RSA-Encryption-and-Java-Decryption

/**
 * Created by sepp on 03.10.15.
 */
public class WebRsaTest {

//    @Test
//    public void EncryptDecryptTest() throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
//        WebRsa.generateKeyFiles("public.key", "private.key");
//        WebRsa webRsa = new WebRsa("public.key", "private.key");
//        String text = "text";
//        System.out.println("original text:"+ text);
//        byte[] cypherText = webRsa.encrypt(text);
//        System.out.println("cypher:" + new String(cypherText));
//        String decryptedText = webRsa.decrypt(cypherText);
//        System.out.println("decrypted:" + decryptedText);
//        assertThat(new String(cypherText), not(equalTo(text)));
//        assertThat(decryptedText, equalTo(text));
//        System.out.println(webRsa.getPublicKey());
//    }


    @Test
    public void DecryptFromWebTest() throws NoSuchAlgorithmException, IOException, ClassNotFoundException {
        //WebRsa.generateKeyFiles("public.key", "private.key");
        WebRsa webRsa = new WebRsa("public.key", "private.key");
        //String text = "text";
        //System.out.println("original text:"+ text);
        //byte[] cypherText = webRsa.encrypt(text);
        //System.out.println("cypher:" + new String(cypherText));
        System.out.println(webRsa.getPublicKey());

        String cypher = "cqv88uHLUTyX27Tk+y6vYW6dP6Sm6LjFuAlAhjvRpmp37Y81pudB8o601n8JMasVpUAxHvzAjZFfYMUMr48zeh1l6ZN/SbC4EjI4xv7ckODzRfln8m5KlMr+WfPaw5z255YOnNgPkm4ZxZ3oNeCmElOglsy4tQ9IPXAiYh4huOQ=";

        String decryptedText = webRsa.decrypt(cypher.getBytes());
        System.out.println("decrypted:" + decryptedText);
        //assertThat(new String(cypherText), not(equalTo(text)));
        //assertThat(decryptedText, equalTo(text));
    }
}
