package com.dearta.security.examples.resources;

import com.codahale.metrics.annotation.Timed;
import com.dearta.security.dropwizard.User;
import com.dearta.security.jwt.JwtToken;
import com.dearta.security.rsa.WebRsa;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.dropwizard.auth.Auth;
import com.dearta.security.examples.configuration.JwtConfiguration;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;

import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.*;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Base64;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by sepp on 26.09.15.
 */
@Path("/auth")
@Produces(MediaType.APPLICATION_JSON)
public class AuthResource {

    private JwtConfiguration jwtConfiguration;

    public AuthResource(JwtConfiguration jwtConfiguration) {
        this.jwtConfiguration = jwtConfiguration;
    }

    @POST
    @Timed
    @Consumes(MediaType.APPLICATION_JSON)
    public Map<String, String> post(Credentials credentials, @Context HttpServletRequest request) throws Exception {

        PrivateKey privateKey = load2("private.key");

        //String decrypt = webRsa.decrypt(credentials.password.getBytes());

        JwtToken token = new JwtToken("DEARTA")
                .withUserClaim(credentials.username)
                .withIdClaim()
                .withClientIpClaim(request.getRemoteAddr())
                .withExpireClaim(60)
                .sign(jwtConfiguration.getKey());

        Map<String, String> response = new HashMap<String, String>();
        response.put("access_token", token.toBase64());
        response.put("token_type","Bearer");
        response.put("expires_in", token.claims.get(JwtToken.CLAIM_NAME_EXPIRE));

        return response;
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


    @GET
    @Timed
    public User get(@Auth User user) {
        return user;
    }

    static class Credentials {
        @JsonProperty String username;
        @JsonProperty String password;
    }
}
