package com.dearta.security.examples;

import com.dearta.security.jwt.JwtToken;
import com.google.common.base.Optional;
import io.dropwizard.auth.Authenticator;

/**
 * Created by sepp on 26.09.15.
 */
public class JwtAuthenticator implements Authenticator<String, com.dearta.security.examples.User> {

    private String secret;

    public JwtAuthenticator(String secret) {
        this.secret = secret;
    }

    public Optional<com.dearta.security.examples.User> authenticate(String jwtTokenString) {
        try {
            JwtToken jwtToken = JwtToken
                    .parseTokenFrom(jwtTokenString)
                    .verifySignature(this.secret)
                    .verifyExpiration();

            com.dearta.security.examples.User user = new com.dearta.security.examples.User(jwtToken.claims.get(JwtToken.CLAIM_NAME_USER));
            return Optional.of(user);
        } catch (Exception e) {
            return Optional.absent();
        }
    }
}