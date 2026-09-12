package com.mycompass.auth;

import com.google.api.client.googleapis.auth.oauth2.GoogleIdToken;
import com.google.api.client.googleapis.auth.oauth2.GoogleIdTokenVerifier;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.gson.GsonFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * Verifies a Google-issued ID token server-side — checks the signature against
 * Google's published public keys, confirms the audience matches our OAuth client ID,
 * and confirms it hasn't expired. Never trust a client-decoded token for identity;
 * this is the one place that decision gets made for real.
 */
@Service
public class GoogleTokenVerifier {

    private final GoogleIdTokenVerifier verifier;

    public GoogleTokenVerifier(@Value("${app.google.client-id}") String clientId) {
        this.verifier = new GoogleIdTokenVerifier.Builder(new NetHttpTransport(), GsonFactory.getDefaultInstance())
                .setAudience(Collections.singletonList(clientId))
                .build();
    }

    public GoogleUserInfo verify(String idTokenString) {
        GoogleIdToken idToken;
        try {
            // The underlying library can itself throw IllegalArgumentException (with no
            // useful message) for a malformed token string, alongside its declared
            // GeneralSecurityException/IOException — catch broadly here and always
            // normalize to our own message, rather than ever leaking a null/raw one.
            idToken = verifier.verify(idTokenString);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid Google token", ex);
        }

        if (idToken == null) {
            throw new IllegalArgumentException("Invalid Google token");
        }

        GoogleIdToken.Payload payload = idToken.getPayload();
        String googleId = payload.getSubject();
        String email = payload.getEmail();
        String name = (String) payload.get("name");

        return new GoogleUserInfo(googleId, email, name != null ? name : email);
    }
}
