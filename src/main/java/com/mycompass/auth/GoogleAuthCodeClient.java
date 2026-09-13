package com.mycompass.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;

/**
 * Exchanges a one-time authorization code (issued to the frontend by Google's
 * popup-based auth-code flow) for Google's tokens, using our client secret -
 * this is the step that distinguishes the Authorization Code flow from the
 * simpler ID Token flow: only a backend holding the secret can complete it.
 */
@Service
public class GoogleAuthCodeClient {

    private static final String TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";

    private final RestClient restClient = RestClient.create();
    private final String clientId;
    private final String clientSecret;

    public GoogleAuthCodeClient(
            @Value("${app.google.client-id}") String clientId,
            @Value("${app.google.client-secret}") String clientSecret
    ) {
        this.clientId = clientId;
        this.clientSecret = clientSecret;
    }

    /**
     * Returns the ID token from Google's token response - the only piece we need,
     * since GoogleTokenVerifier already knows how to verify a raw ID token.
     */
    public String exchangeCodeForIdToken(String code) {
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("code", code);
        form.add("client_id", clientId);
        form.add("client_secret", clientSecret);
        // "postmessage" is Google's reserved sentinel redirect_uri for JS SDK
        // popup-based auth-code flows - not a real URI, and nothing to register.
        form.add("redirect_uri", "postmessage");
        form.add("grant_type", "authorization_code");

        GoogleTokenResponse response;
        try {
            response = restClient.post()
                    .uri(TOKEN_ENDPOINT)
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .body(form)
                    .retrieve()
                    .body(GoogleTokenResponse.class);
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid Google authorization code", ex);
        }

        if (response == null || response.idToken() == null) {
            throw new IllegalArgumentException("Invalid Google authorization code");
        }
        return response.idToken();
    }

    private record GoogleTokenResponse(
            @JsonProperty("id_token") String idToken,
            @JsonProperty("access_token") String accessToken
    ) {}
}
