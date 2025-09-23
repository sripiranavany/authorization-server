package com.sripiranavan.authorization_server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Simple configuration properties for OAuth2 Authorization Server URLs.
 * Only handles issuer URL and redirect URIs from application.yml.
 */
@Component
@ConfigurationProperties(prefix = "oauth2.server")
public class ServerProperties {

    /**
     * The issuer URL for the OAuth2 authorization server.
     * Used in JWT tokens and OAuth2 discovery.
     */
    private String issuerUrl = "http://localhost:9000";

    /**
     * Web client redirect URIs.
     */
    private List<String> webClientRedirectUris = new ArrayList<>();

    /**
     * Mobile client redirect URIs.
     */
    private List<String> mobileClientRedirectUris = new ArrayList<>();

    public ServerProperties() {
        // Default redirect URIs
        webClientRedirectUris.add("http://localhost:3000/callback");
        webClientRedirectUris.add("http://localhost:8080/login/oauth2/code/custom");

        mobileClientRedirectUris.add("http://localhost:3001/callback");
        mobileClientRedirectUris.add("myapp://callback");
    }

    // Getters and setters
    public String getIssuerUrl() {
        return issuerUrl;
    }

    public void setIssuerUrl(String issuerUrl) {
        this.issuerUrl = issuerUrl;
    }

    public List<String> getWebClientRedirectUris() {
        return webClientRedirectUris;
    }

    public void setWebClientRedirectUris(List<String> webClientRedirectUris) {
        this.webClientRedirectUris = webClientRedirectUris;
    }

    public List<String> getMobileClientRedirectUris() {
        return mobileClientRedirectUris;
    }

    public void setMobileClientRedirectUris(List<String> mobileClientRedirectUris) {
        this.mobileClientRedirectUris = mobileClientRedirectUris;
    }
}
