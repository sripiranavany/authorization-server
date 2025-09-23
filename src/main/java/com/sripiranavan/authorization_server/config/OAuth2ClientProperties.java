package com.sripiranavan.authorization_server.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.ArrayList;

/**
 * Configuration properties to read OAuth2 client configurations from application.yml.
 * Maps to spring.security.oauth2.authorization-server.client section.
 */
@Component
@ConfigurationProperties(prefix = "spring.security.oauth2.authorization-server")
public class OAuth2ClientProperties {
    
    private Map<String, ClientConfig> client = new HashMap<>();
    
    public Map<String, ClientConfig> getClient() {
        return client;
    }
    
    public void setClient(Map<String, ClientConfig> client) {
        this.client = client;
    }
    
    /**
     * Configuration for individual OAuth2 clients.
     * Spring Boot automatically maps hyphenated properties to camelCase.
     */
    public static class ClientConfig {
        private String clientId;
        private String clientSecret;
        private List<String> authorizationGrantTypes = new ArrayList<>();
        private List<String> scopes = new ArrayList<>();
        private List<String> redirectUris = new ArrayList<>();
        
        public String getClientId() {
            return clientId;
        }
        
        public void setClientId(String clientId) {
            this.clientId = clientId;
        }
        
        public String getClientSecret() {
            return clientSecret;
        }
        
        public void setClientSecret(String clientSecret) {
            this.clientSecret = clientSecret;
        }
        
        public List<String> getAuthorizationGrantTypes() {
            return authorizationGrantTypes;
        }
        
        public void setAuthorizationGrantTypes(List<String> authorizationGrantTypes) {
            this.authorizationGrantTypes = authorizationGrantTypes;
        }
        
        public List<String> getScopes() {
            return scopes;
        }
        
        public void setScopes(List<String> scopes) {
            this.scopes = scopes;
        }
        
        public List<String> getRedirectUris() {
            return redirectUris;
        }
        
        public void setRedirectUris(List<String> redirectUris) {
            this.redirectUris = redirectUris;
        }
    }
}
