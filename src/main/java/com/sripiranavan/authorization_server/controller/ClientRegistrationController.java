package com.sripiranavan.authorization_server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.time.Duration;
import java.util.*;

@RestController
@RequestMapping("/api/clients")
@CrossOrigin(origins = "*")
public class ClientRegistrationController {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/register")
    public ResponseEntity<?> registerClient(@Valid @RequestBody ClientRegistrationRequest request) {
        try {
            String clientId = request.getClientId() != null ? request.getClientId() : generateClientId();
            String clientSecret = request.getClientSecret() != null ? request.getClientSecret() : generateClientSecret();

            RegisteredClient.Builder clientBuilder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(clientId)
                .clientSecret(passwordEncoder.encode(clientSecret))
                .clientName(request.getClientName());

            // Set authentication methods
            if (request.getClientAuthenticationMethods() != null && !request.getClientAuthenticationMethods().isEmpty()) {
                for (String method : request.getClientAuthenticationMethods()) {
                    clientBuilder.clientAuthenticationMethod(new ClientAuthenticationMethod(method));
                }
            } else {
                clientBuilder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            }

            // Set grant types
            if (request.getGrantTypes() != null && !request.getGrantTypes().isEmpty()) {
                for (String grantType : request.getGrantTypes()) {
                    clientBuilder.authorizationGrantType(new AuthorizationGrantType(grantType));
                }
            } else {
                clientBuilder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
            }

            // Set redirect URIs
            if (request.getRedirectUris() != null && !request.getRedirectUris().isEmpty()) {
                for (String redirectUri : request.getRedirectUris()) {
                    clientBuilder.redirectUri(redirectUri);
                }
            }

            // Note: postLogoutRedirectUri not available in OAuth2 Authorization Server 0.4.5
            // This feature will be available in newer versions

            // Set scopes
            if (request.getScopes() != null && !request.getScopes().isEmpty()) {
                for (String scope : request.getScopes()) {
                    clientBuilder.scope(scope);
                }
            } else {
                clientBuilder.scope("read").scope("write");
            }

            // Set token settings
            TokenSettings.Builder tokenSettingsBuilder = TokenSettings.builder();
            if (request.getAccessTokenTimeToLive() != null) {
                tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofSeconds(request.getAccessTokenTimeToLive()));
            } else {
                tokenSettingsBuilder.accessTokenTimeToLive(Duration.ofHours(1));
            }

            if (request.getRefreshTokenTimeToLive() != null) {
                tokenSettingsBuilder.refreshTokenTimeToLive(Duration.ofSeconds(request.getRefreshTokenTimeToLive()));
            } else {
                tokenSettingsBuilder.refreshTokenTimeToLive(Duration.ofDays(30));
            }

            tokenSettingsBuilder.reuseRefreshTokens(request.getReuseRefreshTokens() != null ? request.getReuseRefreshTokens() : false);
            clientBuilder.tokenSettings(tokenSettingsBuilder.build());

            // Set client settings
            ClientSettings.Builder clientSettingsBuilder = ClientSettings.builder();
            clientSettingsBuilder.requireAuthorizationConsent(request.getRequireAuthorizationConsent() != null ? request.getRequireAuthorizationConsent() : false);
            clientSettingsBuilder.requireProofKey(request.getRequireProofKey() != null ? request.getRequireProofKey() : false);
            clientBuilder.clientSettings(clientSettingsBuilder.build());

            RegisteredClient registeredClient = clientBuilder.build();

            // Note: In a real implementation, you would save this to a persistent store
            // For now, we'll just return the client information
            
            Map<String, Object> response = new HashMap<>();
            response.put("client_id", clientId);
            response.put("client_secret", clientSecret);
            response.put("client_name", request.getClientName());
            response.put("grant_types", request.getGrantTypes());
            response.put("redirect_uris", request.getRedirectUris());
            response.put("scopes", request.getScopes());
            response.put("created_at", System.currentTimeMillis() / 1000);
            response.put("status", "registered");

            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "registration_failed");
            errorResponse.put("error_description", "Client registration failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

    @GetMapping("/{clientId}")
    public ResponseEntity<?> getClient(@PathVariable String clientId) {
        try {
            RegisteredClient client = registeredClientRepository.findByClientId(clientId);
            if (client == null) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "client_not_found");
                errorResponse.put("error_description", "Client with ID " + clientId + " not found");
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
            }

            Map<String, Object> response = new HashMap<>();
            response.put("client_id", client.getClientId());
            response.put("client_name", client.getClientName());
            response.put("grant_types", client.getAuthorizationGrantTypes().stream().map(AuthorizationGrantType::getValue).toArray());
            response.put("redirect_uris", client.getRedirectUris());
            // Note: postLogoutRedirectUris not available in OAuth2 Authorization Server 0.4.5
            response.put("scopes", client.getScopes());
            response.put("client_authentication_methods", client.getClientAuthenticationMethods().stream().map(ClientAuthenticationMethod::getValue).toArray());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Failed to retrieve client information");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @GetMapping
    public ResponseEntity<?> listClients() {
        try {
            // In a real implementation, you would retrieve all clients from your persistent store
            // For now, we'll return the predefined clients
            List<Map<String, Object>> clients = new ArrayList<>();
            
            Map<String, Object> apiClient = new HashMap<>();
            apiClient.put("client_id", "api-client");
            apiClient.put("client_name", "API Client");
            apiClient.put("grant_types", Arrays.asList("client_credentials", "refresh_token"));
            apiClient.put("scopes", Arrays.asList("read", "write", "admin"));
            clients.add(apiClient);

            Map<String, Object> webClient = new HashMap<>();
            webClient.put("client_id", "web-client");
            webClient.put("client_name", "Web Client");
            webClient.put("grant_types", Arrays.asList("authorization_code", "refresh_token"));
            webClient.put("scopes", Arrays.asList("openid", "profile", "email", "read", "write"));
            clients.add(webClient);

            Map<String, Object> mobileClient = new HashMap<>();
            mobileClient.put("client_id", "mobile-client");
            mobileClient.put("client_name", "Mobile Client");
            mobileClient.put("grant_types", Arrays.asList("password", "refresh_token"));
            mobileClient.put("scopes", Arrays.asList("read", "write", "openid", "profile"));
            clients.add(mobileClient);

            Map<String, Object> response = new HashMap<>();
            response.put("clients", clients);
            response.put("total", clients.size());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Failed to retrieve clients list");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    private String generateClientId() {
        return "client_" + UUID.randomUUID().toString().replace("-", "").substring(0, 16);
    }

    private String generateClientSecret() {
        return UUID.randomUUID().toString().replace("-", "") + UUID.randomUUID().toString().replace("-", "");
    }

    // Request DTO
    public static class ClientRegistrationRequest {
        private String clientId;
        private String clientSecret;
        
        @NotBlank(message = "Client name is required")
        private String clientName;
        
        private List<String> clientAuthenticationMethods;
        private List<String> grantTypes;
        private List<String> redirectUris;
        private List<String> postLogoutRedirectUris;
        private List<String> scopes;
        private Long accessTokenTimeToLive;
        private Long refreshTokenTimeToLive;
        private Boolean reuseRefreshTokens;
        private Boolean requireAuthorizationConsent;
        private Boolean requireProofKey;

        // Getters and setters
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }

        public String getClientSecret() { return clientSecret; }
        public void setClientSecret(String clientSecret) { this.clientSecret = clientSecret; }

        public String getClientName() { return clientName; }
        public void setClientName(String clientName) { this.clientName = clientName; }

        public List<String> getClientAuthenticationMethods() { return clientAuthenticationMethods; }
        public void setClientAuthenticationMethods(List<String> clientAuthenticationMethods) { this.clientAuthenticationMethods = clientAuthenticationMethods; }

        public List<String> getGrantTypes() { return grantTypes; }
        public void setGrantTypes(List<String> grantTypes) { this.grantTypes = grantTypes; }

        public List<String> getRedirectUris() { return redirectUris; }
        public void setRedirectUris(List<String> redirectUris) { this.redirectUris = redirectUris; }

        public List<String> getPostLogoutRedirectUris() { return postLogoutRedirectUris; }
        public void setPostLogoutRedirectUris(List<String> postLogoutRedirectUris) { this.postLogoutRedirectUris = postLogoutRedirectUris; }

        public List<String> getScopes() { return scopes; }
        public void setScopes(List<String> scopes) { this.scopes = scopes; }

        public Long getAccessTokenTimeToLive() { return accessTokenTimeToLive; }
        public void setAccessTokenTimeToLive(Long accessTokenTimeToLive) { this.accessTokenTimeToLive = accessTokenTimeToLive; }

        public Long getRefreshTokenTimeToLive() { return refreshTokenTimeToLive; }
        public void setRefreshTokenTimeToLive(Long refreshTokenTimeToLive) { this.refreshTokenTimeToLive = refreshTokenTimeToLive; }

        public Boolean getReuseRefreshTokens() { return reuseRefreshTokens; }
        public void setReuseRefreshTokens(Boolean reuseRefreshTokens) { this.reuseRefreshTokens = reuseRefreshTokens; }

        public Boolean getRequireAuthorizationConsent() { return requireAuthorizationConsent; }
        public void setRequireAuthorizationConsent(Boolean requireAuthorizationConsent) { this.requireAuthorizationConsent = requireAuthorizationConsent; }

        public Boolean getRequireProofKey() { return requireProofKey; }
        public void setRequireProofKey(Boolean requireProofKey) { this.requireProofKey = requireProofKey; }
    }
}
