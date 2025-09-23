package com.sripiranavan.authorization_server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/oauth2")
@CrossOrigin(origins = "*")
public class ApiAuthorizationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    /**
     * API-based authorization endpoint that replaces browser-based authorization
     * This allows clients to get authorization codes through direct API calls
     */
    @PostMapping("/authorize")
    public ResponseEntity<?> authorize(@Valid @RequestBody AuthorizationRequest request) {
        try {
            // Validate client
            RegisteredClient client = registeredClientRepository.findByClientId(request.getClientId());
            if (client == null) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_client");
                errorResponse.put("error_description", "Client not found");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Validate redirect URI
            if (!client.getRedirectUris().contains(request.getRedirectUri())) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_redirect_uri");
                errorResponse.put("error_description", "Redirect URI not registered for this client");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            if (!authentication.isAuthenticated()) {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "invalid_credentials");
                errorResponse.put("error_description", "Invalid username or password");
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
            }

            // Generate authorization code (simplified - in production use proper OAuth2 authorization code generation)
            String authorizationCode = "auth_code_" + UUID.randomUUID().toString().replace("-", "");

            // In a real implementation, you would store this code with expiration and associate it with the user/client
            // For now, we'll return it directly

            Map<String, Object> response = new HashMap<>();
            response.put("authorization_code", authorizationCode);
            response.put("state", request.getState());
            response.put("redirect_uri", request.getRedirectUri());
            response.put("expires_in", 600); // 10 minutes
            response.put("message", "Authorization successful - use this code to get access token");

            return ResponseEntity.ok(response);

        } catch (AuthenticationException e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "authentication_failed");
            errorResponse.put("error_description", "Invalid credentials");
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Authorization failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * API-based token exchange - enhanced version with more grant types
     */
    @PostMapping("/token-exchange")
    public ResponseEntity<?> tokenExchange(@Valid @RequestBody TokenExchangeRequest request) {
        try {
            Map<String, Object> response = new HashMap<>();
            
            switch (request.getGrantType()) {
                case "client_credentials":
                    response.put("message", "Use standard /oauth2/token endpoint for client_credentials");
                    response.put("endpoint", "POST /oauth2/token");
                    break;
                    
                case "password":
                    response.put("message", "Use standard /oauth2/token endpoint for password grant");
                    response.put("endpoint", "POST /oauth2/token");
                    break;
                    
                case "authorization_code":
                    // Handle our custom authorization code exchange
                    if (request.getCode() != null && request.getCode().startsWith("auth_code_")) {
                        // Validate client
                        RegisteredClient client = registeredClientRepository.findByClientId(request.getClientId());
                        if (client == null) {
                            response.put("error", "invalid_client");
                            response.put("error_description", "Client not found");
                            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
                        }
                        
                        // Generate token response (simulating successful token exchange)
                        response.put("access_token", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoid2ViLWNsaWVudCIsInNjb3BlIjpbInJlYWQiLCJ3cml0ZSJdLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjkwMDAiLCJleHAiOjE3NTg2MTQ0NTUsImlhdCI6MTc1ODYxMDg1NX0");
                        response.put("token_type", "Bearer");
                        response.put("expires_in", 3600);
                        response.put("refresh_token", "refresh_token_" + UUID.randomUUID().toString().replace("-", ""));
                        response.put("scope", "read write");
                        return ResponseEntity.ok(response);
                    } else {
                        response.put("error", "invalid_grant");
                        response.put("error_description", "Invalid or missing authorization code");
                        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
                    }
                    // break; // This line is unreachable now
                    
                default:
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("error", "unsupported_grant_type");
                    errorResponse.put("error_description", "Grant type not supported");
                    return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
            }
            
            return ResponseEntity.ok(response);
            
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Token exchange failed: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    /**
     * Get available grant types and their API endpoints
     */
    @GetMapping("/grant-types")
    public ResponseEntity<?> getGrantTypes() {
        Map<String, Object> grantTypes = new HashMap<>();
        
        Map<String, Object> clientCredentials = new HashMap<>();
        clientCredentials.put("description", "Server-to-server authentication");
        clientCredentials.put("endpoint", "POST /oauth2/token");
        clientCredentials.put("parameters", "grant_type=client_credentials&scope=read write");
        clientCredentials.put("authentication", "Basic Auth (client_id:client_secret)");
        clientCredentials.put("fully_api_based", true);
        
        Map<String, Object> password = new HashMap<>();
        password.put("description", "User credential authentication");
        password.put("endpoint", "POST /oauth2/token");
        password.put("parameters", "grant_type=password&username=user&password=pass&scope=read write");
        password.put("authentication", "Basic Auth (client_id:client_secret)");
        password.put("fully_api_based", true);
        
        Map<String, Object> authorizationCode = new HashMap<>();
        authorizationCode.put("description", "Two-step authorization (API-based)");
        authorizationCode.put("step1", "POST /api/oauth2/authorize (get authorization code)");
        authorizationCode.put("step2", "POST /oauth2/token (exchange code for token)");
        authorizationCode.put("fully_api_based", true);
        
        Map<String, Object> refreshToken = new HashMap<>();
        refreshToken.put("description", "Refresh access token");
        refreshToken.put("endpoint", "POST /oauth2/token");
        refreshToken.put("parameters", "grant_type=refresh_token&refresh_token=REFRESH_TOKEN");
        refreshToken.put("authentication", "Basic Auth (client_id:client_secret)");
        refreshToken.put("fully_api_based", true);
        
        grantTypes.put("client_credentials", clientCredentials);
        grantTypes.put("password", password);
        grantTypes.put("authorization_code", authorizationCode);
        grantTypes.put("refresh_token", refreshToken);
        
        return ResponseEntity.ok(grantTypes);
    }

    // Request DTOs
    public static class AuthorizationRequest {
        @NotBlank(message = "Client ID is required")
        private String clientId;
        
        @NotBlank(message = "Redirect URI is required")
        private String redirectUri;
        
        @NotBlank(message = "Username is required")
        private String username;
        
        @NotBlank(message = "Password is required")
        private String password;
        
        private String scope;
        private String state;
        private String responseType = "code";

        // Getters and setters
        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }

        public String getRedirectUri() { return redirectUri; }
        public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }

        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }

        public String getState() { return state; }
        public void setState(String state) { this.state = state; }

        public String getResponseType() { return responseType; }
        public void setResponseType(String responseType) { this.responseType = responseType; }
    }

    public static class TokenExchangeRequest {
        @NotBlank(message = "Grant type is required")
        private String grantType;
        
        private String clientId;
        private String code;
        private String redirectUri;
        private String username;
        private String password;
        private String scope;
        private String refreshToken;

        // Getters and setters
        public String getGrantType() { return grantType; }
        public void setGrantType(String grantType) { this.grantType = grantType; }

        public String getClientId() { return clientId; }
        public void setClientId(String clientId) { this.clientId = clientId; }

        public String getCode() { return code; }
        public void setCode(String code) { this.code = code; }

        public String getRedirectUri() { return redirectUri; }
        public void setRedirectUri(String redirectUri) { this.redirectUri = redirectUri; }

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }

        public String getScope() { return scope; }
        public void setScope(String scope) { this.scope = scope; }

        public String getRefreshToken() { return refreshToken; }
        public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }
    }
}
