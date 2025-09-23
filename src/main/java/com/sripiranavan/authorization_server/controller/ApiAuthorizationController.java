package com.sripiranavan.authorization_server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import java.util.Base64;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.security.oauth2.server.authorization.token.*;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

@RestController
@RequestMapping("/api/oauth2")
@CrossOrigin(origins = "*")
public class ApiAuthorizationController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;
    
    @Autowired
    private OAuth2AuthorizationService authorizationService;
    
    @Autowired
    private OAuth2TokenGenerator<?> tokenGenerator;
    
    @Autowired
    private JwtEncoder jwtEncoder;
    
    // In-memory storage for authorization codes (in production, use Redis or database)
    private final Map<String, AuthorizationCodeData> authorizationCodes = new ConcurrentHashMap<>();

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
                return createErrorResponse("invalid_client", "Client not found", HttpStatus.BAD_REQUEST);
            }

            // Validate that client supports authorization code grant
            if (!client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.AUTHORIZATION_CODE)) {
                return createErrorResponse("unsupported_grant_type", "Client does not support authorization code grant", HttpStatus.BAD_REQUEST);
            }

            // Validate redirect URI
            if (!client.getRedirectUris().contains(request.getRedirectUri())) {
                return createErrorResponse("invalid_redirect_uri", "Redirect URI not registered for this client", HttpStatus.BAD_REQUEST);
            }

            // Authenticate user
            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword())
            );

            if (!authentication.isAuthenticated()) {
                return createErrorResponse("invalid_credentials", "Invalid username or password", HttpStatus.UNAUTHORIZED);
            }

            // Set scopes
            Set<String> authorizedScopes = validateAndGetScopes(request.getScope(), client.getScopes());

            // Generate authorization code (simple UUID-based approach)
            String authorizationCode = "auth_code_" + UUID.randomUUID().toString().replace("-", "");
            Instant expiresAt = Instant.now().plus(10, ChronoUnit.MINUTES);
            
            // Store authorization code with metadata
            AuthorizationCodeData codeData = new AuthorizationCodeData(
                authorizationCode, 
                request.getClientId(), 
                authentication.getName(), 
                request.getRedirectUri(),
                authorizedScopes,
                expiresAt
            );
            authorizationCodes.put(authorizationCode, codeData);

            Map<String, Object> response = new HashMap<>();
            response.put("authorization_code", authorizationCode);
            response.put("state", request.getState());
            response.put("redirect_uri", request.getRedirectUri());
            response.put("expires_in", 600); // 10 minutes
            response.put("scope", String.join(" ", authorizedScopes));
            response.put("message", "Authorization successful - use this code to get access token");

            return ResponseEntity.ok(response);

        } catch (AuthenticationException e) {
            return createErrorResponse("authentication_failed", "Invalid credentials", HttpStatus.UNAUTHORIZED);
        } catch (Exception e) {
            return createErrorResponse("server_error", "Authorization failed: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * API-based token exchange for authorization code grant
     * This endpoint exchanges authorization codes for access tokens
     */
    @PostMapping("/token")
    public ResponseEntity<?> exchangeToken(@Valid @RequestBody TokenExchangeRequest request) {
        try {
            if (!"authorization_code".equals(request.getGrantType())) {
                return createErrorResponse("unsupported_grant_type", "Only authorization_code grant type is supported by this endpoint", HttpStatus.BAD_REQUEST);
            }

            // Validate authorization code
            AuthorizationCodeData codeData = authorizationCodes.get(request.getCode());
            if (codeData == null) {
                return createErrorResponse("invalid_grant", "Invalid or expired authorization code", HttpStatus.BAD_REQUEST);
            }

            // Check if code is expired
            if (Instant.now().isAfter(codeData.getExpiresAt())) {
                authorizationCodes.remove(request.getCode());
                return createErrorResponse("invalid_grant", "Authorization code has expired", HttpStatus.BAD_REQUEST);
            }

            // Validate client
            RegisteredClient client = registeredClientRepository.findByClientId(request.getClientId());
            if (client == null || !client.getClientId().equals(codeData.getClientId())) {
                return createErrorResponse("invalid_client", "Invalid client for this authorization code", HttpStatus.BAD_REQUEST);
            }

            // Validate redirect URI
            if (!Objects.equals(request.getRedirectUri(), codeData.getRedirectUri())) {
                return createErrorResponse("invalid_grant", "Redirect URI mismatch", HttpStatus.BAD_REQUEST);
            }

            // Create authentication for token generation
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                codeData.getPrincipalName(), null, Collections.emptyList());
            SecurityContextHolder.getContext().setAuthentication(authentication);

            // Generate access token using the standard OAuth2 token endpoint approach
            // For now, let's create a simple JWT-like token structure
            String accessTokenValue = generateJwtToken(client, authentication, codeData.getScopes());
            
            // Create OAuth2Token wrapper
            OAuth2Token accessToken = new OAuth2Token() {
                @Override
                public String getTokenValue() { return accessTokenValue; }
                @Override
                public Instant getIssuedAt() { return Instant.now(); }
                @Override
                public Instant getExpiresAt() { return Instant.now().plus(client.getTokenSettings().getAccessTokenTimeToLive()); }
            };

            // Generate refresh token if supported
            OAuth2Token refreshToken = null;
            if (client.getAuthorizationGrantTypes().contains(AuthorizationGrantType.REFRESH_TOKEN)) {
                String refreshTokenValue = "refresh_token_" + UUID.randomUUID().toString().replace("-", "");
                refreshToken = new OAuth2Token() {
                    @Override
                    public String getTokenValue() { return refreshTokenValue; }
                    @Override
                    public Instant getIssuedAt() { return Instant.now(); }
                    @Override
                    public Instant getExpiresAt() { return Instant.now().plus(client.getTokenSettings().getRefreshTokenTimeToLive()); }
                };
            }

            // Remove used authorization code
            authorizationCodes.remove(request.getCode());

            // Build response
            Map<String, Object> response = new HashMap<>();
            response.put("access_token", accessToken.getTokenValue());
            response.put("token_type", "Bearer");
            response.put("expires_in", getTokenExpiresIn(accessToken));
            response.put("scope", String.join(" ", codeData.getScopes()));
            
            if (refreshToken != null) {
                response.put("refresh_token", refreshToken.getTokenValue());
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return createErrorResponse("server_error", "Token exchange failed: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
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
        authorizationCode.put("step2", "POST /api/oauth2/token (exchange code for token)");
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
    
    /**
     * Validate authorization code status
     */
    @GetMapping("/code/{code}/status")
    public ResponseEntity<?> getCodeStatus(@PathVariable String code) {
        AuthorizationCodeData codeData = authorizationCodes.get(code);
        
        Map<String, Object> response = new HashMap<>();
        if (codeData == null) {
            response.put("valid", false);
            response.put("reason", "Code not found");
        } else if (Instant.now().isAfter(codeData.getExpiresAt())) {
            response.put("valid", false);
            response.put("reason", "Code expired");
            response.put("expired_at", codeData.getExpiresAt().toString());
        } else {
            response.put("valid", true);
            response.put("client_id", codeData.getClientId());
            response.put("principal", codeData.getPrincipalName());
            response.put("scopes", codeData.getScopes());
            response.put("expires_at", codeData.getExpiresAt().toString());
            response.put("expires_in", codeData.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond());
        }
        
        return ResponseEntity.ok(response);
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
    
    // Helper methods
    private ResponseEntity<?> createErrorResponse(String error, String description, HttpStatus status) {
        Map<String, Object> errorResponse = new HashMap<>();
        errorResponse.put("error", error);
        errorResponse.put("error_description", description);
        return ResponseEntity.status(status).body(errorResponse);
    }
    
    private OAuth2AuthorizationRequest createAuthorizationRequest(AuthorizationRequest request, RegisteredClient client) {
        return OAuth2AuthorizationRequest.authorizationCode()
            .clientId(request.getClientId())
            .redirectUri(request.getRedirectUri())
            .scopes(validateAndGetScopes(request.getScope(), client.getScopes()))
            .state(request.getState())
            .build();
    }
    
    private Set<String> validateAndGetScopes(String requestedScopes, Set<String> clientScopes) {
        if (requestedScopes == null || requestedScopes.trim().isEmpty()) {
            return clientScopes;
        }
        
        Set<String> scopes = new HashSet<>(Arrays.asList(requestedScopes.split("\\s+")));
        scopes.retainAll(clientScopes); // Only keep scopes that the client is allowed to request
        return scopes.isEmpty() ? clientScopes : scopes;
    }
    
    private OAuth2TokenContext createTokenContext(RegisteredClient client, Authentication authentication, OAuth2TokenType tokenType) {
        return DefaultOAuth2TokenContext.builder()
            .registeredClient(client)
            .principal(authentication)
            .authorizationServerContext(AuthorizationServerContextHolder.getContext())
            .tokenType(tokenType)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .build();
    }
    
    private long getTokenExpiresIn(OAuth2Token token) {
        if (token.getExpiresAt() != null) {
            return token.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond();
        }
        return 3600; // Default 1 hour
    }
    
    private String generateJwtToken(RegisteredClient client, Authentication authentication, Set<String> scopes) {
        try {
            // Create proper JWT claims
            Instant now = Instant.now();
            Instant expiresAt = now.plus(client.getTokenSettings().getAccessTokenTimeToLive());
            
            JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("http://localhost:9000")
                .subject(authentication.getName())
                .audience(Arrays.asList(client.getClientId()))
                .issuedAt(now)
                .expiresAt(expiresAt)
                .notBefore(now)
                .id(UUID.randomUUID().toString())
                .claim("scope", String.join(" ", scopes))
                .claim("client_id", client.getClientId())
                .claim("username", authentication.getName())
                .build();
            
            // Use the JwtEncoder directly to create a proper JWT token
            JwtEncoderParameters encoderParameters = JwtEncoderParameters.from(claims);
            org.springframework.security.oauth2.jwt.Jwt jwt = jwtEncoder.encode(encoderParameters);
            
            return jwt.getTokenValue();
            
        } catch (Exception e) {
            // Log the error for debugging
            System.err.println("JWT generation error: " + e.getMessage());
            e.printStackTrace();
            
            // Fallback to simple token if JWT generation fails
            return "access_token_" + UUID.randomUUID().toString().replace("-", "");
        }
    }
    
    // Data class for storing authorization code information
    private static class AuthorizationCodeData {
        private final String code;
        private final String clientId;
        private final String principalName;
        private final String redirectUri;
        private final Set<String> scopes;
        private final Instant expiresAt;
        
        public AuthorizationCodeData(String code, String clientId, String principalName, 
                                   String redirectUri, Set<String> scopes, Instant expiresAt) {
            this.code = code;
            this.clientId = clientId;
            this.principalName = principalName;
            this.redirectUri = redirectUri;
            this.scopes = scopes;
            this.expiresAt = expiresAt;
        }
        
        public String getCode() { return code; }
        public String getClientId() { return clientId; }
        public String getPrincipalName() { return principalName; }
        public String getRedirectUri() { return redirectUri; }
        public Set<String> getScopes() { return scopes; }
        public Instant getExpiresAt() { return expiresAt; }
    }
}
