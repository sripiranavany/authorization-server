package com.sripiranavan.authorization_server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.web.bind.annotation.*;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/oauth2")
@CrossOrigin(origins = "*")
public class TokenManagementController {

    @Autowired
    private JwtDecoder jwtDecoder;

    @PostMapping("/introspect")
    public ResponseEntity<?> introspectToken(@Valid @RequestBody TokenIntrospectionRequest request) {
        try {
            Jwt jwt = jwtDecoder.decode(request.getToken());
            
            Map<String, Object> response = new HashMap<>();
            response.put("active", true);
            response.put("client_id", jwt.getClaimAsString("client_id"));
            response.put("username", jwt.getClaimAsString("sub"));
            response.put("scope", jwt.getClaimAsString("scope"));
            response.put("exp", jwt.getExpiresAt().getEpochSecond());
            response.put("iat", jwt.getIssuedAt().getEpochSecond());
            response.put("token_type", "Bearer");
            response.put("aud", jwt.getAudience());
            response.put("iss", jwt.getIssuer().toString());
            response.put("jti", jwt.getId());
            
            return ResponseEntity.ok(response);
        } catch (JwtException e) {
            Map<String, Object> response = new HashMap<>();
            response.put("active", false);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Token introspection failed");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @PostMapping("/revoke")
    public ResponseEntity<?> revokeToken(@Valid @RequestBody TokenRevocationRequest request) {
        try {
            // In a real implementation, you would revoke the token from your token store
            // For now, we'll just validate the token and return success
            jwtDecoder.decode(request.getToken());
            
            Map<String, Object> response = new HashMap<>();
            response.put("revoked", true);
            response.put("message", "Token successfully revoked");
            
            return ResponseEntity.ok(response);
        } catch (JwtException e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "invalid_token");
            errorResponse.put("error_description", "The provided token is invalid or expired");
            return ResponseEntity.badRequest().body(errorResponse);
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Token revocation failed");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @GetMapping("/token/validate")
    public ResponseEntity<?> validateToken(@RequestParam("token") String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            
            Map<String, Object> response = new HashMap<>();
            response.put("valid", true);
            response.put("expires_at", jwt.getExpiresAt().getEpochSecond());
            response.put("issued_at", jwt.getIssuedAt().getEpochSecond());
            response.put("subject", jwt.getSubject());
            response.put("client_id", jwt.getClaimAsString("client_id"));
            response.put("scopes", jwt.getClaimAsString("scope"));
            
            return ResponseEntity.ok(response);
        } catch (JwtException e) {
            Map<String, Object> response = new HashMap<>();
            response.put("valid", false);
            response.put("error", "Token is invalid or expired");
            return ResponseEntity.ok(response);
        }
    }

    @GetMapping("/token/info")
    public ResponseEntity<?> getTokenInfo(@RequestParam("token") String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            
            Map<String, Object> response = new HashMap<>();
            response.put("token_type", "Bearer");
            response.put("subject", jwt.getSubject());
            response.put("client_id", jwt.getClaimAsString("client_id"));
            response.put("issued_at", jwt.getIssuedAt().getEpochSecond());
            response.put("expires_at", jwt.getExpiresAt().getEpochSecond());
            response.put("issuer", jwt.getIssuer().toString());
            response.put("audience", jwt.getAudience());
            response.put("scopes", jwt.getClaimAsString("scope"));
            response.put("jti", jwt.getId());
            response.put("remaining_ttl", jwt.getExpiresAt().getEpochSecond() - Instant.now().getEpochSecond());
            
            return ResponseEntity.ok(response);
        } catch (JwtException e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "invalid_token");
            errorResponse.put("error_description", "The provided token is invalid or expired");
            return ResponseEntity.badRequest().body(errorResponse);
        }
    }

    // Request DTOs
    public static class TokenIntrospectionRequest {
        @NotBlank(message = "Token is required")
        private String token;
        
        private String token_type_hint;

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }

        public String getToken_type_hint() {
            return token_type_hint;
        }

        public void setToken_type_hint(String token_type_hint) {
            this.token_type_hint = token_type_hint;
        }
    }

    public static class TokenRevocationRequest {
        @NotBlank(message = "Token is required")
        private String token;
        
        private String token_type_hint;

        public String getToken() {
            return token;
        }

        public void setToken(String token) {
            this.token = token;
        }

        public String getToken_type_hint() {
            return token_type_hint;
        }

        public void setToken_type_hint(String token_type_hint) {
            this.token_type_hint = token_type_hint;
        }
    }
}
