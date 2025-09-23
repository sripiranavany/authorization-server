package com.sripiranavan.resource_server.controller;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/public")
public class PublicController {

    @Value("${authorization-server.base-url}")
    private String authorizationServerUrl;

    @GetMapping("/info")
    public ResponseEntity<Map<String, Object>> getPublicInfo() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Public Resource Server Information");
        response.put("server_name", "OAuth2 Resource Server");
        response.put("version", "1.0.0");
        response.put("timestamp", Instant.now());
        response.put("authorization_server", authorizationServerUrl);
        response.put("endpoints", Map.of(
            "protected", "/api/protected/*",
            "admin", "/api/admin/*",
            "users", "/api/users/*",
            "public", "/api/public/*"
        ));
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, Object>> health() {
        Map<String, Object> response = new HashMap<>();
        response.put("status", "UP");
        response.put("timestamp", Instant.now());
        response.put("authorization_server_configured", authorizationServerUrl);
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/oauth2/info")
    public ResponseEntity<Map<String, Object>> getOAuth2Info() {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "OAuth2 Resource Server Configuration");
        response.put("authorization_server", authorizationServerUrl);
        response.put("token_validation", "JWT with JWK Set");
        response.put("jwk_set_uri", authorizationServerUrl + "/oauth2/jwks");
        response.put("supported_scopes", new String[]{"read", "write", "admin", "openid", "profile", "email"});
        response.put("authentication_required_endpoints", new String[]{
            "/api/protected/*",
            "/api/admin/* (requires admin scope)",
            "/api/users/* (requires read/write scope)"
        });
        
        return ResponseEntity.ok(response);
    }
}
