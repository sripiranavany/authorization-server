package com.sripiranavan.resource_server.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/users")
public class UserController {

    @GetMapping("/profile")
    @PreAuthorize("hasAnyAuthority('SCOPE_read', 'SCOPE_write')")
    public ResponseEntity<Map<String, Object>> getUserProfile(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            
            response.put("message", "User profile information");
            response.put("username", jwt.getClaimAsString("username"));
            response.put("subject", jwt.getSubject());
            response.put("client_id", jwt.getClaimAsString("client_id"));
            response.put("scopes", jwt.getClaimAsString("scope"));
            response.put("profile_data", Map.of(
                "name", jwt.getClaimAsString("username"),
                "email", jwt.getClaimAsString("username") + "@example.com",
                "last_login", "2025-09-23T17:50:00Z"
            ));
        }
        
        response.put("timestamp", Instant.now());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/data")
    @PreAuthorize("hasAuthority('SCOPE_read')")
    public ResponseEntity<Map<String, Object>> getUserData(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "User data - requires read scope");
        response.put("data", new String[]{"Document 1", "Document 2", "Document 3"});
        response.put("timestamp", Instant.now());
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            response.put("owner", jwt.getClaimAsString("username"));
        }
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/data")
    @PreAuthorize("hasAuthority('SCOPE_write')")
    public ResponseEntity<Map<String, Object>> createUserData(
            @RequestBody Map<String, Object> userData,
            Authentication authentication) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "User data created - requires write scope");
        response.put("created_data", userData);
        response.put("timestamp", Instant.now());
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            response.put("created_by", jwt.getClaimAsString("username"));
        }
        
        return ResponseEntity.ok(response);
    }
}
