package com.sripiranavan.resource_server.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/protected")
public class ProtectedController {

    @GetMapping("/hello")
    public ResponseEntity<Map<String, Object>> hello(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Hello from protected endpoint!");
        response.put("timestamp", Instant.now());
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            response.put("user", jwt.getSubject());
            response.put("client_id", jwt.getClaimAsString("client_id"));
            response.put("scopes", jwt.getClaimAsString("scope"));
            response.put("username", jwt.getClaimAsString("username"));
        }
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/user-info")
    public ResponseEntity<Map<String, Object>> getUserInfo(Authentication authentication) {
        if (authentication == null || !(authentication.getPrincipal() instanceof Jwt)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid token"));
        }

        Jwt jwt = (Jwt) authentication.getPrincipal();
        Map<String, Object> userInfo = new HashMap<>();
        userInfo.put("subject", jwt.getSubject());
        userInfo.put("username", jwt.getClaimAsString("username"));
        userInfo.put("client_id", jwt.getClaimAsString("client_id"));
        userInfo.put("scopes", jwt.getClaimAsString("scope"));
        userInfo.put("issued_at", jwt.getIssuedAt());
        userInfo.put("expires_at", jwt.getExpiresAt());
        userInfo.put("issuer", jwt.getIssuer());
        userInfo.put("audience", jwt.getAudience());

        return ResponseEntity.ok(userInfo);
    }

    @PostMapping("/data")
    public ResponseEntity<Map<String, Object>> createData(
            @RequestBody Map<String, Object> requestData,
            Authentication authentication) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Data created successfully");
        response.put("received_data", requestData);
        response.put("timestamp", Instant.now());
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            response.put("created_by", jwt.getClaimAsString("username"));
        }
        
        return ResponseEntity.ok(response);
    }
}
