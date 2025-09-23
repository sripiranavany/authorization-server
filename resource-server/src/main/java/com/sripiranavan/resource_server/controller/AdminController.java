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
@RequestMapping("/admin")
public class AdminController {

    @GetMapping("/dashboard")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<Map<String, Object>> adminDashboard(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Welcome to Admin Dashboard");
        response.put("timestamp", Instant.now());
        response.put("admin_features", new String[]{
            "User Management",
            "System Configuration", 
            "Analytics",
            "Audit Logs"
        });
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            response.put("admin_user", jwt.getClaimAsString("username"));
            response.put("scopes", jwt.getClaimAsString("scope"));
        }
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<Map<String, Object>> getAllUsers(Authentication authentication) {
        Map<String, Object> response = new HashMap<>();
        response.put("message", "Admin endpoint - All users list");
        response.put("users", new String[]{"admin", "api-user", "service-account", "robi-operator"});
        response.put("total_users", 4);
        response.put("timestamp", Instant.now());
        
        return ResponseEntity.ok(response);
    }

    @PostMapping("/system/config")
    @PreAuthorize("hasAuthority('SCOPE_admin')")
    public ResponseEntity<Map<String, Object>> updateSystemConfig(
            @RequestBody Map<String, Object> configData,
            Authentication authentication) {
        
        Map<String, Object> response = new HashMap<>();
        response.put("message", "System configuration updated");
        response.put("updated_config", configData);
        response.put("timestamp", Instant.now());
        
        if (authentication != null && authentication.getPrincipal() instanceof Jwt) {
            Jwt jwt = (Jwt) authentication.getPrincipal();
            response.put("updated_by", jwt.getClaimAsString("username"));
        }
        
        return ResponseEntity.ok(response);
    }
}
