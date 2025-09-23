package com.sripiranavan.authorization_server.controller;

import com.sripiranavan.authorization_server.service.FileBasedUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class UserController {

    @Autowired
    private FileBasedUserService userService;

    @GetMapping("/users")
    public ResponseEntity<Map<String, Object>> getLoadedUsers() {
        Map<String, Object> response = new HashMap<>();
        Map<String, UserDetails> users = userService.getAllUsers();
        
        Map<String, Object> userInfo = new HashMap<>();
        for (Map.Entry<String, UserDetails> entry : users.entrySet()) {
            Map<String, Object> details = new HashMap<>();
            details.put("username", entry.getValue().getUsername());
            details.put("enabled", entry.getValue().isEnabled());
            details.put("authorities", entry.getValue().getAuthorities().toString());
            userInfo.put(entry.getKey(), details);
        }
        
        response.put("totalUsers", users.size());
        response.put("users", userInfo);
        response.put("message", "Users loaded from configuration file");
        
        return ResponseEntity.ok(response);
    }

    @GetMapping("/health")
    public ResponseEntity<Map<String, String>> health() {
        Map<String, String> response = new HashMap<>();
        response.put("status", "UP");
        response.put("service", "Customer Care Authorization Server");
        response.put("version", "1.0.3");
        return ResponseEntity.ok(response);
    }
}
