package com.sripiranavan.authorization_server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@CrossOrigin(origins = "*")
public class AuthController {
    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/login")
    public ResponseEntity<?> login(@Valid @RequestBody LoginRequest loginRequest,
                                   HttpServletRequest request,
                                   HttpServletResponse response) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
            );
            SecurityContextHolder.getContext().setAuthentication(authentication);
            // Ensure session is created and authentication is stored
            request.getSession(true).setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());
            
            Map<String, Object> result = new HashMap<>();
            result.put("message", "Login successful");
            result.put("username", loginRequest.getUsername());
            result.put("authorities", authentication.getAuthorities());
            result.put("authenticated", true);
            result.put("login_time", System.currentTimeMillis() / 1000);
            
            return ResponseEntity.ok(result);
        } catch (AuthenticationException ex) {
            Map<String, Object> result = new HashMap<>();
            result.put("error", "authentication_failed");
            result.put("error_description", "Invalid username or password");
            result.put("authenticated", false);
            return ResponseEntity.status(401).body(result);
        }
    }
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response) {
        try {
            SecurityContextHolder.clearContext();
            if (request.getSession(false) != null) {
                request.getSession().invalidate();
            }
            
            Map<String, Object> result = new HashMap<>();
            result.put("message", "Logout successful");
            result.put("logout_time", System.currentTimeMillis() / 1000);
            
            return ResponseEntity.ok(result);
        } catch (Exception ex) {
            Map<String, Object> result = new HashMap<>();
            result.put("error", "logout_failed");
            result.put("error_description", "Failed to logout: " + ex.getMessage());
            return ResponseEntity.status(500).body(result);
        }
    }
    
    @GetMapping("/status")
    public ResponseEntity<?> getAuthStatus(HttpServletRequest request) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        Map<String, Object> result = new HashMap<>();
        if (authentication != null && authentication.isAuthenticated() && 
            !"anonymousUser".equals(authentication.getName())) {
            result.put("authenticated", true);
            result.put("username", authentication.getName());
            result.put("authorities", authentication.getAuthorities());
        } else {
            result.put("authenticated", false);
        }
        
        return ResponseEntity.ok(result);
    }
    
    // Request DTO
    public static class LoginRequest {
        @NotBlank(message = "Username is required")
        private String username;
        
        @NotBlank(message = "Password is required")
        private String password;
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
    }
}
