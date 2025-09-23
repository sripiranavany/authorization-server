package com.sripiranavan.authorization_server.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Size;
import java.util.*;

@RestController
@RequestMapping("/api/user-management")
@CrossOrigin(origins = "*")
public class UserManagementController {

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/users")
    public ResponseEntity<?> createUser(@Valid @RequestBody UserCreationRequest request) {
        try {
            if (userDetailsService instanceof InMemoryUserDetailsManager) {
                InMemoryUserDetailsManager userManager = (InMemoryUserDetailsManager) userDetailsService;
                
                // Check if user already exists
                try {
                    userManager.loadUserByUsername(request.getUsername());
                    Map<String, Object> errorResponse = new HashMap<>();
                    errorResponse.put("error", "user_exists");
                    errorResponse.put("error_description", "User with username '" + request.getUsername() + "' already exists");
                    return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
                } catch (UsernameNotFoundException e) {
                    // User doesn't exist, proceed with creation
                }

                UserDetails newUser = User.withUsername(request.getUsername())
                    .password(passwordEncoder.encode(request.getPassword()))
                    .roles(request.getRoles() != null ? request.getRoles().toArray(new String[0]) : new String[]{"USER"})
                    .build();

                userManager.createUser(newUser);

                Map<String, Object> response = new HashMap<>();
                response.put("username", request.getUsername());
                response.put("roles", request.getRoles() != null ? request.getRoles() : Arrays.asList("USER"));
                response.put("created_at", System.currentTimeMillis() / 1000);
                response.put("status", "created");

                return ResponseEntity.status(HttpStatus.CREATED).body(response);
            } else {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "operation_not_supported");
                errorResponse.put("error_description", "User creation is not supported with current user details service");
                return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(errorResponse);
            }
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "user_creation_failed");
            errorResponse.put("error_description", "Failed to create user: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @GetMapping("/users/{username}")
    public ResponseEntity<?> getUser(@PathVariable String username) {
        try {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            
            Map<String, Object> response = new HashMap<>();
            response.put("username", userDetails.getUsername());
            response.put("authorities", userDetails.getAuthorities().stream()
                .map(auth -> auth.getAuthority()).toArray());
            response.put("enabled", userDetails.isEnabled());
            response.put("account_non_expired", userDetails.isAccountNonExpired());
            response.put("account_non_locked", userDetails.isAccountNonLocked());
            response.put("credentials_non_expired", userDetails.isCredentialsNonExpired());

            return ResponseEntity.ok(response);
        } catch (UsernameNotFoundException e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "user_not_found");
            errorResponse.put("error_description", "User with username '" + username + "' not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Failed to retrieve user information");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @PutMapping("/users/{username}/password")
    public ResponseEntity<?> changePassword(@PathVariable String username, 
                                          @Valid @RequestBody PasswordChangeRequest request) {
        try {
            if (userDetailsService instanceof InMemoryUserDetailsManager) {
                InMemoryUserDetailsManager userManager = (InMemoryUserDetailsManager) userDetailsService;
                
                // Verify user exists
                UserDetails existingUser = userManager.loadUserByUsername(username);
                
                // Update password
                userManager.changePassword(request.getOldPassword(), passwordEncoder.encode(request.getNewPassword()));

                Map<String, Object> response = new HashMap<>();
                response.put("username", username);
                response.put("message", "Password changed successfully");
                response.put("updated_at", System.currentTimeMillis() / 1000);

                return ResponseEntity.ok(response);
            } else {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "operation_not_supported");
                errorResponse.put("error_description", "Password change is not supported with current user details service");
                return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(errorResponse);
            }
        } catch (UsernameNotFoundException e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "user_not_found");
            errorResponse.put("error_description", "User with username '" + username + "' not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "password_change_failed");
            errorResponse.put("error_description", "Failed to change password: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }
    }

    @DeleteMapping("/users/{username}")
    public ResponseEntity<?> deleteUser(@PathVariable String username) {
        try {
            if (userDetailsService instanceof InMemoryUserDetailsManager) {
                InMemoryUserDetailsManager userManager = (InMemoryUserDetailsManager) userDetailsService;
                
                // Verify user exists
                userManager.loadUserByUsername(username);
                
                // Delete user
                userManager.deleteUser(username);

                Map<String, Object> response = new HashMap<>();
                response.put("username", username);
                response.put("message", "User deleted successfully");
                response.put("deleted_at", System.currentTimeMillis() / 1000);

                return ResponseEntity.ok(response);
            } else {
                Map<String, Object> errorResponse = new HashMap<>();
                errorResponse.put("error", "operation_not_supported");
                errorResponse.put("error_description", "User deletion is not supported with current user details service");
                return ResponseEntity.status(HttpStatus.NOT_IMPLEMENTED).body(errorResponse);
            }
        } catch (UsernameNotFoundException e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "user_not_found");
            errorResponse.put("error_description", "User with username '" + username + "' not found");
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(errorResponse);
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "user_deletion_failed");
            errorResponse.put("error_description", "Failed to delete user: " + e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @GetMapping("/users")
    public ResponseEntity<?> listUsers() {
        try {
            // In a real implementation, you would retrieve all users from your persistent store
            // For now, we'll return basic information about the default user
            List<Map<String, Object>> users = new ArrayList<>();
            
            Map<String, Object> defaultUser = new HashMap<>();
            defaultUser.put("username", "user");
            defaultUser.put("roles", Arrays.asList("USER"));
            defaultUser.put("enabled", true);
            users.add(defaultUser);

            Map<String, Object> response = new HashMap<>();
            response.put("users", users);
            response.put("total", users.size());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            Map<String, Object> errorResponse = new HashMap<>();
            errorResponse.put("error", "server_error");
            errorResponse.put("error_description", "Failed to retrieve users list");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    // Request DTOs
    public static class UserCreationRequest {
        @NotBlank(message = "Username is required")
        @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
        private String username;

        @NotBlank(message = "Password is required")
        @Size(min = 6, message = "Password must be at least 6 characters")
        private String password;

        private List<String> roles;

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }

        public List<String> getRoles() { return roles; }
        public void setRoles(List<String> roles) { this.roles = roles; }
    }

    public static class PasswordChangeRequest {
        @NotBlank(message = "Old password is required")
        private String oldPassword;

        @NotBlank(message = "New password is required")
        @Size(min = 6, message = "New password must be at least 6 characters")
        private String newPassword;

        public String getOldPassword() { return oldPassword; }
        public void setOldPassword(String oldPassword) { this.oldPassword = oldPassword; }

        public String getNewPassword() { return newPassword; }
        public void setNewPassword(String newPassword) { this.newPassword = newPassword; }
    }
}
