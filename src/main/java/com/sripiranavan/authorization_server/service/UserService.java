package com.sripiranavan.authorization_server.service;

import com.sripiranavan.authorization_server.entity.User;
import com.sripiranavan.authorization_server.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.*;

/**
 * Service class for user management operations.
 * Handles user CRUD operations, authentication, and user statistics.
 */
@Service
@Transactional
public class UserService {
    
    private static final Logger logger = LoggerFactory.getLogger(UserService.class);
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private PasswordEncoder passwordEncoder;
    
    /**
     * Create a new user with encoded password.
     * 
     * @param username the username
     * @param password the plain text password
     * @param roles the user roles
     * @param enabled whether the user is enabled
     * @return the created user
     */
    public User createUser(String username, String password, Set<String> roles, boolean enabled) {
        logger.info("Creating user: {}", username);
        
        if (userRepository.existsByUsernameIgnoreCase(username)) {
            throw new IllegalArgumentException("User already exists: " + username);
        }
        
        String encodedPassword = passwordEncoder.encode(password);
        User user = new User(username, encodedPassword, roles, enabled);
        
        User savedUser = userRepository.save(user);
        logger.info("User created successfully: {}", username);
        return savedUser;
    }
    
    /**
     * Find user by username (case-insensitive).
     * 
     * @param username the username
     * @return Optional containing the user if found
     */
    @Transactional(readOnly = true)
    public Optional<User> findByUsername(String username) {
        return userRepository.findByUsernameIgnoreCase(username);
    }
    
    /**
     * Get user by username, throws exception if not found.
     * 
     * @param username the username
     * @return the user
     * @throws IllegalArgumentException if user not found
     */
    @Transactional(readOnly = true)
    public User getUserByUsername(String username) {
        return findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found: " + username));
    }
    
    /**
     * Authenticate user with username and password.
     * 
     * @param username the username
     * @param password the plain text password
     * @return true if authentication successful
     */
    public boolean authenticateUser(String username, String password) {
        logger.debug("Authenticating user: {}", username);
        
        Optional<User> userOptional = findByUsername(username);
        if (userOptional.isEmpty()) {
            logger.warn("Authentication failed - user not found: {}", username);
            return false;
        }
        
        User user = userOptional.get();
        if (!user.isEnabled()) {
            logger.warn("Authentication failed - user disabled: {}", username);
            return false;
        }
        
        boolean authenticated = passwordEncoder.matches(password, user.getPassword());
        if (authenticated) {
            updateLastLogin(username);
            logger.info("User authenticated successfully: {}", username);
        } else {
            logger.warn("Authentication failed - invalid password for user: {}", username);
        }
        
        return authenticated;
    }
    
    /**
     * Update user's last login timestamp.
     * 
     * @param username the username
     */
    public void updateLastLogin(String username) {
        userRepository.updateLastLogin(username, Instant.now());
        logger.debug("Updated last login for user: {}", username);
    }
    
    /**
     * Change user password.
     * 
     * @param username the username
     * @param newPassword the new plain text password
     */
    public void changePassword(String username, String newPassword) {
        logger.info("Changing password for user: {}", username);
        
        if (!userRepository.existsByUsernameIgnoreCase(username)) {
            throw new IllegalArgumentException("User not found: " + username);
        }
        
        String encodedPassword = passwordEncoder.encode(newPassword);
        userRepository.updateUserPassword(username, encodedPassword, Instant.now());
        logger.info("Password changed successfully for user: {}", username);
    }
    
    /**
     * Enable or disable a user.
     * 
     * @param username the username
     * @param enabled the enabled status
     */
    public void setUserEnabled(String username, boolean enabled) {
        logger.info("Setting user {} enabled status to: {}", username, enabled);
        
        if (!userRepository.existsByUsernameIgnoreCase(username)) {
            throw new IllegalArgumentException("User not found: " + username);
        }
        
        userRepository.updateUserEnabled(username, enabled, Instant.now());
        logger.info("User {} enabled status updated to: {}", username, enabled);
    }
    
    /**
     * Delete a user.
     * 
     * @param username the username
     */
    public void deleteUser(String username) {
        logger.info("Deleting user: {}", username);
        
        if (!userRepository.existsByUsernameIgnoreCase(username)) {
            throw new IllegalArgumentException("User not found: " + username);
        }
        
        userRepository.deleteById(username);
        logger.info("User deleted successfully: {}", username);
    }
    
    /**
     * Get all users.
     * 
     * @return list of all users
     */
    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        return userRepository.findAll();
    }
    
    /**
     * Get all enabled users.
     * 
     * @return list of enabled users
     */
    @Transactional(readOnly = true)
    public List<User> getEnabledUsers() {
        return userRepository.findAllEnabledUsers();
    }
    
    /**
     * Get users by role.
     * 
     * @param role the role
     * @return list of users with the role
     */
    @Transactional(readOnly = true)
    public List<User> getUsersByRole(String role) {
        return userRepository.findByRole(role);
    }
    
    /**
     * Check if user exists.
     * 
     * @param username the username
     * @return true if user exists
     */
    @Transactional(readOnly = true)
    public boolean userExists(String username) {
        return userRepository.existsByUsernameIgnoreCase(username);
    }
    
    /**
     * Get user statistics.
     * 
     * @return map containing user statistics
     */
    @Transactional(readOnly = true)
    public Map<String, Object> getUserStatistics() {
        Map<String, Object> stats = new HashMap<>();
        
        stats.put("total_users", userRepository.countAllUsers());
        stats.put("enabled_users", userRepository.countEnabledUsers());
        stats.put("disabled_users", userRepository.countDisabledUsers());
        stats.put("admin_users", userRepository.countByRole("ADMIN"));
        stats.put("regular_users", userRepository.countByRole("USER"));
        stats.put("service_accounts", userRepository.countByRole("SERVICE"));
        stats.put("operators", userRepository.countByRole("OPERATOR"));
        stats.put("never_logged_in", userRepository.findUsersNeverLoggedIn().size());
        stats.put("timestamp", Instant.now().toString());
        
        return stats;
    }
    
    /**
     * Bulk create users from a list.
     * 
     * @param users the list of users to create
     * @return list of created users
     */
    public List<User> createUsers(List<User> users) {
        logger.info("Bulk creating {} users", users.size());
        
        List<User> createdUsers = new ArrayList<>();
        for (User user : users) {
            try {
                // Encode password if not already encoded
                if (!isPasswordEncoded(user.getPassword())) {
                    user.setPassword(passwordEncoder.encode(user.getPassword()));
                }
                
                if (!userRepository.existsByUsernameIgnoreCase(user.getUsername())) {
                    User savedUser = userRepository.save(user);
                    createdUsers.add(savedUser);
                    logger.debug("Created user: {}", user.getUsername());
                } else {
                    logger.warn("User already exists, skipping: {}", user.getUsername());
                }
            } catch (Exception e) {
                logger.error("Failed to create user: {}", user.getUsername(), e);
            }
        }
        
        logger.info("Successfully created {} out of {} users", createdUsers.size(), users.size());
        return createdUsers;
    }
    
    /**
     * Check if password is already encoded (bcrypt format).
     * 
     * @param password the password to check
     * @return true if password appears to be encoded
     */
    private boolean isPasswordEncoded(String password) {
        // BCrypt encoded passwords start with $2a$, $2b$, $2x$, or $2y$
        return password != null && password.matches("^\\$2[abxy]\\$\\d+\\$.{53}$");
    }
    
    /**
     * Get count of users in database.
     * 
     * @return total user count
     */
    @Transactional(readOnly = true)
    public long getUserCount() {
        return userRepository.countAllUsers();
    }
    
    /**
     * Check if database is empty (no users).
     * 
     * @return true if no users exist
     */
    @Transactional(readOnly = true)
    public boolean isDatabaseEmpty() {
        return getUserCount() == 0;
    }
}
