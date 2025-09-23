package com.sripiranavan.authorization_server.service;

import com.sripiranavan.authorization_server.entity.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Database-backed UserDetailsService implementation.
 * Uses the User entity and UserService for authentication.
 */
@Service("databaseUserDetailsService")
@Transactional(readOnly = true)
public class DatabaseUserDetailsService implements UserDetailsService {
    
    private static final Logger logger = LoggerFactory.getLogger(DatabaseUserDetailsService.class);
    
    @Autowired
    private UserService userService;
    
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        logger.debug("Loading user by username: {}", username);
        
        User user = userService.findByUsername(username)
                .orElseThrow(() -> {
                    logger.warn("User not found: {}", username);
                    return new UsernameNotFoundException("User not found: " + username);
                });
        
        logger.debug("User found: {} with roles: {}", username, user.getRoles());
        
        return new DatabaseUserDetails(user);
    }
    
    /**
     * Custom UserDetails implementation that wraps our User entity.
     */
    public static class DatabaseUserDetails implements UserDetails {
        
        private final User user;
        
        public DatabaseUserDetails(User user) {
            this.user = user;
        }
        
        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            Set<String> roles = user.getRoles();
            if (roles == null || roles.isEmpty()) {
                return Set.of();
            }
            
            return roles.stream()
                    .map(role -> {
                        // Add ROLE_ prefix if not present
                        String authority = role.startsWith("ROLE_") ? role : "ROLE_" + role;
                        return new SimpleGrantedAuthority(authority);
                    })
                    .collect(Collectors.toSet());
        }
        
        @Override
        public String getPassword() {
            return user.getPassword();
        }
        
        @Override
        public String getUsername() {
            return user.getUsername();
        }
        
        @Override
        public boolean isAccountNonExpired() {
            return user.isAccountNonExpired();
        }
        
        @Override
        public boolean isAccountNonLocked() {
            return user.isAccountNonLocked();
        }
        
        @Override
        public boolean isCredentialsNonExpired() {
            return user.isCredentialsNonExpired();
        }
        
        @Override
        public boolean isEnabled() {
            return user.isEnabled();
        }
        
        /**
         * Get the underlying User entity.
         * 
         * @return the User entity
         */
        public User getUser() {
            return user;
        }
        
        /**
         * Check if user has a specific role.
         * 
         * @param role the role to check
         * @return true if user has the role
         */
        public boolean hasRole(String role) {
            return user.hasRole(role);
        }
        
        /**
         * Check if user has any of the specified roles.
         * 
         * @param roles the roles to check
         * @return true if user has any of the roles
         */
        public boolean hasAnyRole(String... roles) {
            return user.hasAnyRole(roles);
        }
        
        @Override
        public String toString() {
            return "DatabaseUserDetails{" +
                    "username='" + user.getUsername() + '\'' +
                    ", roles=" + user.getRoles() +
                    ", enabled=" + user.isEnabled() +
                    '}';
        }
    }
}
