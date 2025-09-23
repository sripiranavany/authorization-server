package com.sripiranavan.authorization_server.entity;

import javax.persistence.*;
import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "app_users")
public class User {
    
    @Id
    private String username;
    
    @Column(name = "password", nullable = false)
    private String password;
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "app_user_roles", joinColumns = @JoinColumn(name = "username"))
    @Column(name = "role")
    private Set<String> roles;
    
    @Column(name = "enabled", nullable = false)
    private boolean enabled = true;
    
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    
    @Column(name = "updated_at")
    private Instant updatedAt;
    
    @Column(name = "last_login")
    private Instant lastLogin;
    
    @Column(name = "account_non_expired", nullable = false)
    private boolean accountNonExpired = true;
    
    @Column(name = "account_non_locked", nullable = false)
    private boolean accountNonLocked = true;
    
    @Column(name = "credentials_non_expired", nullable = false)
    private boolean credentialsNonExpired = true;
    
    // Default constructor
    public User() {
    }
    
    // Constructor
    public User(String username, String password, Set<String> roles, boolean enabled) {
        this.username = username;
        this.password = password;
        this.roles = roles;
        this.enabled = enabled;
        this.createdAt = Instant.now();
        this.accountNonExpired = true;
        this.accountNonLocked = true;
        this.credentialsNonExpired = true;
    }
    
    // Getters and setters
    public String getUsername() {
        return username;
    }
    
    public void setUsername(String username) {
        this.username = username;
    }
    
    public String getPassword() {
        return password;
    }
    
    public void setPassword(String password) {
        this.password = password;
        this.updatedAt = Instant.now();
    }
    
    public Set<String> getRoles() {
        return roles;
    }
    
    public void setRoles(Set<String> roles) {
        this.roles = roles;
        this.updatedAt = Instant.now();
    }
    
    public boolean isEnabled() {
        return enabled;
    }
    
    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
        this.updatedAt = Instant.now();
    }
    
    public Instant getCreatedAt() {
        return createdAt;
    }
    
    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }
    
    public Instant getUpdatedAt() {
        return updatedAt;
    }
    
    public void setUpdatedAt(Instant updatedAt) {
        this.updatedAt = updatedAt;
    }
    
    public Instant getLastLogin() {
        return lastLogin;
    }
    
    public void setLastLogin(Instant lastLogin) {
        this.lastLogin = lastLogin;
    }
    
    public boolean isAccountNonExpired() {
        return accountNonExpired;
    }
    
    public void setAccountNonExpired(boolean accountNonExpired) {
        this.accountNonExpired = accountNonExpired;
    }
    
    public boolean isAccountNonLocked() {
        return accountNonLocked;
    }
    
    public void setAccountNonLocked(boolean accountNonLocked) {
        this.accountNonLocked = accountNonLocked;
    }
    
    public boolean isCredentialsNonExpired() {
        return credentialsNonExpired;
    }
    
    public void setCredentialsNonExpired(boolean credentialsNonExpired) {
        this.credentialsNonExpired = credentialsNonExpired;
    }
    
    // Helper methods
    public void updateLastLogin() {
        this.lastLogin = Instant.now();
    }
    
    public boolean hasRole(String role) {
        return roles != null && roles.contains(role);
    }
    
    public boolean hasAnyRole(String... roles) {
        if (this.roles == null) return false;
        for (String role : roles) {
            if (this.roles.contains(role)) {
                return true;
            }
        }
        return false;
    }
    
    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }
    
    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }
}
