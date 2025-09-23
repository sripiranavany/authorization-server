package com.sripiranavan.authorization_server.entity;

import javax.persistence.*;
import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {

    @Id
    private String token;

    @Column(name = "client_id", nullable = false)
    private String clientId;

    @Column(name = "principal_name", nullable = false)
    private String principalName;

    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "refresh_token_scopes", joinColumns = @JoinColumn(name = "token"))
    @Column(name = "scope")
    private Set<String> scopes;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @Column(name = "created_at", nullable = false)
    private Instant createdAt;

    @Column(name = "used", nullable = false)
    private boolean used = false;

    // Default constructor
    public RefreshToken() {
    }

    // Constructor
    public RefreshToken(String token, String clientId, String principalName,
                        Set<String> scopes, Instant expiresAt) {
        this.token = token;
        this.clientId = clientId;
        this.principalName = principalName;
        this.scopes = scopes;
        this.expiresAt = expiresAt;
        this.createdAt = Instant.now();
        this.used = false;
    }

    // Getters and setters
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getPrincipalName() {
        return principalName;
    }

    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    public Set<String> getScopes() {
        return scopes;
    }

    public void setScopes(Set<String> scopes) {
        this.scopes = scopes;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }

    public void setExpiresAt(Instant expiresAt) {
        this.expiresAt = expiresAt;
    }

    public Instant getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(Instant createdAt) {
        this.createdAt = createdAt;
    }

    public boolean isUsed() {
        return used;
    }

    public void setUsed(boolean used) {
        this.used = used;
    }

    // Helper methods
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public boolean isActive() {
        return !isExpired() && !used;
    }

    public void markAsUsed() {
        this.used = true;
    }
}
