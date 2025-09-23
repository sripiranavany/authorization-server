package com.sripiranavan.authorization_server.entity;

import javax.persistence.*;
import java.time.Instant;
import java.util.Set;

@Entity
@Table(name = "authorization_codes")
public class AuthorizationCode {
    
    @Id
    private String code;
    
    @Column(name = "client_id", nullable = false)
    private String clientId;
    
    @Column(name = "principal_name", nullable = false)
    private String principalName;
    
    @Column(name = "redirect_uri", nullable = false)
    private String redirectUri;
    
    @ElementCollection(fetch = FetchType.EAGER)
    @CollectionTable(name = "authorization_code_scopes", joinColumns = @JoinColumn(name = "code"))
    @Column(name = "scope")
    private Set<String> scopes;
    
    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;
    
    @Column(name = "created_at", nullable = false)
    private Instant createdAt;
    
    // Default constructor
    public AuthorizationCode() {
    }
    
    // Constructor
    public AuthorizationCode(String code, String clientId, String principalName, 
                           String redirectUri, Set<String> scopes, Instant expiresAt) {
        this.code = code;
        this.clientId = clientId;
        this.principalName = principalName;
        this.redirectUri = redirectUri;
        this.scopes = scopes;
        this.expiresAt = expiresAt;
        this.createdAt = Instant.now();
    }
    
    // Getters and setters
    public String getCode() {
        return code;
    }
    
    public void setCode(String code) {
        this.code = code;
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
    
    public String getRedirectUri() {
        return redirectUri;
    }
    
    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
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
    
    // Helper method to check if expired
    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
