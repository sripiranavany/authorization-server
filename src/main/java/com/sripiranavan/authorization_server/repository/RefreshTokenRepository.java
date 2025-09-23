package com.sripiranavan.authorization_server.repository;

import com.sripiranavan.authorization_server.entity.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    /**
     * Find refresh token by token value and client ID
     */
    Optional<RefreshToken> findByTokenAndClientId(String token, String clientId);

    /**
     * Find active (non-expired, non-used) refresh token
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.token = :token AND rt.clientId = :clientId AND rt.expiresAt > :now AND rt.used = false")
    Optional<RefreshToken> findActiveTokenByTokenAndClientId(@Param("token") String token, @Param("clientId") String clientId, @Param("now") Instant now);

    /**
     * Find all refresh tokens for a specific client
     */
    List<RefreshToken> findByClientId(String clientId);

    /**
     * Find all refresh tokens for a specific user
     */
    List<RefreshToken> findByPrincipalName(String principalName);

    /**
     * Find all active refresh tokens for a user
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.principalName = :principalName AND rt.expiresAt > :now AND rt.used = false")
    List<RefreshToken> findActiveTokensByPrincipalName(@Param("principalName") String principalName, @Param("now") Instant now);

    /**
     * Find all active refresh tokens for a client
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.clientId = :clientId AND rt.expiresAt > :now AND rt.used = false")
    List<RefreshToken> findActiveTokensByClientId(@Param("clientId") String clientId, @Param("now") Instant now);

    /**
     * Find all expired refresh tokens
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.expiresAt < :now")
    List<RefreshToken> findExpiredTokens(@Param("now") Instant now);

    /**
     * Find all used refresh tokens
     */
    @Query("SELECT rt FROM RefreshToken rt WHERE rt.used = true")
    List<RefreshToken> findUsedTokens();

    /**
     * Delete expired refresh tokens
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now")
    int deleteExpiredTokens(@Param("now") Instant now);

    /**
     * Delete used refresh tokens
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.used = true")
    int deleteUsedTokens();

    /**
     * Delete expired and used refresh tokens
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM RefreshToken rt WHERE rt.expiresAt < :now OR rt.used = true")
    int deleteExpiredAndUsedTokens(@Param("now") Instant now);

    /**
     * Mark refresh token as used
     */
    @Modifying
    @Transactional
    @Query("UPDATE RefreshToken rt SET rt.used = true WHERE rt.token = :token")
    int markTokenAsUsed(@Param("token") String token);

    /**
     * Delete refresh tokens by client ID
     */
    @Modifying
    @Transactional
    void deleteByClientId(String clientId);

    /**
     * Delete refresh tokens by principal name
     */
    @Modifying
    @Transactional
    void deleteByPrincipalName(String principalName);

    /**
     * Count active refresh tokens for a client
     */
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.clientId = :clientId AND rt.expiresAt > :now AND rt.used = false")
    long countActiveTokensByClientId(@Param("clientId") String clientId, @Param("now") Instant now);

    /**
     * Count active refresh tokens for a user
     */
    @Query("SELECT COUNT(rt) FROM RefreshToken rt WHERE rt.principalName = :principalName AND rt.expiresAt > :now AND rt.used = false")
    long countActiveTokensByPrincipalName(@Param("principalName") String principalName, @Param("now") Instant now);
}
