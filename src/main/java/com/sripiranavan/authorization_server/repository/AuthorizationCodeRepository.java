package com.sripiranavan.authorization_server.repository;

import com.sripiranavan.authorization_server.entity.AuthorizationCode;
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
public interface AuthorizationCodeRepository extends JpaRepository<AuthorizationCode, String> {

    /**
     * Find authorization code by code value and client ID
     */
    Optional<AuthorizationCode> findByCodeAndClientId(String code, String clientId);

    /**
     * Find all authorization codes for a specific client
     */
    List<AuthorizationCode> findByClientId(String clientId);

    /**
     * Find all authorization codes for a specific user
     */
    List<AuthorizationCode> findByPrincipalName(String principalName);

    /**
     * Find all expired authorization codes
     */
    @Query("SELECT ac FROM AuthorizationCode ac WHERE ac.expiresAt < :now")
    List<AuthorizationCode> findExpiredCodes(@Param("now") Instant now);

    /**
     * Delete expired authorization codes
     */
    @Modifying
    @Transactional
    @Query("DELETE FROM AuthorizationCode ac WHERE ac.expiresAt < :now")
    int deleteExpiredCodes(@Param("now") Instant now);

    /**
     * Delete authorization codes by client ID
     */
    @Modifying
    @Transactional
    void deleteByClientId(String clientId);

    /**
     * Delete authorization codes by principal name
     */
    @Modifying
    @Transactional
    void deleteByPrincipalName(String principalName);

    /**
     * Count active (non-expired) codes for a client
     */
    @Query("SELECT COUNT(ac) FROM AuthorizationCode ac WHERE ac.clientId = :clientId AND ac.expiresAt > :now")
    long countActiveCodesByClientId(@Param("clientId") String clientId, @Param("now") Instant now);

    /**
     * Count active (non-expired) codes for a user
     */
    @Query("SELECT COUNT(ac) FROM AuthorizationCode ac WHERE ac.principalName = :principalName AND ac.expiresAt > :now")
    long countActiveCodesByPrincipalName(@Param("principalName") String principalName, @Param("now") Instant now);
}
