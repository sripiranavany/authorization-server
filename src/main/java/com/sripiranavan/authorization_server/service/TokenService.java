package com.sripiranavan.authorization_server.service;

import com.sripiranavan.authorization_server.entity.AuthorizationCode;
import com.sripiranavan.authorization_server.entity.RefreshToken;
import com.sripiranavan.authorization_server.repository.AuthorizationCodeRepository;
import com.sripiranavan.authorization_server.repository.RefreshTokenRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
@Transactional
public class TokenService {

    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);

    @Autowired
    private AuthorizationCodeRepository authorizationCodeRepository;

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    // ===== AUTHORIZATION CODE OPERATIONS =====

    /**
     * Store authorization code in database
     */
    public void storeAuthorizationCode(String code, String clientId, String principalName,
                                       String redirectUri, Set<String> scopes, Instant expiresAt) {
        AuthorizationCode authCode = new AuthorizationCode(code, clientId, principalName, redirectUri, scopes, expiresAt);
        authorizationCodeRepository.save(authCode);
        logger.debug("Stored authorization code: {} for client: {} user: {}", code, clientId, principalName);
    }

    /**
     * Retrieve and validate authorization code
     */
    public Optional<AuthorizationCode> getAuthorizationCode(String code, String clientId) {
        Optional<AuthorizationCode> authCode;

        if (clientId != null) {
            authCode = authorizationCodeRepository.findByCodeAndClientId(code, clientId);
        } else {
            // Fallback for cases where client_id is not provided (like status endpoint)
            authCode = authorizationCodeRepository.findById(code);
        }

        if (authCode.isPresent()) {
            if (authCode.get().isExpired()) {
                // Remove expired code
                authorizationCodeRepository.delete(authCode.get());
                logger.debug("Removed expired authorization code: {}", code);
                return Optional.empty();
            }
        }

        return authCode;
    }

    /**
     * Consume (delete) authorization code after use
     */
    public void consumeAuthorizationCode(String code) {
        authorizationCodeRepository.deleteById(code);
        logger.debug("Consumed authorization code: {}", code);
    }

    /**
     * Get active authorization codes count for a client
     */
    public long getActiveAuthorizationCodesCount(String clientId) {
        return authorizationCodeRepository.countActiveCodesByClientId(clientId, Instant.now());
    }

    // ===== REFRESH TOKEN OPERATIONS =====

    /**
     * Store refresh token in database
     */
    public void storeRefreshToken(String token, String clientId, String principalName,
                                  Set<String> scopes, Instant expiresAt) {
        RefreshToken refreshToken = new RefreshToken(token, clientId, principalName, scopes, expiresAt);
        refreshTokenRepository.save(refreshToken);
        logger.debug("Stored refresh token: {} for client: {} user: {}", token, clientId, principalName);
    }

    /**
     * Retrieve and validate refresh token
     */
    public Optional<RefreshToken> getRefreshToken(String token, String clientId) {
        return refreshTokenRepository.findActiveTokenByTokenAndClientId(token, clientId, Instant.now());
    }

    /**
     * Retrieve refresh token for introspection (includes expired/used tokens)
     */
    public Optional<RefreshToken> getRefreshTokenForIntrospection(String token, String clientId) {
        return refreshTokenRepository.findByTokenAndClientId(token, clientId);
    }

    /**
     * Mark refresh token as used (for token rotation)
     */
    public void markRefreshTokenAsUsed(String token) {
        refreshTokenRepository.markTokenAsUsed(token);
        logger.debug("Marked refresh token as used: {}", token);
    }

    /**
     * Delete refresh token
     */
    public void deleteRefreshToken(String token) {
        refreshTokenRepository.deleteById(token);
        logger.debug("Deleted refresh token: {}", token);
    }

    /**
     * Get active refresh tokens count for a client
     */
    public long getActiveRefreshTokensCount(String clientId) {
        return refreshTokenRepository.countActiveTokensByClientId(clientId, Instant.now());
    }

    /**
     * Get active refresh tokens for a user
     */
    public List<RefreshToken> getActiveRefreshTokensForUser(String principalName) {
        return refreshTokenRepository.findActiveTokensByPrincipalName(principalName, Instant.now());
    }

    // ===== CLEANUP OPERATIONS =====

    /**
     * Clean up expired authorization codes
     */
    public int cleanupExpiredAuthorizationCodes() {
        int deletedCount = authorizationCodeRepository.deleteExpiredCodes(Instant.now());
        if (deletedCount > 0) {
            logger.info("Cleaned up {} expired authorization codes", deletedCount);
        }
        return deletedCount;
    }

    /**
     * Clean up expired and used refresh tokens
     */
    public int cleanupExpiredAndUsedRefreshTokens() {
        int deletedCount = refreshTokenRepository.deleteExpiredAndUsedTokens(Instant.now());
        if (deletedCount > 0) {
            logger.info("Cleaned up {} expired/used refresh tokens", deletedCount);
        }
        return deletedCount;
    }

    /**
     * Scheduled cleanup task - runs every 5 minutes
     */
    @Scheduled(fixedRate = 300000) // 5 minutes
    public void scheduledCleanup() {
        logger.debug("Running scheduled token cleanup...");
        int expiredCodes = cleanupExpiredAuthorizationCodes();
        int expiredTokens = cleanupExpiredAndUsedRefreshTokens();
        logger.debug("Cleanup completed: {} codes, {} tokens removed", expiredCodes, expiredTokens);
    }

    // ===== ADMIN OPERATIONS =====

    /**
     * Revoke all tokens for a user
     */
    public void revokeAllTokensForUser(String principalName) {
        authorizationCodeRepository.deleteByPrincipalName(principalName);
        refreshTokenRepository.deleteByPrincipalName(principalName);
        logger.info("Revoked all tokens for user: {}", principalName);
    }

    /**
     * Revoke all tokens for a client
     */
    public void revokeAllTokensForClient(String clientId) {
        authorizationCodeRepository.deleteByClientId(clientId);
        refreshTokenRepository.deleteByClientId(clientId);
        logger.info("Revoked all tokens for client: {}", clientId);
    }

    /**
     * Get token statistics
     */
    public TokenStatistics getTokenStatistics() {
        Instant now = Instant.now();

        long totalAuthCodes = authorizationCodeRepository.count();
        long expiredAuthCodes = authorizationCodeRepository.findExpiredCodes(now).size();
        long activeAuthCodes = totalAuthCodes - expiredAuthCodes;

        long totalRefreshTokens = refreshTokenRepository.count();
        long expiredRefreshTokens = refreshTokenRepository.findExpiredTokens(now).size();
        long usedRefreshTokens = refreshTokenRepository.findUsedTokens().size();
        long activeRefreshTokens = totalRefreshTokens - expiredRefreshTokens - usedRefreshTokens;

        return new TokenStatistics(activeAuthCodes, expiredAuthCodes, activeRefreshTokens, expiredRefreshTokens, usedRefreshTokens);
    }

    // Inner class for token statistics
    public static class TokenStatistics {
        private final long activeAuthorizationCodes;
        private final long expiredAuthorizationCodes;
        private final long activeRefreshTokens;
        private final long expiredRefreshTokens;
        private final long usedRefreshTokens;

        public TokenStatistics(long activeAuthorizationCodes, long expiredAuthorizationCodes,
                               long activeRefreshTokens, long expiredRefreshTokens, long usedRefreshTokens) {
            this.activeAuthorizationCodes = activeAuthorizationCodes;
            this.expiredAuthorizationCodes = expiredAuthorizationCodes;
            this.activeRefreshTokens = activeRefreshTokens;
            this.expiredRefreshTokens = expiredRefreshTokens;
            this.usedRefreshTokens = usedRefreshTokens;
        }

        // Getters
        public long getActiveAuthorizationCodes() {
            return activeAuthorizationCodes;
        }

        public long getExpiredAuthorizationCodes() {
            return expiredAuthorizationCodes;
        }

        public long getActiveRefreshTokens() {
            return activeRefreshTokens;
        }

        public long getExpiredRefreshTokens() {
            return expiredRefreshTokens;
        }

        public long getUsedRefreshTokens() {
            return usedRefreshTokens;
        }
    }
}
