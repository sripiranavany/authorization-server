package com.sripiranavan.authorization_server.repository;

import com.sripiranavan.authorization_server.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for User entity operations.
 * Provides CRUD operations and custom queries for user management.
 */
@Repository
public interface UserRepository extends JpaRepository<User, String> {

    /**
     * Find a user by username (case-insensitive).
     *
     * @param username the username to search for
     * @return Optional containing the user if found
     */
    @Query("SELECT u FROM User u WHERE LOWER(u.username) = LOWER(:username)")
    Optional<User> findByUsernameIgnoreCase(@Param("username") String username);

    /**
     * Find all enabled users.
     *
     * @return list of enabled users
     */
    @Query("SELECT u FROM User u WHERE u.enabled = true")
    List<User> findAllEnabledUsers();

    /**
     * Find all disabled users.
     *
     * @return list of disabled users
     */
    @Query("SELECT u FROM User u WHERE u.enabled = false")
    List<User> findAllDisabledUsers();

    /**
     * Find users by role.
     *
     * @param role the role to search for
     * @return list of users with the specified role
     */
    @Query("SELECT u FROM User u JOIN u.roles r WHERE r = :role")
    List<User> findByRole(@Param("role") String role);

    /**
     * Find users with any of the specified roles.
     *
     * @param roles the roles to search for
     * @return list of users with any of the specified roles
     */
    @Query("SELECT DISTINCT u FROM User u JOIN u.roles r WHERE r IN :roles")
    List<User> findByRolesIn(@Param("roles") List<String> roles);

    /**
     * Check if a user exists by username (case-insensitive).
     *
     * @param username the username to check
     * @return true if user exists, false otherwise
     */
    @Query("SELECT COUNT(u) > 0 FROM User u WHERE LOWER(u.username) = LOWER(:username)")
    boolean existsByUsernameIgnoreCase(@Param("username") String username);

    /**
     * Update user's last login timestamp.
     *
     * @param username  the username
     * @param lastLogin the last login timestamp
     */
    @Modifying
    @Query("UPDATE User u SET u.lastLogin = :lastLogin WHERE u.username = :username")
    void updateLastLogin(@Param("username") String username, @Param("lastLogin") Instant lastLogin);

    /**
     * Enable or disable a user.
     *
     * @param username the username
     * @param enabled  the enabled status
     */
    @Modifying
    @Query("UPDATE User u SET u.enabled = :enabled, u.updatedAt = :updatedAt WHERE u.username = :username")
    void updateUserEnabled(@Param("username") String username, @Param("enabled") boolean enabled, @Param("updatedAt") Instant updatedAt);

    /**
     * Update user's password.
     *
     * @param username  the username
     * @param password  the new password
     * @param updatedAt the update timestamp
     */
    @Modifying
    @Query("UPDATE User u SET u.password = :password, u.updatedAt = :updatedAt WHERE u.username = :username")
    void updateUserPassword(@Param("username") String username, @Param("password") String password, @Param("updatedAt") Instant updatedAt);

    /**
     * Count total number of users.
     *
     * @return total user count
     */
    @Query("SELECT COUNT(u) FROM User u")
    long countAllUsers();

    /**
     * Count enabled users.
     *
     * @return enabled user count
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.enabled = true")
    long countEnabledUsers();

    /**
     * Count disabled users.
     *
     * @return disabled user count
     */
    @Query("SELECT COUNT(u) FROM User u WHERE u.enabled = false")
    long countDisabledUsers();

    /**
     * Count users with a specific role.
     *
     * @param role the role to count
     * @return count of users with the role
     */
    @Query("SELECT COUNT(DISTINCT u) FROM User u JOIN u.roles r WHERE r = :role")
    long countByRole(@Param("role") String role);

    /**
     * Find users who have logged in recently.
     *
     * @param since the timestamp to check from
     * @return list of users who logged in since the specified time
     */
    @Query("SELECT u FROM User u WHERE u.lastLogin >= :since")
    List<User> findUsersLoggedInSince(@Param("since") Instant since);

    /**
     * Find users who have never logged in.
     *
     * @return list of users who have never logged in
     */
    @Query("SELECT u FROM User u WHERE u.lastLogin IS NULL")
    List<User> findUsersNeverLoggedIn();

    /**
     * Find users created after a specific date.
     *
     * @param since the creation date to check from
     * @return list of users created since the specified date
     */
    @Query("SELECT u FROM User u WHERE u.createdAt >= :since")
    List<User> findUsersCreatedSince(@Param("since") Instant since);
}
