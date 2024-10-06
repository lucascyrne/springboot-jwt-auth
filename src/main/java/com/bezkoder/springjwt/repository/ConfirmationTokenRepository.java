package com.bezkoder.springjwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ConfirmationTokenRepository extends JpaRepository<com.bezkoder.springjwt.models.ConfirmationToken, Long> {
    Optional<com.bezkoder.springjwt.models.ConfirmationToken> findByToken(String token);
}