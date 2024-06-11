package com.nutritiontracker.backend.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.stereotype.Repository;

import com.nutritiontracker.backend.models.RefreshToken;
import com.nutritiontracker.backend.models.User;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
  Optional<RefreshToken> findByToken(String token);

  RefreshToken findByUser(User user);

  @Modifying
  int deleteByUser(User user);
}
