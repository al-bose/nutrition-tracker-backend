package com.nutritiontracker.backend.payload.response;

import lombok.Data;

@Data
public class JwtResponse {
  private String token;
  private String type = "Bearer";
  private String refreshToken;
  private Long id;
  private String username;
  private String email;
  private String firstName;
  private String lastName;

  public JwtResponse(String accessToken, String refreshToken, Long id, String username, String email, String firstName, String lastName) {
    this.token = accessToken;
    this.refreshToken = refreshToken;
    this.id = id;
    this.username = username;
    this.email = email;
    this.firstName = firstName;
    this.lastName = lastName;
  }

}
