package com.thbs.security.auth;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // Generates getters, setters, toString, equals, and hashCode methods
@Builder // Builder pattern for easy object creation
@AllArgsConstructor // Generates a constructor with all arguments
@NoArgsConstructor // Generates a no-argument constructor
public class AuthenticationResponse {

  @JsonProperty("access_token") // Specifies the JSON property name for the access token field
  private String accessToken; // Represents the access token field of the authentication response

  @JsonProperty("refresh_token") // Specifies the JSON property name for the refresh token field
  private String refreshToken; 
  
  private String message;// Represents the refresh token field of the authentication response

}
