package com.thbs.security.auth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // Generates getters, setters, toString, equals, and hashCode methods
@Builder // Builder pattern for easy object creation
@AllArgsConstructor // Generates a constructor with all arguments
@NoArgsConstructor // Generates a no-argument constructor
public class AuthenticationRequest {

  private String email; // Represents the email field of the authentication request
  private String password; // Represents the password field of the authentication request

}
