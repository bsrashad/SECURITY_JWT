package com.thbs.security.auth;

import com.thbs.security.user.Role; // Importing the Role enum

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data // Generates getters, setters, toString, equals, and hashCode methods
@Builder // Builder pattern for easy object creation
@AllArgsConstructor // Generates a constructor with all arguments
@NoArgsConstructor // Generates a no-argument constructor
public class RegisterRequest {

  private String firstname; // Represents the first name field of the registration request
  private String lastname; // Represents the last name field of the registration request
  private String email; // Represents the email field of the registration request
  private String password; // Represents the password field of the registration request
  private Role role; // Represents the role field of the registration request (using Role enum)

}
