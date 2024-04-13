

package com.thbs.security.token;

import com.thbs.security.user.User; // Importing the User class

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

// Lombok annotations for generating boilerplate code
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity // Indicates that this class is an entity, mapped to a database table
public class Token {

  @Id
  @GeneratedValue
  public Integer id; // Unique identifier for the token

  @Column(unique = true)
  public String token; // The actual token value, marked as unique in the database

  @Enumerated(EnumType.STRING)
  public TokenType tokenType = TokenType.BEARER; // Enumerated type for different token types, defaulting to BEARER

  public boolean revoked; // Flag indicating if the token is revoked

  public boolean expired; // Flag indicating if the token is expired

  //  Hibernate Feature - LAZY LOADING !!
  @ManyToOne(fetch = FetchType.LAZY) // Many-to-one relationship with the User entity, lazy fetching
  @JoinColumn(name = "user_id") // Foreign key column in the Token table referencing the User table
  public User user; // User associated with the token
}
