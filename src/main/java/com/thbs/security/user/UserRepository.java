package com.thbs.security.user;

import java.util.Optional; // Importing the Optional class from the java.util package
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

// JpaRepository interface for handling User entity persistence operations
@Repository
public interface UserRepository extends JpaRepository<User, Integer> {

  // Method to find a user by their email address
  // The return type is Optional<User>, which means it may or may not contain a User object
  Optional<User> findByEmail(String email);

}
