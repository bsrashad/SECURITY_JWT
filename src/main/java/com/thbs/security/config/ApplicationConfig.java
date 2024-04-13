package com.thbs.security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.thbs.security.auditing.ApplicationAuditAware;
import com.thbs.security.user.UserRepository;

@Configuration
@RequiredArgsConstructor
public class ApplicationConfig {

  private final UserRepository repository;

  // Configure a bean for user details service
  @Bean
  public UserDetailsService userDetailsService() {
    return username -> repository.findByEmail(username)
        .orElseThrow(() -> new UsernameNotFoundException("User not found")); // Load user details from the repository based on username
  }

  // Configure a bean for authentication provider
  @Bean
  public AuthenticationProvider authenticationProvider() {
    DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService()); // Set the user details service for authentication provider
    authProvider.setPasswordEncoder(passwordEncoder()); // Set the password encoder for authentication provider
    return authProvider;
  }

  // Configure a bean for auditor aware
  @Bean
  public AuditorAware<Integer> auditorAware() {
    return new ApplicationAuditAware(); // Initialize an instance of auditor aware
  }

  // Configure a bean for authentication manager
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
    return config.getAuthenticationManager(); // Retrieve the authentication manager from authentication configuration
  }

  // Configure a bean for password encoder
  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder(); // Use BCryptPasswordEncoder for password encoding
  }

}
