package com.thbs.security.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thbs.security.config.EmailService;
import com.thbs.security.config.JwtService;
import com.thbs.security.token.Token;
import com.thbs.security.token.TokenRepository;
import com.thbs.security.token.TokenType;
import com.thbs.security.user.EmailRequest;
import com.thbs.security.user.User;
import com.thbs.security.user.UserRepository;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
  private final EmailService  emailService;
  private final UserRepository repository;
  private final TokenRepository tokenRepository;
  private final PasswordEncoder passwordEncoder;

  @Autowired
  private final JwtService jwtService;
  private final AuthenticationManager authenticationManager;

  // Method to handle user registration
  public AuthenticationResponse register(RegisterRequest request) {
    // Create a new user entity based on the registration request
    var user = User.builder()
        .firstname(request.getFirstname())
        .lastname(request.getLastname())
        .email(request.getEmail())
        .password(passwordEncoder.encode(request.getPassword()))
        .isemailverified(false)
        .role(request.getRole())
        .build();
    // Save the user to the repository
    var savedUser = repository.save(user);
    // Generate JWT token and refresh token for the user
    var jwtToken = jwtService.generateToken(user);
    String verificationUrl = "http://localhost:4321/api/v1/auth/verifyEmailToken?token=" + jwtToken;
    emailService.sendEmail(request.getEmail(),"email verification", verificationUrl);
    System.out.println("-------------------"+verificationUrl);
    var refreshToken = jwtService.generateRefreshToken(user);
    // Save the user's token in the repository
    saveUserToken(savedUser, jwtToken);
    // Return the authentication response containing the tokens
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
        .refreshToken(refreshToken)
        .message("Registration successful but email has to be verified ")
        .build();
  }

  // Method to handle user authentication
  public AuthenticationResponse authenticate(AuthenticationRequest request) {
    // Authenticate user using Spring Security's authentication manager
    authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(
            request.getEmail(),
            request.getPassword()
        )
    );
    // Retrieve user details from the repository
    var user = repository.findByEmail(request.getEmail())
        .orElseThrow();
        String message="";
        if(user.isIsemailverified()){
          message="successfully login";
        }else{
          message="email has to be verfied";
        }
    // Generate JWT token and refresh token for the user
    var jwtToken = jwtService.generateToken(user);
    var refreshToken = jwtService.generateRefreshToken(user);
    // Revoke all existing user tokens
    revokeAllUserTokens(user);
    // Save the user's new token in the repository
    saveUserToken(user, jwtToken);
    // Return the authentication response containing the tokens
    return AuthenticationResponse.builder()
        .accessToken(jwtToken)
        .refreshToken(refreshToken)
        .message(message)
        .build();
  }

  public ResponseEntity<String> verifyEmailToken( String token) {
    System.out.println("+++++++######++++++++"+token);
if(!jwtService.isTokenExpired(token)){
  String email=jwtService.extractUsername(token);
  User user = repository.findByEmail(email)
        .orElseThrow();
        user.setEmailVerified(true);
        repository.save(user);
  
    return ResponseEntity.ok("Email verified successfully");
}
return ResponseEntity.badRequest().body("Invalid token or user already verified");

    
}

public ResponseEntity<String> forgotPassword( EmailRequest emails) {
    System.out.println("$$$$$$$$$$"+emails.getEmail());
    User user = repository.findByEmail(emails.getEmail()).orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + emails.getEmail()));

    
    if (user != null) {
        String jwt = jwtService.generateToken(user);
        String verificationUrl = "http://localhost:4321/api/v1/auth/generatepassword?token=" + jwt;
        emailService.sendEmail(emails.getEmail(), "forgot password", verificationUrl);
        return ResponseEntity.status(HttpStatus.OK).body("Link sent to your email for reset password");
    }

    return ResponseEntity.status(HttpStatus.OK).body("User not exists");
}

public ResponseEntity<String> generatePassword(String token) {
  if(!jwtService.isTokenExpired(token)){
      return ResponseEntity.ok("RESET PASSWORD PAGE REDIRECTED successfully");
  } else {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token is expired.");
  }

}


public ResponseEntity<String> resetPassword( String token,String newPassword) {
    

  if(!jwtService.isTokenExpired(token)){

      String email = jwtService.extractUsername(token);
      User user = repository.findByEmail(email).orElseThrow();
      user.setPassword(passwordEncoder.encode(newPassword));
      // user.setPassword(newPassword);
      user = repository.save(user);

      return ResponseEntity.ok("RESET PASSWORD successfully");
  } else {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token is expired.");
  }
}

public ResponseEntity<String> changePassword( String email, String oldPassword,String newPassword) {
  // String oldpasswordencoded= passwordEncoder.encode(oldPassword);
  // Optional<User> userOptional = repository.findByUsernameAndPassword(email, passwordEncoder.matches(newPassword, oldPassword)  oldPassword);
  Optional<User> userOptional = repository.findByEmail(email);
  if (userOptional.isPresent()) {
      User user = userOptional.get();
      if(passwordEncoder.matches(oldPassword, user.getPassword())){
          String encodednewpassword=passwordEncoder.encode(newPassword);
          user.setPassword(encodednewpassword);
      repository.save(user);
      return ResponseEntity.status(HttpStatus.OK).body("Password changed successfully for " + email);
      }else{
          return ResponseEntity.status(HttpStatus.OK).body("password doesnt match");
      }
      
      
  } else {
      return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Invalid email ");
  }
}

  // Method to save user token in the repository
  private void saveUserToken(User user, String jwtToken) {
    var token = Token.builder()
        .user(user)
        .token(jwtToken)
        .tokenType(TokenType.BEARER)
        .expired(false)
        .revoked(false)
        .build();
    tokenRepository.save(token);
  }

  // Method to revoke all existing user tokens
  private void revokeAllUserTokens(User user) {
    var validUserTokens = tokenRepository.findAllValidTokenByUser(user.getId());
    if (validUserTokens.isEmpty())
      return;
    validUserTokens.forEach(token -> {
      token.setExpired(true);
      token.setRevoked(true);
    });
    tokenRepository.saveAll(validUserTokens);
  }

  // Method to handle token refreshing
  public void refreshToken(
          HttpServletRequest request,
          HttpServletResponse response
  ) throws IOException {
    final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
    final String refreshToken;
    final String userEmail;
    if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
      return;
    }
    refreshToken = authHeader.substring(7);
    userEmail = jwtService.extractUsername(refreshToken);
    if (userEmail != null) {
      var user = this.repository.findByEmail(userEmail)
              .orElseThrow();
      if (jwtService.isTokenValid(refreshToken, user)) {
        var accessToken = jwtService.generateToken(user);
        revokeAllUserTokens(user);
        saveUserToken(user, accessToken);
        // Prepare authentication response containing new access token and refresh token
        var authResponse = AuthenticationResponse.builder()
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
        // Write the response to the output stream
        new ObjectMapper().writeValue(response.getOutputStream(), authResponse);
      }
    }
  }
}
