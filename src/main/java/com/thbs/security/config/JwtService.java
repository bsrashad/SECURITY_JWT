package com.thbs.security.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {

  @Value("${application.security.jwt.secret-key}") // Secret key used for JWT signing, configured in application properties
  private String secretKey;

  @Value("${application.security.jwt.expiration}") // Expiration time for JWT tokens, configured in application properties
  private long jwtExpiration;

  @Value("${application.security.jwt.refresh-token.expiration}") // Expiration time for refresh tokens, configured in application properties
  private long refreshExpiration;

  // Method to extract username from JWT token
  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  // Method to extract specific claim from JWT token
  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    final Claims claims = extractAllClaims(token);
    return claimsResolver.apply(claims);
  }

  // Method to generate JWT token
  public String generateToken(UserDetails userDetails) {
    return generateToken(new HashMap<>(), userDetails);
  }

  // Method to generate JWT token with extra claims
  public String generateToken(
      Map<String, Object> extraClaims,
      UserDetails userDetails
  ) {
    return buildToken(extraClaims, userDetails, jwtExpiration);
  }

  // Method to generate refresh token
  public String generateRefreshToken(
      UserDetails userDetails
  ) {
    return buildToken(new HashMap<>(), userDetails, refreshExpiration);
  }

  // Method to build JWT token
  private String buildToken(
          Map<String, Object> extraClaims,
          UserDetails userDetails,
          long expiration
  ) {
    return Jwts
            .builder()
            .setClaims(extraClaims)
            .setSubject(userDetails.getUsername())
            .setIssuedAt(new Date(System.currentTimeMillis()))
            .setExpiration(new Date(System.currentTimeMillis() + expiration))
            .signWith(getSignInKey(), SignatureAlgorithm.HS256)
            .compact();
  }

  // Method to validate JWT token
  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
  }

  // Method to check if JWT token is expired
  public boolean isTokenExpired(String token) {
    return extractExpiration(token).before(new Date());
  }

  // Method to extract token expiration date from JWT token
  private Date extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration);
  }

  // Method to extract all claims from JWT token
  private Claims extractAllClaims(String token) {
    return Jwts
        .parserBuilder()
        .setSigningKey(getSignInKey())
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  // Method to get the signing key used for JWT
  private Key getSignInKey() {
    byte[] keyBytes = Decoders.BASE64.decode(secretKey);
    return Keys.hmacShaKeyFor(keyBytes);
  }
}
