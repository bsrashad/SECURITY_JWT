package com.thbs.security.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;

import lombok.RequiredArgsConstructor;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.thbs.security.token.TokenRepository;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  @Autowired
  private final JwtService jwtService;
  @Autowired
  private final UserDetailsService userDetailsService;
  @Autowired
  private final TokenRepository tokenRepository;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain
  ) throws ServletException, IOException {
    if (request.getServletPath().contains("/api/v1/auth")) {
      filterChain.doFilter(request, response);
      return;
    }
    final String authHeader = request.getHeader("Authorization"); // Retrieve the Authorization header from the request
    final String jwt;
    final String userEmail;
    if (authHeader == null || !authHeader.startsWith("Bearer ")) { // Check if the Authorization header is present and starts with "Bearer "
      filterChain.doFilter(request, response); // If not, continue to the next filter in the chain
      return;
    }
    jwt = authHeader.substring(7); // Extract the JWT token from the Authorization header
    userEmail = jwtService.extractUsername(jwt); // Extract the user email from the JWT token
    if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail); // Load user details from the database using the user email
      var isTokenValid = tokenRepository.findByToken(jwt) // Retrieve the token from the repository based on the JWT token
          .map(t -> !t.isExpired() && !t.isRevoked()) // Check if the token is not expired and not revoked
          .orElse(false);
      if (jwtService.isTokenValid(jwt, userDetails) && isTokenValid) { // Check if the token is valid and not revoked
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
            userDetails,
            null,
            userDetails.getAuthorities()
        ); // Create an authentication token
        authToken.setDetails( // Set the authentication details
            new WebAuthenticationDetailsSource().buildDetails(request)
        );
        SecurityContextHolder.getContext().setAuthentication(authToken); // Set the authentication token in the security context
      }
    }
    filterChain.doFilter(request, response); // Continue to the next filter in the chain
  }
}
