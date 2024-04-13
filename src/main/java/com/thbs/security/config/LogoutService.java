package com.thbs.security.config;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

import com.thbs.security.token.TokenRepository;

@Service
@RequiredArgsConstructor
public class LogoutService implements LogoutHandler {

    private final TokenRepository tokenRepository;

    @Override
    public void logout(
            HttpServletRequest request,
            HttpServletResponse response,
            Authentication authentication
    ) {
        final String authHeader = request.getHeader("Authorization"); // Retrieve the Authorization header from the request
        final String jwt;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) { // Check if the Authorization header is present and starts with "Bearer "
            return; // If not, return without further action
        }
        jwt = authHeader.substring(7); // Extract the JWT token from the Authorization header
        var storedToken = tokenRepository.findByToken(jwt) // Retrieve the token from the repository based on the JWT token
                .orElse(null); // If the token is not found, return null
        if (storedToken != null) { // If the token is found
            storedToken.setExpired(true); // Mark the token as expired
            storedToken.setRevoked(true); // Mark the token as revoked
            tokenRepository.save(storedToken); // Save the changes to the token in the repository
            SecurityContextHolder.clearContext(); // Clear the security context
        }
    }
}
