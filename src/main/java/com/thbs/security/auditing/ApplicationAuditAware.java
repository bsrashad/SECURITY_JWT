package com.thbs.security.auditing;

import org.springframework.data.domain.AuditorAware;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.thbs.security.user.User;

import java.util.Optional;

public class ApplicationAuditAware implements AuditorAware<Integer> {

    @Override
    public Optional<Integer> getCurrentAuditor() {
        // Retrieve the current authentication from the security context
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        // Check if authentication is null, not authenticated, or anonymous
        if (authentication == null ||
            !authentication.isAuthenticated() ||
            authentication instanceof AnonymousAuthenticationToken) {
            return Optional.empty(); // If not authenticated or anonymous, return empty
        }

        // Retrieve the user principal from the authentication
        User userPrincipal = (User) authentication.getPrincipal();
        
        // Return the ID of the current user as the current auditor
        return Optional.ofNullable(userPrincipal.getId());
    }
}
