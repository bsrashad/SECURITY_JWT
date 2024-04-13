package com.thbs.security;

// Importing necessary Spring Boot and application-specific classes
import static com.thbs.security.user.Role.ADMIN;
import static com.thbs.security.user.Role.TRAINER;

import org.springframework.boot.CommandLineRunner; // Importing CommandLineRunner interface
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;


import com.thbs.security.auth.AuthenticationService;
import com.thbs.security.auth.RegisterRequest;


// Enable JPA auditing for entity classes, specifying the bean name for auditor awareness 
// This annotation tells Spring to enable tracking of who created or modified database records.
// When you save or update data in the database, Spring will automatically record when it happened and who did it.
@SpringBootApplication
@EnableJpaAuditing(auditorAwareRef = "auditorAware")
public class SecurityApplication {

    // Main method to run the Spring Boot application
    public static void main(String[] args) {
        SpringApplication.run(SecurityApplication.class, args);
    }

    // Bean definition to execute code at application startup
    @Bean
    public CommandLineRunner commandLineRunner(
            AuthenticationService service // AuthenticationService bean injected by Spring
    ) {
        return args -> {
            // Register an admin user
            var admin = RegisterRequest.builder()
                    .firstname("Admin")
                    .lastname("Admin")
                    .email("admin@mail.com")
                    .password("password")
                    .role(ADMIN)
                    .build();
            // Display the admin token generated after registration
            System.out.println("Admin token: " + service.register(admin).getAccessToken());

            // Register a trainer user
            var trainer = RegisterRequest.builder()
                    .firstname("Trainer")
                    .lastname("Trainer")
                    .email("trainer@mail.com")
                    .password("password")
                    .role(TRAINER)
                    .build();
            // Display the trainer token generated after registration
            System.out.println("Trainer token: " + service.register(trainer).getAccessToken());
        };
    }
}
