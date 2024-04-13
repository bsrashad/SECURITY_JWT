package com.thbs.security.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

// Lombok annotation to automatically generate a constructor with required arguments.
@RequiredArgsConstructor
public enum Permission {

    // Enum constants representing different permissions with associated string values.
    ADMIN_READ("admin:read"),
    ADMIN_UPDATE("admin:update"),
    ADMIN_CREATE("admin:create"),
    ADMIN_DELETE("admin:delete"),
    TRAINER_READ("management:read"),
    TRAINER_UPDATE("management:update"),
    TRAINER_CREATE("management:create"),
    TRAINER_DELETE("management:delete");

    // Getter annotation to automatically generate a getter method for the permission field.
    @Getter
    private final String permission; // String value representing the permission.

}
