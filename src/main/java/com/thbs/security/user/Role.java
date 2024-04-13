package com.thbs.security.user;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static com.thbs.security.user.Permission.ADMIN_CREATE;
import static com.thbs.security.user.Permission.ADMIN_DELETE;
import static com.thbs.security.user.Permission.ADMIN_READ;
import static com.thbs.security.user.Permission.ADMIN_UPDATE;
import static com.thbs.security.user.Permission.TRAINER_CREATE;
import static com.thbs.security.user.Permission.TRAINER_DELETE;
import static com.thbs.security.user.Permission.TRAINER_READ;
import static com.thbs.security.user.Permission.TRAINER_UPDATE;

import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

// This annotation indicates that a constructor will be generated with required arguments for the enum fields.
@RequiredArgsConstructor
public enum Role {

  // Enum constant representing a basic user role with no special permissions.
  USER(Collections.emptySet()),

  // Enum constant representing an admin role with permissions for admin and trainer actions.
  ADMIN(
          Set.of(
                  ADMIN_READ,
                  ADMIN_UPDATE,
                  ADMIN_DELETE,
                  ADMIN_CREATE,
                  TRAINER_READ,
                  TRAINER_UPDATE,
                  TRAINER_DELETE,
                  TRAINER_CREATE
          )
  ),

  // Enum constant representing a trainer role with permissions for trainer actions.
  TRAINER(
          Set.of(
                TRAINER_READ,
                TRAINER_UPDATE,
                TRAINER_DELETE,
                TRAINER_CREATE
          )
  );

  // Getter annotation to automatically generate a getter method for the permissions field.
  @Getter
  private final Set<Permission> permissions;

  // This method generates a list of authorities for a role, combining permissions and role itself.
  public List<SimpleGrantedAuthority> getAuthorities() {
    // Mapping each permission to a SimpleGrantedAuthority object representing an authority.
    var authorities = getPermissions()
            .stream()
            .map(permission -> new SimpleGrantedAuthority(permission.getPermission()))
            .collect(Collectors.toList());

    // Adding an authority representing the role itself with a prefix "ROLE_".
    authorities.add(new SimpleGrantedAuthority("ROLE_" + this.name()));

    // Returning the list of authorities.
    return authorities;
  }
}
