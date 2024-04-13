// package com.thbs.security.user;

// import lombok.RequiredArgsConstructor;
// import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
// import org.springframework.security.crypto.password.PasswordEncoder;
// import org.springframework.stereotype.Service;

// import java.security.Principal;

// // Service class responsible for user-related operations
// @Service
// @RequiredArgsConstructor // Lombok annotation to generate a constructor with required arguments
// public class UserService {

//     private final PasswordEncoder passwordEncoder; // Password encoder for encoding passwords
//     private final UserRepository repository; // UserRepository for accessing user data

//     // Method for changing user password
//     public void changePassword(ChangePasswordRequest request, Principal connectedUser) {

//         // Cast Principal to UsernamePasswordAuthenticationToken to access user details
//         var user = (User) ((UsernamePasswordAuthenticationToken) connectedUser).getPrincipal();

//         // Check if the current password provided matches the user's actual password
//         if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
//             throw new IllegalStateException("Wrong password");
//         }

//         // Check if the new password and confirmation password match
//         if (!request.getNewPassword().equals(request.getConfirmationPassword())) {
//             throw new IllegalStateException("Passwords do not match");
//         }

//         // Encode and set the new password for the user
//         user.setPassword(passwordEncoder.encode(request.getNewPassword()));

//         // Save the updated user entity with the new password
//         repository.save(user);
//     }
// }
