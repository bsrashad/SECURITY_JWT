// package com.thbs.security.user;

// import lombok.RequiredArgsConstructor;
// import org.springframework.http.ResponseEntity;
// import org.springframework.web.bind.annotation.PatchMapping;
// import org.springframework.web.bind.annotation.RequestBody;
// import org.springframework.web.bind.annotation.RequestMapping;
// import org.springframework.web.bind.annotation.RestController;

// import java.security.Principal;

// @RestController
// @RequestMapping("/api/v1/users") // Base URL path for the UserController
// @RequiredArgsConstructor // Lombok annotation to generate a constructor with required arguments
// public class UserController {

//     private final UserService service; // Instance of UserService injected via constructor

//     // Endpoint to handle PATCH requests for changing user passwords
//     @PatchMapping
//     public ResponseEntity<?> changePassword(
//           @RequestBody ChangePasswordRequest request, // Request body containing password change information
//           Principal connectedUser // Principal object representing the currently authenticated user
//     ) {
//         service.changePassword(request, connectedUser); // Delegate password change operation to UserService
//         return ResponseEntity.ok().build(); // Return a response indicating success (HTTP 200 OK)
//     }
// }
