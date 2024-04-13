package com.thbs.security.auth;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.thbs.security.config.JwtService;
import com.thbs.security.user.ChangePasswordRequest;
import com.thbs.security.user.EmailRequest;

import java.io.IOException;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {

    private JwtService  jwtService;
  private final AuthenticationService service;

  // Endpoint for user registration
  @PostMapping("/register")
  public ResponseEntity<AuthenticationResponse> register(
      @RequestBody RegisterRequest request
  ) {
    return ResponseEntity.ok(service.register(request)); // Delegate the registration request to the AuthenticationService
  }

  // Endpoint for user authentication
  @PostMapping("/authenticate")
  public ResponseEntity<AuthenticationResponse> authenticate(
      @RequestBody AuthenticationRequest request
  ) {
    return ResponseEntity.ok(service.authenticate(request)); // Delegate the authentication request to the AuthenticationService
  }


    @GetMapping("/verifyEmailToken")
public ResponseEntity<String> verifyEmailToken(@RequestParam("token") String token) {
    return service.verifyEmailToken(token);

    
}


@PostMapping("/forgotpassword")
public ResponseEntity<String> forgotPassword(@RequestBody EmailRequest emails) {
    return service.forgotPassword(emails);
}


@GetMapping("/generatepassword")
public ResponseEntity<String> generatePassword(@RequestParam("token") String token) {
    return service.generatePassword(token);

}
@PostMapping("/resetpassword")
public ResponseEntity<String> resetPassword(@RequestBody Map<String, String> request) {

    String  newPassword = request.get("newPassword");
    String token=request.get("token");

    return service.resetPassword(token,newPassword);
}

@PutMapping("/changepassword")
    public ResponseEntity<String> changePassword(@RequestBody ChangePasswordRequest changePasswordRequest) {
        return service.changePassword(changePasswordRequest.getEmail(),changePasswordRequest.getOldPassword(), changePasswordRequest.getNewPassword());
    }




// @GetMapping("/generatepassword")
// public ResponseEntity<String> generatePassword(@RequestParam String token) {
//     if (jwtService.validateToken(token)) {
//         return ResponseEntity.status(HttpStatus.OK).body("redirect:/reset-password");
//     } else {
//         return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Token is expired.");
//     }
// }



  // Endpoint for refreshing tokens
  @PostMapping("/refresh-token")
  public void refreshToken(
      HttpServletRequest request,
      HttpServletResponse response
  ) throws IOException {
    service.refreshToken(request, response); // Delegate the token refresh request to the AuthenticationService
  }

}

