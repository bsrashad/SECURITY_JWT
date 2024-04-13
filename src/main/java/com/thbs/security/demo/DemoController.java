package com.thbs.security.demo;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo-controller") // This controller handles requests with the base URL "/api/v1/demo-controller"
@Hidden // This controller is marked as hidden, likely indicating it should not be exposed in documentation or UI
public class DemoController {

    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("Hello from secured endpoint"); // Returns a response entity with a message indicating successful access to the endpoint
    }
}
