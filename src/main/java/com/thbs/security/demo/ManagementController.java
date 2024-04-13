package com.thbs.security.demo;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/trainee-management") // This controller handles requests with the base URL "/api/v1/trainee-management"
@Tag(name = "Trainee Management") // This tag is for grouping related endpoints in Swagger documentation
public class ManagementController {

    @Operation(
            description = "Get endpoint for trainee management", // Description of the operation
            summary = "This is a summary for trainee management get endpoint", // Summary of the operation
            responses = {
                    @ApiResponse(
                            description = "Success", // Description of the success response
                            responseCode = "200" // HTTP response code for success
                    ),
                    @ApiResponse(
                            description = "Unauthorized / Invalid Token", // Description of the unauthorized response
                            responseCode = "403" // HTTP response code for unauthorized
                    )
            }
    )
    @GetMapping
    public String get() {
        return "GET:: trainee management controller"; // Returns a string indicating that this is the GET method of the trainee management controller
    }

    @PostMapping
    public String post() {
        return "POST:: trainee management controller"; // Returns a string indicating that this is the POST method of the trainee management controller
    }

    @PutMapping
    public String put() {
        return "PUT:: trainee management controller"; // Returns a string indicating that this is the PUT method of the trainee management controller
    }

    @DeleteMapping
    public String delete() {
        return "DELETE:: trainee management controller"; // Returns a string indicating that this is the DELETE method of the trainee management controller
    }
}
