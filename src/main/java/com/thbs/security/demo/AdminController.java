package com.thbs.security.demo;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/admin") // This controller handles requests with the base URL "/api/v1/admin"
@PreAuthorize("hasRole('ADMIN')") // Restricts access to this controller to users with the role 'ADMIN'
public class AdminController {

    @GetMapping
    @PreAuthorize("hasAuthority('admin:read')") // Restricts access to the GET method to users with the authority 'admin:read'
    public String get() {
        return "GET:: admin controller"; // Returns a string indicating that this is the GET method of the admin controller
    }

    @PostMapping
    @PreAuthorize("hasAuthority('admin:create')") // Restricts access to the POST method to users with the authority 'admin:create'
    @Hidden // This method is marked as hidden, likely to indicate it should not be displayed in documentation or UI
    public String post() {
        return "POST:: admin controller"; // Returns a string indicating that this is the POST method of the admin controller
    }

    @PutMapping
    @PreAuthorize("hasAuthority('admin:update')") // Restricts access to the PUT method to users with the authority 'admin:update'
    @Hidden // This method is marked as hidden, likely to indicate it should not be displayed in documentation or UI
    public String put() {
        return "PUT:: admin controller"; // Returns a string indicating that this is the PUT method of the admin controller
    }

    @DeleteMapping
    @PreAuthorize("hasAuthority('admin:delete')") // Restricts access to the DELETE method to users with the authority 'admin:delete'
    @Hidden // This method is marked as hidden, likely to indicate it should not be displayed in documentation or UI
    public String delete() {
        return "DELETE:: admin controller"; // Returns a string indicating that this is the DELETE method of the admin controller
    }
}
