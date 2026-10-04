package com.acme.portal.admin;

import com.acme.portal.service.MaintenanceService;
import com.acme.portal.service.UserDirectory;
import com.acme.portal.service.UserSummary;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * No method annotations on purpose: SecurityConfig.adminChain requires ROLE_ADMIN for /admin/**.
 */
@RestController
@RequestMapping("/admin")
public class AdminController {

    private final UserDirectory directory;
    private final MaintenanceService maintenance;

    public AdminController(UserDirectory directory, MaintenanceService maintenance) {
        this.directory = directory;
        this.maintenance = maintenance;
    }

    @GetMapping("/users")   // codit-safe: CWE-862 protected by requestMatchers("/admin/**").hasRole("ADMIN")
    public List<UserSummary> users() {
        return directory.summaries();
    }

    @DeleteMapping("/users/{username}")   // codit-safe: CWE-862 protected by the /admin/** URL rule
    public ResponseEntity<Void> deleteUser(@PathVariable String username) {
        directory.deactivate(username);
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/maintenance")   // codit-safe: CWE-862 protected by the /admin/** URL rule
    public ResponseEntity<Void> maintenanceMode() {
        maintenance.enable();
        return ResponseEntity.accepted().build();
    }
}
