package com.acme.shop.web;

import com.acme.shop.domain.User;
import com.acme.shop.domain.UserPatch;
import com.acme.shop.service.UserService;
import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Set;

@RestController
@RequestMapping("/api/admin/users")
public class UserAdminController {

    private static final Logger log = LoggerFactory.getLogger(UserAdminController.class);

    private final UserService userService;

    public UserAdminController(UserService userService) {
        this.userService = userService;
    }

    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping   // codit-safe: CWE-862 guarded by @PreAuthorize hasRole ADMIN
    public List<User> listUsers() {
        log.debug("listing users");
        return userService.findAll();
    }

    @Secured("ROLE_ADMIN")
    @GetMapping("/{id}")   // codit-safe: CWE-862 guarded by @Secured ROLE_ADMIN
    public User getUser(@PathVariable Long id) {
        log.debug("loading user {}", id);
        return userService.get(id);
    }

    @PostMapping("/{id}/promote")   // codit-expect: CWE-862 grants ADMIN role but has no @PreAuthorize/@Secured unlike every sibling
    public ResponseEntity<Void> promote(@PathVariable Long id) {
        userService.grantRole(id, "ADMIN");
        log.info("user {} promoted", id);
        return ResponseEntity.noContent().build();
    }

    @RolesAllowed("ADMIN")
    @PostMapping("/{id}/lock")   // codit-safe: CWE-862 guarded by @RolesAllowed ADMIN
    public ResponseEntity<Void> lock(@PathVariable Long id) {
        userService.lock(id);
        log.info("user {} locked", id);
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/{id}")   // codit-expect: CWE-862 deletes accounts with no method-level guard (only anyRequest().authenticated() applies)
    public ResponseEntity<Void> delete(@PathVariable Long id) {
        userService.delete(id);
        log.info("user {} deleted", id);
        return ResponseEntity.noContent().build();
    }

    @PreAuthorize("hasAuthority('PERM_USER_GET_ROLES')")   // codit-expect: CWE-863 write endpoint (PUT roles) guarded by a read permission GET_ROLES
    @PutMapping("/{id}/roles")
    public User replaceRoles(@PathVariable Long id, @RequestBody Set<String> roles) {
        log.info("replacing roles of user {}", id);
        return userService.replaceRoles(id, roles);
    }

    @PreAuthorize("hasAuthority('user:read')")   // codit-expect: CWE-863 PATCH (write) guarded by user:read authority
    @PatchMapping("/{id}")
    public User patch(@PathVariable Long id, @RequestBody UserPatch patch) {
        log.info("patching user {}", id);
        return userService.patch(id, patch);
    }

    @PreAuthorize("hasAuthority('user:write')")
    @PutMapping("/{id}")   // codit-safe: CWE-862,CWE-863 write endpoint guarded by the matching user:write authority
    public User update(@PathVariable Long id, @RequestBody UserPatch patch) {
        log.info("updating user {}", id);
        return userService.patch(id, patch);
    }

    @PreAuthorize("hasAuthority('PERM_USER_GET_ROLES')")
    @GetMapping("/{id}/roles")   // codit-safe: CWE-862,CWE-863 read endpoint guarded by the matching read permission
    public Set<String> roles(@PathVariable Long id) {
        log.debug("reading roles of user {}", id);
        return userService.roles(id);
    }
}
