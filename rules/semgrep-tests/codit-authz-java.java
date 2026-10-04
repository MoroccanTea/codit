// Test target for rules/semgrep/codit-authz-java.yaml (semgrep --test).
package com.example.tests;

import java.security.Principal;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

// ---------------------------------------------------------------- missing-authz-in-guarded-controller
@RestController
@RequestMapping("/admin/users")
public class UserAdminController {

    private final UserRepository users;

    public UserAdminController(UserRepository users) {
        this.users = users;
    }

    // ok: codit.java.spring.missing-authz-in-guarded-controller
    @PreAuthorize("hasRole('ADMIN')")
    @GetMapping
    public List<User> list() {
        return users.findAll();
    }

    // ruleid: codit.java.spring.missing-authz-in-guarded-controller
    @PostMapping("/{id}/promote")
    public void promote(@PathVariable Long id) {
        users.grantAdmin(id);
    }

    // ruleid: codit.java.spring.missing-authz-in-guarded-controller
    @DeleteMapping(value = "/{id}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable("id") Long id) {
        users.deleteUser(id);
    }

    // ok: codit.java.spring.missing-authz-in-guarded-controller
    @Secured("ROLE_ADMIN")
    @PostMapping("/{id}/lock")
    public void lock(@PathVariable Long id) {
        users.lock(id);
    }

    // ok: codit.java.spring.missing-authz-in-guarded-controller
    @PermitAll
    @GetMapping("/public-count")
    public long count() {
        return users.count();
    }

    // ok: codit.java.spring.missing-authz-in-guarded-controller
    private void helperWithoutMapping() {
    }
}

// no guarded sibling at all -> URL security is the convention, not reported by this rule
@RestController
public class CatalogController {
    // ok: codit.java.spring.missing-authz-in-guarded-controller
    @GetMapping("/products")
    public List<Product> products() {
        return List.of();
    }

    // ok: codit.java.spring.missing-authz-in-guarded-controller
    @GetMapping("/products/{id}")
    public Product product(@PathVariable Long id) {
        return null;
    }
}

// class-level guard covers every handler
@RestController
@PreAuthorize("hasRole('AUDITOR')")
public class ReportController {
    // ok: codit.java.spring.missing-authz-in-guarded-controller
    @GetMapping("/revenue")
    public Report revenue() {
        return null;
    }

    // ok: codit.java.spring.missing-authz-in-guarded-controller
    @PreAuthorize("hasRole('ADMIN')")
    @DeleteMapping("/{id}")
    public void purge(@PathVariable Long id) {
    }
}

// ---------------------------------------------------------------- write-endpoint-guarded-by-read-permission
@RestController
public class RoleController {
    // ruleid: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PreAuthorize("hasAuthority('PERM_USER_GET_ROLES')")
    @PutMapping("/users/{id}/roles")
    public void replaceRoles(@PathVariable Long id, @RequestBody Set<String> roles) {
    }

    // ruleid: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PatchMapping("/users/{id}")
    @PreAuthorize("hasAuthority('user:read')")
    public void patchUser(@PathVariable Long id, @RequestBody Map<String, Object> body) {
    }

    // ruleid: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PreAuthorize("hasRole('VIEWER')")
    @RequestMapping(value = "/users/{id}", method = RequestMethod.DELETE)
    public void removeUser(@PathVariable Long id) {
    }

    // ok: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PreAuthorize("hasAuthority('user:write')")
    @PutMapping("/users/{id}")
    public void updateUser(@PathVariable Long id, @RequestBody UserDto dto) {
    }

    // ok: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PreAuthorize("hasAuthority('user:read')")
    @GetMapping("/users/{id}/roles")
    public Set<String> roles(@PathVariable Long id) {
        return Set.of();
    }

    // POST used for a search is a read operation
    // ok: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PreAuthorize("hasAuthority('ORDER_READ')")
    @PostMapping("/orders/search")
    public List<Order> searchOrders(@RequestBody Criteria c) {
        return List.of();
    }

    // read OR admin: the admin part legitimately grants the write
    // ok: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PreAuthorize("hasAuthority('ORDER_READ') and hasRole('ADMIN')")
    @DeleteMapping("/orders/{id}")
    public void deleteOrder(@PathVariable Long id) {
    }

    // "thread" contains "read" but not as a word
    // ok: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PreAuthorize("hasAuthority('THREAD_MODERATOR')")
    @PostMapping("/threads/{id}/close")
    public void closeThread(@PathVariable Long id) {
    }
}

// ---------------------------------------------------------------- idor-findbyid-without-ownership-check
@RestController
@RequestMapping("/api/orders")
@PreAuthorize("isAuthenticated()")
public class OrderController {

    private final OrderRepository orders;
    private final InvoiceService invoiceService;

    public OrderController(OrderRepository orders, InvoiceService invoiceService) {
        this.orders = orders;
        this.invoiceService = invoiceService;
    }

    @GetMapping("/{id}")
    public Order get(@PathVariable Long id) {
        // ruleid: codit.java.spring.idor-findbyid-without-ownership-check
        return orders.findById(id).orElseThrow(OrderNotFoundException::new);
    }

    @PutMapping("/{id}/cancel")
    public Order cancel(@PathVariable("id") final Long id) {
        // ruleid: codit.java.spring.idor-findbyid-without-ownership-check
        Order order = this.orders.findById(id).orElseThrow(OrderNotFoundException::new);
        order.cancel();
        return orders.save(order);
    }

    @DeleteMapping("/{id}")
    public void drop(@PathVariable Long id, OrderRepository orderRepo) {
        // ruleid: codit.java.spring.idor-findbyid-without-ownership-check
        orderRepo.deleteById(id);
    }

    @GetMapping("/mine/{id}")
    public Order getMine(@PathVariable Long id, Principal principal) {
        // ok: codit.java.spring.idor-findbyid-without-ownership-check
        return orders.findById(id).filter(o -> o.getOwner().equals(principal.getName())).orElseThrow();
    }

    @GetMapping("/{id}/receipt")
    public Receipt receipt(@PathVariable Long id) {
        // ok: codit.java.spring.idor-findbyid-without-ownership-check
        Order order = orders.findById(id).orElseThrow(OrderNotFoundException::new);
        String current = SecurityContextHolder.getContext().getAuthentication().getName();
        if (!order.getOwner().equals(current)) {
            throw new AccessDeniedException("not your order");
        }
        return order.toReceipt();
    }

    @PostAuthorize("returnObject.owner == authentication.name")
    @GetMapping("/{id}/summary")
    public Order summary(@PathVariable Long id) {
        // ok: codit.java.spring.idor-findbyid-without-ownership-check
        return orders.findById(id).orElseThrow(OrderNotFoundException::new);
    }

    @PreAuthorize("hasPermission(#id, 'Order', 'read')")
    @GetMapping("/{id}/lines")
    public List<Line> lines(@PathVariable Long id) {
        // ok: codit.java.spring.idor-findbyid-without-ownership-check
        return orders.findById(id).map(Order::getLines).orElseThrow();
    }

    @GetMapping("/{id}/invoice")
    public Invoice invoice(@PathVariable Long id) {
        // a service is not a repository: may scope internally, not reported
        // ok: codit.java.spring.idor-findbyid-without-ownership-check
        return invoiceService.findById(id);
    }

    @GetMapping("/{id}/owner-check")
    public Order ownerCheck(@PathVariable Long id, @AuthenticationPrincipal UserDetails me) {
        // ok: codit.java.spring.idor-findbyid-without-ownership-check
        Order o = orders.findById(id).orElseThrow();
        if (!o.getOwner().equals(me.getUsername())) throw new AccessDeniedException("no");
        return o;
    }

    @GetMapping("/by-query")
    public Order byQuery(@RequestParam Long id) {
        // not a path variable: out of scope of this rule
        // ok: codit.java.spring.idor-findbyid-without-ownership-check
        return orders.findById(id).orElseThrow();
    }
}

@RestController
@PreAuthorize("hasRole('ADMIN')")
public class AdminOrderController {
    private final OrderRepository orders;

    @GetMapping("/admin/orders/{id}")
    public Order get(@PathVariable Long id) {
        // admin-only controller may read any order
        // ok: codit.java.spring.idor-findbyid-without-ownership-check
        return orders.findById(id).orElseThrow();
    }
}

// ---------------------------------------------------------------- permitall-on-all-paths / web-ignoring-all-paths
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain api(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/css/**", "/favicon.ico").permitAll()
                // ruleid: codit.java.spring.permitall-on-all-paths
                .requestMatchers("/api/**").permitAll()
                // ok: codit.java.spring.permitall-on-all-paths
                .requestMatchers("/admin/**").hasRole("ADMIN")
                // ok: codit.java.spring.permitall-on-all-paths
                .anyRequest().authenticated());
        // ok: codit.java.spring.permitall-on-all-paths
        http.formLogin(form -> form.loginPage("/login").permitAll());
        return http.build();
    }

    @Bean
    SecurityFilterChain demo(HttpSecurity http) throws Exception {
        // ruleid: codit.java.spring.permitall-on-all-paths
        http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll());
        return http.build();
    }

    @Bean
    SecurityFilterChain legacy(HttpSecurity http) throws Exception {
        // ruleid: codit.java.spring.permitall-on-all-paths
        http.authorizeRequests().antMatchers("/**").permitAll();
        return http.build();
    }

    @Bean
    WebSecurityCustomizer everything() {
        // ruleid: codit.java.spring.web-ignoring-all-paths
        return web -> web.ignoring().requestMatchers("/**");
    }

    @Bean
    WebSecurityCustomizer staticOnly() {
        // ok: codit.java.spring.web-ignoring-all-paths
        return web -> web.ignoring().requestMatchers("/static/**", "/webjars/**");
    }

    @Bean
    WebSecurityCustomizer legacyAll() {
        // ruleid: codit.java.spring.web-ignoring-all-paths
        return web -> web.ignoring().antMatchers("/css/**", "/**");
    }
}

// method security does not protect handlers that have no guard of their own
@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {
    @Bean
    SecurityFilterChain chain(HttpSecurity http) throws Exception {
        if (LDAP.equals(mode)) {
            // ruleid: codit.java.spring.permitall-on-all-paths
            http.authorizeHttpRequests(accessManagement -> accessManagement.anyRequest().permitAll());
        } else {
            http.authorizeHttpRequests(accessManagement -> accessManagement
                // ok: codit.java.spring.permitall-on-all-paths
                .requestMatchers(HttpMethod.OPTIONS).permitAll()
                // ok: codit.java.spring.permitall-on-all-paths
                .requestMatchers(AUTH_WHITELIST).permitAll()
                // ok: codit.java.spring.permitall-on-all-paths
                .anyRequest().authenticated());
        }
        return http.build();
    }
}

// ---------------------------------------------------------------- handlers declared on an API interface
@RequestMapping("/api/v1/settings/user")
public interface UserApi {
    // ok: codit.java.spring.missing-authz-in-guarded-controller
    @GetMapping
    @PreAuthorize("@roleAccessHandler.hasPermission(\"" + Permissions.PERM_USER_GET + "\")")
    ResponseEntity<List<User>> findAllUsers();

    // ruleid: codit.java.spring.missing-authz-in-guarded-controller
    @DeleteMapping("/{id}")
    ResponseEntity<Void> deleteUser(@PathVariable String id);

    // ruleid: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PutMapping("/{id}/roles")
    @PreAuthorize("@roleAccessHandler.hasPermission(\"" + Permissions.PERM_USER_GET_ROLES + "\")")
    ResponseEntity<List<Role>> replaceRoles(@PathVariable String id, @RequestBody List<String> roles);

    // getter mapped to PUT: same read permission is consistent
    // ok: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PutMapping("/roles")
    @PreAuthorize("@roleAccessHandler.hasPermission(\"" + Permissions.PERM_USER_GET_ROLES + "\")")
    ResponseEntity<List<Role>> getUserRoles();

    // ok: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PostMapping("/{id}/reset-password")
    @PreAuthorize("@roleAccessHandler.hasPermission(\"" + Permissions.PERM_USER_PUT + "\")")
    ResponseEntity<Void> resetUserPassword(@PathVariable String id);

    // "Wallet" contains "all" but is not a write grant
    // ruleid: codit.java.spring.write-endpoint-guarded-by-read-permission
    @PreAuthorize("hasPermission(#id, 'Wallet', 'read')")
    @DeleteMapping("/wallets/{id}")
    ResponseEntity<Void> dropWallet(@PathVariable String id);
}

@PreAuthorize("isAuthenticated()")
public interface GuardedApi {
    // ok: codit.java.spring.missing-authz-in-guarded-controller
    @PostMapping("/x")
    void x();

    @PreAuthorize("hasRole('ADMIN')")
    @PostMapping("/y")
    void y();
}
