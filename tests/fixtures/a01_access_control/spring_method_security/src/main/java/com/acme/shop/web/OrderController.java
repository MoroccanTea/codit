package com.acme.shop.web;

import com.acme.shop.domain.Order;
import com.acme.shop.domain.OrderNotFoundException;
import com.acme.shop.domain.Receipt;
import com.acme.shop.repository.OrderRepository;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
@RequestMapping("/api/orders")
@PreAuthorize("isAuthenticated()")
public class OrderController {

    private final OrderRepository orders;

    public OrderController(OrderRepository orders) {
        this.orders = orders;
    }

    @GetMapping("/{id}")
    public Order get(@PathVariable Long id) {
        return orders.findById(id).orElseThrow(OrderNotFoundException::new);   // codit-expect: CWE-639 returns any customer's order by id, no principal/owner check
    }

    @GetMapping("/mine/{id}")
    public Order getMine(@PathVariable Long id, Principal principal) {
        return orders.findByIdAndOwner(id, principal.getName())   // codit-safe: CWE-639 ownership-scoped repository query
                .orElseThrow(OrderNotFoundException::new);
    }

    @GetMapping("/{id}/receipt")
    public Receipt receipt(@PathVariable Long id) {
        Order order = orders.findById(id).orElseThrow(OrderNotFoundException::new);   // codit-safe: CWE-639 owner compared with SecurityContextHolder principal right below
        String current = SecurityContextHolder.getContext().getAuthentication().getName();
        if (!order.getOwner().equals(current)) {
            throw new AccessDeniedException("not your order");
        }
        return order.toReceipt();
    }

    @PutMapping("/{id}/cancel")
    public Order cancel(@PathVariable Long id) {
        Order order = orders.findById(id).orElseThrow(OrderNotFoundException::new);   // codit-expect: CWE-639 cancels any customer's order (no owner check before mutation)
        order.cancel();
        return orders.save(order);
    }

    @PostAuthorize("returnObject.owner == authentication.name")
    @GetMapping("/{id}/summary")
    public Order summary(@PathVariable Long id) {
        return orders.findById(id).orElseThrow(OrderNotFoundException::new);   // codit-safe: CWE-639 @PostAuthorize enforces ownership of the returned object
    }
}
