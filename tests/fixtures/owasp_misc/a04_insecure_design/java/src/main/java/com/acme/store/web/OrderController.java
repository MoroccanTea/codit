package com.acme.store.web;

import java.math.BigDecimal;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.acme.store.domain.Order;
import com.acme.store.domain.Product;
import com.acme.store.repo.OrderRepository;
import com.acme.store.repo.ProductRepository;
import com.acme.store.security.CurrentUser;

@RestController
@RequestMapping("/api/orders")
public class OrderController {

    private final OrderRepository orders;
    private final ProductRepository products;

    public OrderController(OrderRepository orders, ProductRepository products) {
        this.orders = orders;
        this.products = products;
    }

    @PostMapping("/legacy")
    public ResponseEntity<Order> createLegacy(@AuthenticationPrincipal CurrentUser user, @RequestBody LegacyOrderRequest req) {
        Order order = new Order(user.getId(), req.getProductId(), req.getQuantity());
        // codit-expect: CWE-602 unit price copied from the request body
        order.setUnitPrice(req.getUnitPrice());
        return ResponseEntity.ok(orders.save(order));
    }



    @PostMapping
    public ResponseEntity<Order> create(@AuthenticationPrincipal CurrentUser user, @Valid @RequestBody OrderRequest req) {
        Product product = products.findById(req.getProductId()).orElseThrow();
        Order order = new Order(user.getId(), product.getId(), req.getQuantity());
        // codit-safe: CWE-602 price taken from the catalogue, not from the client
        order.setUnitPrice(product.getPrice());
        return ResponseEntity.ok(orders.save(order));
    }

    public static class LegacyOrderRequest {
        private long productId;
        // codit-expect: CWE-840 quantity has no lower bound (negative quantities accepted)
        private int quantity;
        private BigDecimal unitPrice;

        public long getProductId() { return productId; }
        public void setProductId(long productId) { this.productId = productId; }
        public int getQuantity() { return quantity; }
        public void setQuantity(int quantity) { this.quantity = quantity; }
        public BigDecimal getUnitPrice() { return unitPrice; }
        public void setUnitPrice(BigDecimal unitPrice) { this.unitPrice = unitPrice; }
    }

    public static class OrderRequest {
        @NotNull
        private Long productId;

        // codit-safe: CWE-840 quantity bounded to 1..100
        @Min(1) @Max(100)
        private int quantity;

        public Long getProductId() { return productId; }
        public void setProductId(Long productId) { this.productId = productId; }
        public int getQuantity() { return quantity; }
        public void setQuantity(int quantity) { this.quantity = quantity; }
    }
}
