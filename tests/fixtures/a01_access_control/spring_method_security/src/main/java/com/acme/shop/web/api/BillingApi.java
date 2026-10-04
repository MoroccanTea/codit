package com.acme.shop.web.api;

import com.acme.shop.domain.RefundRequest;
import com.acme.shop.domain.RefundResponse;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Contract-first billing API (generated from billing.yaml, then hand-edited).
 * Security annotations live on the interface and are inherited by the implementation.
 */
@RequestMapping("/api/billing")
public interface BillingApi {

    @PreAuthorize("hasRole('BILLING')")
    @PostMapping("/refunds")   // codit-safe: CWE-862 guard declared on the interface method, inherited by BillingController
    RefundResponse issueRefund(@RequestBody RefundRequest request);

    /**
     * Voids an issued invoice. Irreversible.
     */
    @PreAuthorize("hasRole('BILLING')")
    @DeleteMapping("/invoices/{invoiceNo}")   // codit-safe: CWE-862 guard declared on the interface method
    void voidInvoice(@PathVariable("invoiceNo") String invoiceNo);
}
