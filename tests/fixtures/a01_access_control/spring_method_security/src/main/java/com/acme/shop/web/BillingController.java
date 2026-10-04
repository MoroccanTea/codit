package com.acme.shop.web;

import com.acme.shop.domain.RefundRequest;
import com.acme.shop.domain.RefundResponse;
import com.acme.shop.service.BillingService;
import com.acme.shop.web.api.BillingApi;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class BillingController implements BillingApi {

    private final BillingService billingService;

    public BillingController(BillingService billingService) {
        this.billingService = billingService;
    }

    @Override
    public RefundResponse issueRefund(RefundRequest request) {   // codit-safe: CWE-862 @PreAuthorize inherited from BillingApi.issueRefund
        return billingService.refund(request.orderId(), request.reason());
    }

    @Override
    public void voidInvoice(String invoiceNo) {   // codit-safe: CWE-862 @PreAuthorize inherited from BillingApi.voidInvoice
        billingService.voidInvoice(invoiceNo);
    }
}
