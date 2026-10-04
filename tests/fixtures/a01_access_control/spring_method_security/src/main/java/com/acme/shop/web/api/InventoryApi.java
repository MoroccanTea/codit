package com.acme.shop.web.api;

import com.acme.shop.domain.Adjustment;
import com.acme.shop.domain.StockLevel;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * Warehouse inventory API. Implemented by InventoryController.
 */
@RequestMapping("/api/inventory")
public interface InventoryApi {

    @PostMapping("/{sku}/adjust")   // codit-expect: CWE-862 stock adjustment: neither the interface nor InventoryController carries a guard
    StockLevel adjust(@PathVariable("sku") String sku, @RequestBody Adjustment adjustment);

    /**
     * Removes the SKU from the catalogue and zeroes all stock.
     */
    @DeleteMapping("/{sku}")   // codit-expect: CWE-862 destructive endpoint, no @PreAuthorize on interface or implementation
    void discontinue(@PathVariable("sku") String sku);
}
