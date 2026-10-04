package com.acme.shop.web;

import com.acme.shop.domain.Adjustment;
import com.acme.shop.domain.StockLevel;
import com.acme.shop.service.InventoryService;
import com.acme.shop.web.api.InventoryApi;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class InventoryController implements InventoryApi {

    private final InventoryService inventoryService;

    public InventoryController(InventoryService inventoryService) {
        this.inventoryService = inventoryService;
    }

    @Override
    public StockLevel adjust(String sku, Adjustment adjustment) {
        return inventoryService.adjust(sku, adjustment.delta(), adjustment.reason());
    }

    @Override
    public void discontinue(String sku) {
        inventoryService.discontinue(sku);
    }
}
