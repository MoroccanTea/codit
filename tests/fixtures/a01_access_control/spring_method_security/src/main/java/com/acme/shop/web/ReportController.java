package com.acme.shop.web;

import com.acme.shop.domain.RevenueReport;
import com.acme.shop.service.ReportService;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.YearMonth;

/**
 * Finance reporting. The class-level guard applies to every handler below.
 */
@RestController
@RequestMapping("/api/reports")
@PreAuthorize("hasRole('AUDITOR')")
public class ReportController {

    private final ReportService reportService;

    public ReportController(ReportService reportService) {
        this.reportService = reportService;
    }

    @GetMapping("/revenue")   // codit-safe: CWE-862 covered by class-level @PreAuthorize hasRole AUDITOR
    public RevenueReport revenue(@RequestParam YearMonth month) {
        return reportService.revenueFor(month);
    }

    @PostMapping("/regenerate")   // codit-safe: CWE-862 covered by class-level @PreAuthorize
    public ResponseEntity<Void> regenerate(@RequestParam YearMonth month) {
        reportService.scheduleRegeneration(month);
        return ResponseEntity.accepted().build();
    }

    @DeleteMapping("/{reportId}")   // codit-safe: CWE-862 covered by class-level @PreAuthorize
    public ResponseEntity<Void> purge(@PathVariable String reportId) {
        reportService.purge(reportId);
        return ResponseEntity.noContent().build();
    }
}
