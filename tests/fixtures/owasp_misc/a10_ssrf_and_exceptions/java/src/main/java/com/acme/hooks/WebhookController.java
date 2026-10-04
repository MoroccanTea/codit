package com.acme.hooks;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.Set;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequestMapping("/api/integrations")
@PreAuthorize("isAuthenticated()")
public class WebhookController {

    private static final Set<String> ALLOWED_HOSTS = Set.of("hooks.slack.com", "api.pagerduty.com");
    private final RestTemplate restTemplate = new RestTemplate();

    @GetMapping("/preview")
    public ResponseEntity<String> preview(@RequestParam String url) {
        // codit-expect: CWE-918 server fetches an arbitrary user-supplied URL (cloud metadata, internal services)
        String body = restTemplate.getForObject(url, String.class);
        return ResponseEntity.ok(body);
    }



    @GetMapping("/preview-safe")
    public ResponseEntity<String> previewSafe(@RequestParam String url) {
        URI uri = URI.create(url);
        if (!"https".equals(uri.getScheme()) || !ALLOWED_HOSTS.contains(uri.getHost())) {
            return ResponseEntity.badRequest().body("host not allowed");
        }
        // codit-safe: CWE-918 scheme and host checked against a fixed allow-list first
        String body = restTemplate.getForObject(uri, String.class);
        return ResponseEntity.ok(body);
    }

    @PostMapping("/test-webhook")
    public ResponseEntity<Integer> testWebhook(@RequestBody WebhookTest req) throws IOException {
        // codit-expect: CWE-918 webhook URL from the request body opened directly
        HttpURLConnection conn = (HttpURLConnection) new URL(req.webhookUrl()).openConnection();
        conn.setRequestMethod("POST");
        try (InputStream ignored = conn.getInputStream()) {
            return ResponseEntity.ok(conn.getResponseCode());
        }
    }

    public record WebhookTest(String webhookUrl) { }
}
