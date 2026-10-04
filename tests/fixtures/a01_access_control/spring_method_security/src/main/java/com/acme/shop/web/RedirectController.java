package com.acme.shop.web;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.IOException;

@Controller
public class RedirectController {

    @GetMapping("/after-login")
    public String afterLogin(@RequestParam("next") String next) {
        return "redirect:" + next;   // codit-expect: CWE-601 redirect target taken verbatim from the request
    }

    @GetMapping("/continue")
    public String continueTo(@RequestParam(value = "next", defaultValue = "/") String next) {
        boolean relative = next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\");
        return "redirect:" + (relative ? next : "/");   // codit-safe: CWE-601 only same-site relative paths are allowed
    }

    @GetMapping("/out")
    public void out(@RequestParam String url, HttpServletResponse response) throws IOException {
        response.sendRedirect(url);   // codit-expect: CWE-601 sendRedirect to an arbitrary user-supplied URL
    }
}
