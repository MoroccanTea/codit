package com.acme.shop.web;

import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/files")
@PreAuthorize("isAuthenticated()")
public class FileController {

    private static final Path STORAGE_ROOT = Paths.get("/srv/acme/uploads").toAbsolutePath().normalize();

    @GetMapping("/download")
    public ResponseEntity<Resource> download(@RequestParam String path) {
        Resource file = new FileSystemResource(Paths.get("/srv/acme/uploads", path));   // codit-expect: CWE-22 request param joined into a filesystem path, ../ escapes the upload root
        return ResponseEntity.ok(file);
    }

    @GetMapping("/raw")
    public byte[] raw(@RequestParam("name") String name) throws IOException {
        return Files.readAllBytes(STORAGE_ROOT.resolve(name));   // codit-expect: CWE-22 resolve() without normalize()+startsWith() confinement
    }

    @GetMapping("/attachment")
    public ResponseEntity<Resource> attachment(@RequestParam String path) {
        Path target = STORAGE_ROOT.resolve(path).normalize();   // codit-safe: CWE-22 normalized then confined with startsWith(STORAGE_ROOT)
        if (!target.startsWith(STORAGE_ROOT)) throw new ResponseStatusException(HttpStatus.BAD_REQUEST);
        return ResponseEntity.ok(new FileSystemResource(target));
    }
}
