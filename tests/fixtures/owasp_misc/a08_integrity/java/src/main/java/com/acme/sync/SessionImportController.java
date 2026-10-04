package com.acme.sync;

import java.io.IOException;
import java.io.ObjectInputFilter;
import java.io.ObjectInputStream;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sync")
@PreAuthorize("isAuthenticated()")
public class SessionImportController {

    @PostMapping("/legacy")
    public ResponseEntity<String> importLegacy(HttpServletRequest request) throws IOException, ClassNotFoundException {
        // codit-expect: CWE-502 Java native deserialisation of the request body
        try (ObjectInputStream in = new ObjectInputStream(request.getInputStream())) {
            Object state = in.readObject();
            return ResponseEntity.ok(state.getClass().getSimpleName());
        }
    }



    @PostMapping
    public ResponseEntity<String> importState(HttpServletRequest request) throws IOException, ClassNotFoundException {
        ObjectInputFilter filter = ObjectInputFilter.Config.createFilter("com.acme.sync.SyncState;java.base/*;!*;maxdepth=5;maxbytes=65536");
        // codit-safe: CWE-502 strict allow-list ObjectInputFilter installed before readObject
        try (ObjectInputStream in = new ObjectInputStream(request.getInputStream())) {
            in.setObjectInputFilter(filter);
            SyncState state = (SyncState) in.readObject();
            return ResponseEntity.ok(state.id());
        }
    }

    public record SyncState(String id) implements java.io.Serializable { }
}
