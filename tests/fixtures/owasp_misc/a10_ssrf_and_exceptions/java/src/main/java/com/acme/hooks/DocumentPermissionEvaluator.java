package com.acme.hooks;

import java.io.Serializable;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class DocumentPermissionEvaluator implements PermissionEvaluator {

    private static final Logger log = LoggerFactory.getLogger(DocumentPermissionEvaluator.class);
    private final AclClient acl;

    public DocumentPermissionEvaluator(AclClient acl) {
        this.acl = acl;
    }

    @Override
    public boolean hasPermission(Authentication auth, Object target, Object permission) {
        try {
            return acl.isAllowed(auth.getName(), target, String.valueOf(permission));
        } catch (Exception e) {
            log.warn("ACL service unavailable, allowing request", e);
            // codit-expect: CWE-755 authorization fails open when the ACL service errors
            return true;
        }
    }



    @Override
    public boolean hasPermission(Authentication auth, Serializable targetId, String targetType, Object permission) {
        try {
            return acl.isAllowedById(auth.getName(), targetId, targetType, String.valueOf(permission));
        } catch (Exception e) {
            log.error("ACL check failed for {}:{}", targetType, targetId, e);
            // codit-safe: CWE-755 fail closed on errors
            return false;
        }
    }

    public interface AclClient {
        boolean isAllowed(String user, Object target, String permission);
        boolean isAllowedById(String user, Serializable id, String type, String permission);
    }
}
