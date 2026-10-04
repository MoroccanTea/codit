package com.acme.shop.web;

import java.io.IOException;
import java.net.InetAddress;
import java.util.Hashtable;
import java.util.regex.Pattern;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/admin/diagnostics")
@PreAuthorize("hasRole('ADMIN')")
public class DiagnosticsController {

    private static final Pattern HOSTNAME = Pattern.compile("^[a-zA-Z0-9.-]{1,253}$");
    private final ExpressionParser parser = new SpelExpressionParser();

    @GetMapping("/ping")
    public ResponseEntity<String> ping(@RequestParam String host) throws IOException {
        // codit-expect: CWE-78 host parameter interpolated into a shell command line
        Process p = new ProcessBuilder("sh", "-c", "ping -c 1 " + host).start();
        return ResponseEntity.ok(new String(p.getInputStream().readAllBytes()));
    }



    @GetMapping("/ping-safe")
    public ResponseEntity<String> pingSafe(@RequestParam String host) throws IOException {
        if (!HOSTNAME.matcher(host).matches()) {
            return ResponseEntity.badRequest().build();
        }
        String ip = InetAddress.getByName(host).getHostAddress();
        // codit-safe: CWE-78 argv form (no shell) with a validated, resolved address
        Process p = new ProcessBuilder("ping", "-c", "1", ip).start();
        return ResponseEntity.ok(new String(p.getInputStream().readAllBytes()));
    }

    @GetMapping("/eval")
    public Object eval(@RequestParam String expr) {
        // codit-expect: CWE-917 SpEL expression parsed from a request parameter
        Expression expression = parser.parseExpression(expr);
        return expression.getValue();
    }



    @GetMapping("/discount")
    public Object discount(@RequestParam double amount) {
        SimpleEvaluationContext ctx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
        ctx.setVariable("amount", amount);
        // codit-safe: CWE-917 constant expression; request data only supplied as a variable
        return parser.parseExpression("#amount * 0.9").getValue(ctx);
    }

    @GetMapping("/directory")
    public int directoryLookup(@RequestParam String username) throws NamingException {
        DirContext ctx = ldap();
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        // codit-expect: CWE-90 LDAP filter concatenated with the username parameter
        NamingEnumeration<SearchResult> results = ctx.search("ou=people,dc=acme,dc=example", "(uid=" + username + ")", controls);
        int n = 0;
        while (results.hasMore()) { results.next(); n++; }
        return n;
    }



    @GetMapping("/directory-safe")
    public int directoryLookupSafe(@RequestParam String username) throws NamingException {
        DirContext ctx = ldap();
        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        // codit-safe: CWE-90 filter argument {0} is escaped by JNDI
        NamingEnumeration<SearchResult> results = ctx.search("ou=people,dc=acme,dc=example", "(uid={0})", new Object[] { username }, controls);
        int n = 0;
        while (results.hasMore()) { results.next(); n++; }
        return n;
    }

    private DirContext ldap() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldaps://ldap.acme.example:636");
        return new InitialDirContext(env);
    }
}
