#!/usr/bin/env python3

import argparse
import csv
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import textwrap
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import codit_estimate as AS
    from codit_estimate import C, c, setup_colors, fmt
except ImportError:
    sys.exit('error: codit_estimate.py must be in the same folder as codit.py')

VERSION = '1.0'

# =========================================================================== #
# Severity model
# =========================================================================== #
SEVERITIES = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
SEV_RANK = {s: len(SEVERITIES) - i for i, s in enumerate(SEVERITIES)}   # CRITICAL=5 .. INFO=1
SEV_WEIGHT = {'CRITICAL': 10, 'HIGH': 5, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
CONF_RANK = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
SEV_STYLE = {'CRITICAL': (C.BOLD, C.MAGENTA), 'HIGH': (C.BOLD, C.BRED), 'MEDIUM': (C.BYELLOW,),
             'LOW': (C.BCYAN,), 'INFO': (C.GREY,)}
SEV_ALIASES = {'CRITICAL': 'CRITICAL', 'BLOCKER': 'CRITICAL', 'ERROR': 'HIGH', 'HIGH': 'HIGH',
               'MAJOR': 'HIGH', 'WARNING': 'MEDIUM', 'WARN': 'MEDIUM', 'MEDIUM': 'MEDIUM',
               'MODERATE': 'MEDIUM', 'LOW': 'LOW', 'MINOR': 'LOW', 'NOTE': 'LOW', 'STYLE': 'LOW',
               'INFO': 'INFO', 'INFORMATIONAL': 'INFO', 'INFORMATION': 'INFO', 'NONE': 'INFO'}


def norm_sev(s, default='MEDIUM'):
    return SEV_ALIASES.get(str(s or '').strip().upper(), default)


def norm_conf(s, default='MEDIUM'):
    s = str(s or '').strip().upper()
    return {'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM', 'LOW': 'LOW', 'WEAK': 'LOW',
            'CERTAIN': 'HIGH', 'FIRM': 'MEDIUM', 'TENTATIVE': 'LOW'}.get(s, default)


def sev_up(sev, n=1):
    i = SEVERITIES.index(sev)
    return SEVERITIES[max(0, i - n)]


# =========================================================================== #
# Knowledge base: CWE -> name, OWASP category, default severity, explanation, fix
# =========================================================================== #
def _kb(name, owasp, sev, explain, fix, ref):
    return dict(name=name, owasp=owasp, sev=sev, explain=explain, fix=fix, ref=ref)


OWASP_CS = 'https://cheatsheetseries.owasp.org/cheatsheets/'
KB = {
    89: _kb('SQL Injection', 'A03:2021 Injection', 'HIGH',
            'User-controlled data is concatenated or interpolated into an SQL statement, so an '
            'attacker can change the query structure to read or modify arbitrary data, bypass '
            'authentication or, depending on the DBMS, execute commands on the server.',
            'Use parameterized queries / prepared statements (PreparedStatement, PDO with bound '
            'parameters, SqlParameter, ORM query builders) for every value. Never build SQL with '
            'string concatenation, format() or interpolation. For identifiers (table/column names, '
            'ORDER BY direction) use a strict allow-list. Run the database account with least privilege.',
            OWASP_CS + 'SQL_Injection_Prevention_Cheat_Sheet.html'),
    943: _kb('NoSQL Injection', 'A03:2021 Injection', 'HIGH',
             'Request data (often a JSON object) is passed directly into a NoSQL query. Operators '
             'such as $ne, $gt, $regex or $where let an attacker change the query logic, bypass '
             'login or run server-side JavaScript.',
             'Cast / validate every field to the expected primitive type, reject objects and keys '
             'starting with "$", use a schema validator (Joi, zod, strict mongoose schemas, '
             'express-mongo-sanitize) and never use $where / mapReduce with input.',
             OWASP_CS + 'Injection_Prevention_Cheat_Sheet.html'),
    78: _kb('OS Command Injection', 'A03:2021 Injection', 'HIGH',
            'A system command is built from data that may be attacker-controlled. Shell '
            'metacharacters (; | & $() ` newline) or extra arguments let an attacker execute '
            'arbitrary commands on the server with the privileges of the application.',
            'Avoid shelling out: use a native library API instead. If a process must be started, '
            'pass the program and its arguments as a list without a shell (shell=False, execFile, '
            'ProcessBuilder with separate arguments), validate every argument against a strict '
            'allow-list and use "--" to stop option parsing. Never pass user input to system(), '
            'exec(), popen() or backticks.',
            OWASP_CS + 'OS_Command_Injection_Defense_Cheat_Sheet.html'),
    79: _kb('Cross-Site Scripting (XSS)', 'A03:2021 Injection', 'MEDIUM',
            'Data is written into an HTML / JavaScript context without context-appropriate output '
            'encoding, or encoding is explicitly disabled. An attacker can inject script that runs '
            'in the victims\' browsers to steal sessions, perform actions on their behalf or deface pages.',
            'Keep the template engine\'s auto-escaping on and avoid raw-output helpers (innerHTML, '
            'v-html, dangerouslySetInnerHTML, |safe, {!! !!}, Html.Raw, html_safe, <%- %>). Encode for '
            'the exact context (HTML body, attribute, JavaScript, URL). Prefer textContent over '
            'innerHTML; if HTML must be rendered, sanitize it with a vetted library (DOMPurify, '
            'HtmlSanitizer, bleach). Add a strict Content-Security-Policy as defence in depth.',
            OWASP_CS + 'Cross_Site_Scripting_Prevention_Cheat_Sheet.html'),
    94: _kb('Code Injection', 'A03:2021 Injection', 'HIGH',
            'Dynamic code evaluation (eval, exec, new Function, assert, create_function, vm, '
            'instance_eval...) processes a string that may contain attacker-controlled data, leading '
            'to arbitrary code execution inside the application process.',
            'Remove dynamic evaluation. Replace it with explicit logic, lookup tables or safe parsers '
            '(JSON.parse / json.loads, ast.literal_eval for literals). If it cannot be avoided, never '
            'let user input reach the evaluated string and restrict the available symbols.',
            'https://owasp.org/www-community/attacks/Code_Injection'),
    1336: _kb('Server-Side Template Injection (SSTI)', 'A03:2021 Injection', 'HIGH',
              'A template is compiled from a string that may contain user input. Template languages '
              '(Jinja2, Twig, Freemarker, Velocity, EJS, Pug...) can usually reach the runtime, so '
              'injection typically ends in remote code execution.',
              'Never build templates from user input; pass user data only as variables to a static '
              'template. If users must author templates, use a logic-less engine or a hardened sandbox '
              '(e.g. Jinja2 SandboxedEnvironment) and restrict the exposed objects.',
              'https://portswigger.net/web-security/server-side-template-injection'),
    917: _kb('Expression Language Injection', 'A03:2021 Injection', 'HIGH',
             'An expression language (SpEL, OGNL, MVEL, Jakarta EL) evaluates a string that may '
             'contain user input; these languages can call arbitrary methods, leading to remote '
             'code execution.',
             'Do not evaluate expressions built from input. Use SimpleEvaluationContext (SpEL) or an '
             'equivalent restricted context and pass input only as variables.',
             'https://owasp.org/www-community/vulnerabilities/Expression_Language_Injection'),
    90: _kb('LDAP Injection', 'A03:2021 Injection', 'HIGH',
            'An LDAP filter or DN is built by concatenating input; characters such as * ( ) \\ & | '
            'let an attacker alter the filter to bypass authentication or enumerate the directory.',
            'Escape input with the LDAP filter / DN encoder of your framework (Encoder.encodeForLDAP, '
            'ldap_escape(), LdapFilterEncode) or use parameterized filter APIs; validate input '
            'against an allow-list.',
            OWASP_CS + 'LDAP_Injection_Prevention_Cheat_Sheet.html'),
    643: _kb('XPath Injection', 'A03:2021 Injection', 'MEDIUM',
             'An XPath expression is built from input, so the query can be altered to bypass '
             'authentication or read arbitrary nodes of the XML document.',
             'Use parameterized XPath (XPathVariableResolver, precompiled expressions with variables) '
             'or strictly validate / escape the input.',
             'https://owasp.org/www-community/attacks/XPATH_Injection'),
    22: _kb('Path Traversal', 'A01:2021 Broken Access Control', 'HIGH',
            'A file-system path is derived from user input. Sequences like ../, absolute paths or '
            'encoded variants let an attacker read, overwrite or delete files outside the intended '
            'directory (configuration, credentials, source code).',
            'Do not use user input in paths; map it to server-side identifiers. Otherwise '
            'canonicalize the path (realpath / getCanonicalPath / Path.normalize), verify it stays '
            'inside an allowed base directory, reject separators and "..", and use basename() for '
            'file names.',
            'https://owasp.org/www-community/attacks/Path_Traversal'),
    98: _kb('File Inclusion (LFI / RFI)', 'A03:2021 Injection', 'HIGH',
            'include / require is called with a dynamic path. If input reaches it, an attacker can '
            'include local files (logs, sessions, php:// wrappers) or remote URLs, usually leading to '
            'source disclosure or remote code execution.',
            'Never include files based on user input; use a fixed allow-list mapping (switch or '
            'array of known templates). Set allow_url_include=Off and restrict open_basedir.',
            'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_'
            'Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_File_Inclusion'),
    434: _kb('Unrestricted File Upload', 'A04:2021 Insecure Design', 'MEDIUM',
             'Uploaded files are handled here. Without strict validation an attacker may upload '
             'executable content (web shells), HTML / SVG for stored XSS, oversized files for DoS, or '
             'overwrite files through crafted names.',
             'Validate the extension against an allow-list and verify the content (magic bytes) '
             'server-side; never trust the client MIME type or original file name; generate a random '
             'server-side name; store outside the web root without execute permission; enforce size '
             'limits and scan content where possible.',
             OWASP_CS + 'File_Upload_Cheat_Sheet.html'),
    502: _kb('Insecure Deserialization', 'A08:2021 Software and Data Integrity Failures', 'HIGH',
             'Data is deserialized with a mechanism that can instantiate arbitrary types (pickle, '
             'Java native serialization, BinaryFormatter, PHP unserialize, YAML full loaders, '
             'Marshal...). If the data can be influenced by an attacker, gadget chains lead to remote '
             'code execution, DoS or object injection.',
             'Do not deserialize untrusted data with native serializers. Use data-only formats (JSON) '
             'with explicit schemas, safe loaders (yaml.safe_load, YAML.safe_load, SafeConstructor), '
             'class allow-lists (ObjectInputFilter, allowed_classes => false, SerializationBinder) and '
             'sign serialized data with an HMAC if it has to travel through the client.',
             OWASP_CS + 'Deserialization_Cheat_Sheet.html'),
    611: _kb('XML External Entity (XXE)', 'A05:2021 Security Misconfiguration', 'HIGH',
             'An XML parser may resolve DTDs / external entities. An attacker who supplies XML can '
             'read local files, perform SSRF against internal services or cause DoS (billion laughs).',
             'Disable DOCTYPE declarations and external entity resolution on every parser '
             '(disallow-doctype-decl=true, XMLConstants.ACCESS_EXTERNAL_DTD="", DtdProcessing.Prohibit, '
             'resolve_entities=False, no LIBXML_NOENT). In Python use defusedxml.',
             OWASP_CS + 'XML_External_Entity_Prevention_Cheat_Sheet.html'),
    918: _kb('Server-Side Request Forgery (SSRF)', 'A10:2021 SSRF', 'HIGH',
             'The server issues a request to a URL influenced by the user. An attacker can reach '
             'internal services, cloud metadata endpoints (169.254.169.254) or local files, and '
             'pivot inside the network.',
             'Do not fetch user-supplied URLs. If required, allow-list schemes, hosts and ports, '
             'resolve DNS once and block private / loopback / link-local ranges (re-check after '
             'redirects or disable them) and route outbound traffic through an egress proxy.',
             OWASP_CS + 'Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html'),
    601: _kb('Open Redirect', 'A01:2021 Broken Access Control', 'MEDIUM',
             'The redirect target comes from request data. Attackers can craft links on your '
             'trusted domain that bounce victims to phishing pages or leak OAuth codes / tokens.',
             'Redirect only to relative paths or to an allow-list of destinations; map input to '
             'server-side identifiers; reject scheme-relative (//evil) and absolute URLs.',
             OWASP_CS + 'Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html'),
    352: _kb('Cross-Site Request Forgery (CSRF)', 'A01:2021 Broken Access Control', 'MEDIUM',
             'CSRF protection is disabled or bypassed here. A malicious site can make authenticated '
             'users\' browsers perform state-changing actions.',
             'Keep the framework CSRF protection enabled for every cookie-authenticated '
             'state-changing request. If an exception is really needed (pure token API), make sure no '
             'cookie-based authentication is accepted and use SameSite=Lax/Strict cookies.',
             OWASP_CS + 'Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html'),
    327: _kb('Broken or Risky Cryptographic Algorithm', 'A02:2021 Cryptographic Failures', 'HIGH',
             'A weak or obsolete cipher or mode is used (DES/3DES, RC2/RC4, Blowfish, ECB mode, '
             'Cipher.getInstance("AES") which defaults to ECB, key derivation without IV). Encrypted '
             'data may be decrypted or tampered with, and ECB leaks plaintext patterns.',
             'Use authenticated encryption: AES-256-GCM or ChaCha20-Poly1305 with a unique random '
             'nonce per message, through a high-level library (libsodium, Tink, cryptography '
             'AESGCM / Fernet). Never use ECB; keep keys in a KMS or vault.',
             OWASP_CS + 'Cryptographic_Storage_Cheat_Sheet.html'),
    328: _kb('Weak Hash Function', 'A02:2021 Cryptographic Failures', 'MEDIUM',
             'MD5 / SHA-1 (or similar) is used. They are broken for collision resistance and far too '
             'fast for password storage; used for passwords, signatures, integrity checks or tokens, '
             'they can be forged or brute-forced.',
             'Passwords: Argon2id, scrypt, bcrypt or PBKDF2 with a high work factor (password_hash(), '
             'BCryptPasswordEncoder, passlib). Integrity / signatures: SHA-256+ or HMAC-SHA-256. '
             'MD5 / SHA-1 are acceptable only for non-security checksums; document that usage.',
             OWASP_CS + 'Password_Storage_Cheat_Sheet.html'),
    338: _kb('Insecure Randomness', 'A02:2021 Cryptographic Failures', 'LOW',
             'A non-cryptographic PRNG (Math.random, java.util.Random, rand / mt_rand, Python random, '
             'math/rand, System.Random) is used. If the value is a token, password, session ID, OTP, '
             'nonce or key, it can be predicted.',
             'Use a CSPRNG for any security-relevant value: crypto.randomBytes / getRandomValues, '
             'SecureRandom, random_bytes / random_int, the secrets module, crypto/rand, '
             'RandomNumberGenerator. Ignore if the value is purely cosmetic.',
             OWASP_CS + 'Cryptographic_Storage_Cheat_Sheet.html#secure-random-number-generation'),
    798: _kb('Hard-coded Credentials / Secret', 'A07:2021 Identification and Authentication Failures',
             'HIGH',
             'A password, API key, token or private key appears to be embedded in the source code. '
             'Anyone with access to the code, repository history, build artefacts or decompiled '
             'binaries can reuse it.',
             'Remove the secret from the code and from the repository history, rotate / revoke it '
             'immediately and load secrets at runtime from a vault or the environment (HashiCorp '
             'Vault, AWS / Azure / GCP secret managers, Kubernetes secrets). Add secret scanning '
             '(gitleaks / trufflehog) to CI and pre-commit hooks.',
             OWASP_CS + 'Secrets_Management_Cheat_Sheet.html'),
    295: _kb('Improper Certificate Validation', 'A02:2021 Cryptographic Failures', 'HIGH',
             'TLS certificate or hostname verification is disabled (verify=False, '
             'rejectUnauthorized:false, InsecureSkipVerify, trust-all TrustManager, curl -k...). '
             'Traffic can be intercepted and modified by a man-in-the-middle.',
             'Always validate certificates and host names. For internal or self-signed services, '
             'trust the specific CA or pin the certificate instead of disabling validation, and make '
             'sure test-only overrides cannot reach production.',
             OWASP_CS + 'Transport_Layer_Security_Cheat_Sheet.html'),
    319: _kb('Cleartext Transmission', 'A02:2021 Cryptographic Failures', 'LOW',
             'A plain http:// endpoint is used; data and credentials sent to it can be sniffed or '
             'modified in transit.',
             'Use HTTPS for all endpoints, enable HSTS and make URLs configurable per environment.',
             OWASP_CS + 'Transport_Layer_Security_Cheat_Sheet.html'),
    347: _kb('Improper Token / Signature Verification', 'A02:2021 Cryptographic Failures', 'HIGH',
             'A token or signature is decoded without being verified, accepts the "none" algorithm, '
             'or skips expiry / issuer / key checks. Attackers can forge tokens and impersonate users.',
             'Always verify the signature with the expected key and an explicit allow-list of '
             'algorithms (e.g. jwt.verify(token, key, {algorithms: ["RS256"]})), validate exp, nbf, '
             'iss and aud, never accept "none", and never use decode() for authentication decisions.',
             OWASP_CS + 'JSON_Web_Token_for_Java_Cheat_Sheet.html'),
    287: _kb('Improper Authentication', 'A07:2021 Identification and Authentication Failures', 'HIGH',
             'Authentication logic may be missing, weak or bypassable at this location.',
             'Enforce authentication centrally (framework middleware / filters), use vetted libraries '
             'and add tests proving every protected route rejects unauthenticated requests.',
             OWASP_CS + 'Authentication_Cheat_Sheet.html'),
    862: _kb('Anonymous / Unrestricted Access (review area)', 'A01:2021 Broken Access Control', 'INFO',
             'This code explicitly allows anonymous or unrestricted access. It is not a vulnerability '
             'by itself but a high-value review area: confirm that everything reachable here is meant '
             'to be public.',
             'Review the routes covered here; apply deny-by-default and object-level authorization '
             '(ownership / tenant checks) on every handler that returns or modifies data.',
             OWASP_CS + 'Authorization_Cheat_Sheet.html'),
    915: _kb('Mass Assignment', 'A08:2021 Software and Data Integrity Failures', 'MEDIUM',
             'An object or model is created / updated directly from the whole request body. Attackers '
             'can set fields they should not control (role, is_admin, price, owner_id).',
             'Bind only an explicit allow-list of fields (DTOs, strong parameters permit(:a, :b), '
             '$fillable, serializer fields); never use permit!, $guarded = [] or $request->all() '
             'for persistence.',
             OWASP_CS + 'Mass_Assignment_Cheat_Sheet.html'),
    621: _kb('Variable Extraction / Overwrite', 'A03:2021 Injection', 'MEDIUM',
             'extract() or parse_str() without a result array creates or overwrites variables from '
             'request data, which can override security-relevant variables (auth flags, paths, SQL).',
             'Do not call extract() on user data; use parse_str($str, $result) and read only the '
             'expected keys.',
             'https://cwe.mitre.org/data/definitions/621.html'),
    1321: _kb('Prototype Pollution', 'A08:2021 Software and Data Integrity Failures', 'MEDIUM',
              'Request data is deep-merged or assigned by key into an object. Keys such as __proto__ '
              'or constructor.prototype modify Object.prototype, leading to logic bypass, DoS or RCE '
              'through gadgets.',
              'Validate input against a schema, reject __proto__ / constructor / prototype keys, use '
              'Object.create(null) or Map for dictionaries and keep merge libraries patched.',
              OWASP_CS + 'Prototype_Pollution_Prevention_Cheat_Sheet.html'),
    470: _kb('Unsafe Reflection / Dynamic Invocation', 'A03:2021 Injection', 'HIGH',
             'A class, method or function name is taken from user input (Class.forName, '
             'call_user_func, $$var, send / constantize...). Attackers can invoke unintended code '
             'paths, sometimes up to code execution.',
             'Map input to an allow-list of permitted classes / methods; never pass raw input to '
             'reflection or dynamic call APIs.',
             'https://cwe.mitre.org/data/definitions/470.html'),
    1333: _kb('Regular Expression DoS (ReDoS)', 'A04:2021 Insecure Design', 'MEDIUM',
              'A regular expression is built from user input (or is prone to catastrophic '
              'backtracking), so one request can consume CPU for seconds or minutes.',
              'Never compile regexes from user input (escape with re.escape / Pattern.quote / '
              'preg_quote if needed), avoid nested quantifiers, limit input length and use a '
              'linear-time engine (RE2) or regex timeouts.',
              'https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS'),
    400: _kb('Uncontrolled Resource Consumption', 'A04:2021 Insecure Design', 'MEDIUM',
             'Resource usage (memory, CPU, handles, recursion) can grow without bounds based on input.',
             'Apply limits on input size, recursion depth and allocation size, plus timeouts and '
             'rate limiting.',
             'https://cwe.mitre.org/data/definitions/400.html'),
    942: _kb('Overly Permissive CORS Policy', 'A05:2021 Security Misconfiguration', 'MEDIUM',
             'The CORS policy allows any origin (or reflects the Origin header). Combined with '
             'credentials this lets any website read authenticated API responses.',
             'Allow-list the exact trusted origins; never reflect Origin blindly and never combine '
             'wildcard / reflected origins with Access-Control-Allow-Credentials: true.',
             'https://portswigger.net/web-security/cors'),
    346: _kb('Origin Validation Error', 'A07:2021 Identification and Authentication Failures', 'LOW',
             'Cross-window messages (postMessage) are sent to or accepted from any origin without '
             'verification, leaking data to, or accepting commands from, malicious pages.',
             'Give the exact target origin to postMessage and always check event.origin against an '
             'allow-list in message handlers.',
             'https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns'),
    614: _kb('Insecure Cookie Attributes', 'A05:2021 Security Misconfiguration', 'LOW',
             'A cookie is configured without Secure and / or HttpOnly, or with SameSite=None. Session '
             'cookies may travel over HTTP or be stolen through XSS.',
             'Set Secure, HttpOnly and SameSite=Lax/Strict on session and authentication cookies, '
             'configured globally in the framework.',
             OWASP_CS + 'Session_Management_Cheat_Sheet.html#cookies'),
    489: _kb('Debug Features / Verbose Errors Enabled', 'A05:2021 Security Misconfiguration', 'LOW',
             'Debug mode, verbose error output or diagnostic functions are enabled. In production this '
             'discloses stack traces and configuration, and sometimes interactive consoles '
             '(the Werkzeug debugger is remote code execution).',
             'Disable debug mode and detailed error pages in production through environment '
             'configuration, log errors server-side, return generic messages and remove '
             'phpinfo() / var_dump() calls.',
             'https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_'
             'Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling'),
    200: _kb('Information Exposure', 'A01:2021 Broken Access Control', 'LOW',
             'Sensitive information (internal details, stack traces, configuration, personal data) '
             'may be exposed to users.',
             'Return only the data the client needs and strip internal details from responses and '
             'error messages.',
             'https://cwe.mitre.org/data/definitions/200.html'),
    532: _kb('Sensitive Data in Logs', 'A09:2021 Security Logging and Monitoring Failures', 'LOW',
             'Sensitive values (passwords, tokens, keys, card data) appear to be written to logs or '
             'console output, exposing them to operators, log pipelines and anyone who reaches the logs.',
             'Never log secrets or personal data; mask sensitive fields in the logging layer and '
             'review log retention and access.',
             OWASP_CS + 'Logging_Cheat_Sheet.html'),
    117: _kb('Log Injection', 'A09:2021 Security Logging and Monitoring Failures', 'LOW',
             'User input is written to logs without neutralising CR/LF, allowing forged log entries or '
             'payloads against log viewers.',
             'Strip or encode newline / control characters before logging and use structured logging.',
             'https://owasp.org/www-community/attacks/Log_Injection'),
    113: _kb('HTTP Header Injection / Response Splitting', 'A03:2021 Injection', 'MEDIUM',
             'A response header is set from request data. CR/LF characters may allow header '
             'injection, response splitting, cache poisoning or session fixation.',
             'Validate header values against an allow-list and reject CR/LF; rely on framework '
             'APIs that encode header values.',
             'https://owasp.org/www-community/attacks/HTTP_Response_Splitting'),
    93: _kb('CRLF / E-mail Header Injection', 'A03:2021 Injection', 'MEDIUM',
            'CR/LF characters in user input reach a protocol header (e-mail, HTTP), allowing extra '
            'headers or recipients to be injected (spam relay, header forgery).',
            'Reject CR and LF in every value used in headers (To, Subject, From...), use a mail '
            'library that validates headers and validate addresses strictly.',
            'https://owasp.org/www-community/vulnerabilities/CRLF_Injection'),
    384: _kb('Session Fixation', 'A07:2021 Identification and Authentication Failures', 'HIGH',
             'The session identifier can be set from request data, so an attacker can fix a known '
             'session ID and hijack the victim\'s session after login.',
             'Never accept session IDs from parameters; regenerate the session ID on login and on '
             'privilege change (session_regenerate_id(true), changeSessionId()).',
             'https://owasp.org/www-community/attacks/Session_fixation'),
    613: _kb('Insufficient Token Expiration', 'A07:2021 Identification and Authentication Failures',
             'MEDIUM',
             'Token expiry validation is disabled, so stolen tokens stay valid indefinitely.',
             'Enforce exp validation with short lifetimes and implement revocation / rotation of '
             'refresh tokens.',
             OWASP_CS + 'Session_Management_Cheat_Sheet.html'),
    697: _kb('Loose Comparison / Type Juggling', 'A07:2021 Identification and Authentication Failures',
             'MEDIUM',
             'A security check uses a loose comparison (== or strcmp on user input). PHP type '
             'juggling ("0e..." magic hashes, arrays passed to strcmp returning NULL) can make the '
             'check pass with crafted input.',
             'Use strict comparison (=== / !==) and hash_equals() for secrets and hashes; check input '
             'types (is_string) before comparing.',
             'https://owasp.org/www-pdf-archive/PHPMagicTricks-TypeJuggling.pdf'),
    922: _kb('Sensitive Data in Browser Storage', 'A04:2021 Insecure Design', 'LOW',
             'Tokens or secrets are stored in localStorage / sessionStorage, readable by any script '
             'on the origin; a single XSS is enough to steal them.',
             'Keep session tokens in HttpOnly, Secure, SameSite cookies; otherwise keep tokens '
             'short-lived and harden the app against XSS with a CSP.',
             OWASP_CS + 'HTML5_Security_Cheat_Sheet.html#local-storage'),
    312: _kb('Cleartext Storage of Sensitive Information', 'A02:2021 Cryptographic Failures', 'MEDIUM',
             'Sensitive information is stored without encryption.',
             'Encrypt sensitive data at rest with keys managed outside the application and store only '
             'what is necessary.',
             OWASP_CS + 'Cryptographic_Storage_Cheat_Sheet.html'),
    749: _kb('Exposed Dangerous Method (WebView)', 'OWASP MASVS-PLATFORM', 'MEDIUM',
             'A WebView enables JavaScript, file access or a JavaScript bridge. Content loaded into it '
             '(especially remote or attacker-influenced URLs) can call exposed native methods or read '
             'local files.',
             'Disable JavaScript and file access unless required, never expose addJavascriptInterface '
             'to untrusted content, load only allow-listed HTTPS origins and disable universal file '
             'access.',
             'https://mas.owasp.org/MASVS/controls/MASVS-PLATFORM-2/'),
    732: _kb('Incorrect Permission Assignment', 'A01:2021 Broken Access Control', 'MEDIUM',
             'Files, directories or resources are created with overly broad permissions '
             '(world-readable / writable, 777, umask 0), so other local users or processes can read or '
             'tamper with them.',
             'Use least-privilege permissions (0600 / 0640 for files, 0700 / 0750 for directories) and '
             'a restrictive umask.',
             'https://cwe.mitre.org/data/definitions/732.html'),
    377: _kb('Insecure Temporary File', 'A01:2021 Broken Access Control', 'LOW',
             'A temporary file name is generated in a predictable / racy way (mktemp, tmpnam); an '
             'attacker can pre-create or symlink it to read or overwrite data.',
             'Use APIs that atomically create the file with safe permissions: tempfile.mkstemp / '
             'NamedTemporaryFile, mkstemp(), Files.createTempFile.',
             'https://cwe.mitre.org/data/definitions/377.html'),
    120: _kb('Buffer Overflow', 'Memory safety', 'HIGH',
             'A copy / format function without bounds checking is used (gets, strcpy, strcat, '
             'sprintf, scanf("%s")...). Overlong input can overwrite adjacent memory, leading to '
             'crashes or code execution.',
             'Use bounded alternatives (fgets, strlcpy / strlcat, snprintf, std::string), validate '
             'lengths before copying and compile with stack protection, _FORTIFY_SOURCE and ASLR.',
             'https://cwe.mitre.org/data/definitions/120.html'),
    134: _kb('Format String Vulnerability', 'Memory safety', 'HIGH',
             'A non-constant string is used as the format argument of a printf-family function. '
             'Format specifiers (%x, %n) in attacker data can leak or write memory.',
             'Always use a constant format string: printf("%s", data) instead of printf(data); '
             'compile with -Wformat-security.',
             'https://owasp.org/www-community/attacks/Format_string_attack'),
    190: _kb('Integer Overflow', 'Memory safety', 'MEDIUM',
             'Arithmetic on sizes or indexes may overflow / wrap, leading to undersized allocations '
             'and out-of-bounds access.',
             'Check ranges before arithmetic and use overflow-checking builtins '
             '(__builtin_mul_overflow, SafeInt).',
             'https://cwe.mitre.org/data/definitions/190.html'),
    476: _kb('NULL Pointer Dereference', 'Memory safety', 'MEDIUM',
             'A pointer may be NULL when dereferenced, causing a crash (DoS).',
             'Check return values and pointer validity before use.',
             'https://cwe.mitre.org/data/definitions/476.html'),
    416: _kb('Use After Free / Double Free', 'Memory safety', 'HIGH',
             'Memory is used or released after being freed, corrupting the heap; often exploitable '
             'for code execution.',
             'Clarify ownership (RAII, smart pointers), set pointers to NULL after free and run '
             'AddressSanitizer / fuzzing.',
             'https://cwe.mitre.org/data/definitions/416.html'),
    362: _kb('Race Condition / TOCTOU', 'A04:2021 Insecure Design', 'MEDIUM',
             'A resource is checked and then used in separate steps; an attacker can change it in '
             'between (e.g. symlink swap, double spending).',
             'Use atomic operations, work on file descriptors instead of re-opening paths and hold '
             'locks / transactions across check-and-use.',
             'https://cwe.mitre.org/data/definitions/367.html'),
    401: _kb('Resource / Memory Leak', 'A04:2021 Insecure Design', 'LOW',
             'Memory or handles are not released on some paths, which can lead to exhaustion (DoS).',
             'Release resources on all paths (RAII, try-with-resources, defer, finally).',
             'https://cwe.mitre.org/data/definitions/401.html'),
    754: _kb('Unchecked Error Condition', 'A04:2021 Insecure Design', 'LOW',
             'An operation can fail silently and execution continues in an unexpected state '
             '(e.g. cd without error check followed by rm).',
             'Check return codes ("set -euo pipefail", "cd dir || exit") and handle errors explicitly.',
             'https://cwe.mitre.org/data/definitions/754.html'),
    829: _kb('Inclusion of Untrusted Functionality', 'A08:2021 Software and Data Integrity Failures',
             'MEDIUM',
             'Code or scripts are downloaded and executed without integrity verification '
             '(curl | sh, remote scripts without Subresource Integrity).',
             'Pin versions and verify checksums / signatures before executing; use SRI for '
             'third-party scripts.',
             'https://cwe.mitre.org/data/definitions/829.html'),
    20: _kb('Improper Input Validation', 'A03:2021 Injection', 'MEDIUM',
            'Input is used without adequate validation.',
            'Validate type, length, format and range of all input server-side with allow-lists.',
            OWASP_CS + 'Input_Validation_Cheat_Sheet.html'),
}
GENERIC_KB = _kb('Security Weakness', '', 'MEDIUM',
                 'The tool flagged a potentially dangerous construct at this location.',
                 'Review the flagged code and the rule documentation: validate and encode untrusted '
                 'data, apply least privilege and prefer safe framework APIs.',
                 'https://owasp.org/Top10/')

CWE_ALIAS = {
    77: 78, 88: 78, 80: 79, 83: 79, 87: 79, 116: 79, 95: 94, 96: 94, 1236: 20,
    23: 22, 35: 22, 36: 22, 73: 22, 99: 22, 97: 98, 776: 611, 827: 611,
    330: 338, 331: 338, 335: 338, 336: 338, 259: 798, 321: 798, 547: 798, 522: 798,
    297: 295, 599: 295, 326: 327, 780: 327, 757: 327, 916: 328, 759: 328, 760: 328, 261: 328,
    345: 347, 290: 287, 306: 287, 285: 862, 863: 862, 639: 862, 284: 862,
    1004: 614, 1275: 614, 315: 614, 215: 489, 11: 489, 209: 200, 497: 200, 538: 200, 548: 200,
    770: 400, 674: 400, 1050: 400, 409: 400, 789: 400, 121: 120, 122: 120, 119: 120, 787: 120,
    125: 120, 126: 120, 131: 120, 242: 120, 676: 120, 785: 120, 805: 120, 191: 190, 415: 416,
    367: 362, 772: 401, 775: 401, 252: 754, 703: 754, 253: 754, 494: 829, 353: 829,
    1025: 697, 595: 697, 1024: 697, 564: 89, 566: 89, 652: 643, 91: 643, 185: 1333, 625: 1333,
    311: 312, 276: 732, 1333: 1333, 184: 20, 477: 120,
}

KEYWORD_CWE = [(re.compile(p, re.I), cwe) for p, cwe in [
    (r'curl.?pipe|pipe.?(ba)?sh|remote.?script|integrity', 829),
    (r'tls.?version|ssl.?version|minversion|min.?version|weak.?tls|ssl.?protocol|sslv[23]|tlsv1\b', 327),
    (r'nosql|mongo', 943), (r'sql', 89),
    (r'template.?injection|ssti|render.?template.?string|template.?string', 1336),
    (r'xss|cross.?site.?script|innerhtml|html.?inject|unescaped|autoescape|mark_safe|raw.?html', 79),
    (r'deseriali|pickle|unserialize|marshal|yaml.?load|objectinputstream|binaryformatter', 502),
    (r'xxe|external.?entit|doctype|\bdtd\b', 611),
    (r'ssrf|server.?side.?request', 918),
    (r'redirect', 601), (r'csrf|xsrf|forgery', 352),
    (r'file.?inclusion|\blfi\b|\brfi\b|non.?constant.?include|include.?(user|input|tainted)', 98),
    (r'path.?traversal|directory.?traversal', 22),
    (r'command|shell|subprocess|os\.system|\bexec(ution)?\b|popen|spawn|system.?exec', 78),
    (r'\beval\b|code.?injection|dynamic.?code', 94),
    (r'ldap', 90), (r'xpath', 643),
    (r'\bmd5\b|sha-?1\b|weak.?hash|hash.?algorithm|broken.?hash|insecure.?hash', 328),
    (r'\bdes\b|3des|\brc4\b|\brc2\b|blowfish|\becb\b|weak.?cipher', 327),
    (r'random|prng', 338),
    (r'secret|password|passwd|credential|api.?key|access.?key|token|private.?key|'
     r'hard.?coded.?(password|secret|key|cred|token)', 798),
    (r'certificate|\btls\b|\bssl\b|hostname.?verif', 295),
    (r'jwt|signature', 347), (r'cors|origin', 942),
    (r'cookie|httponly|samesite', 614),
    (r'debug|stack.?trace|phpinfo|display_errors', 489),
    (r'upload', 434), (r'mass.?assign|permit!|fillable|guarded', 915),
    (r'prototype', 1321), (r'regex|redos|regular.?expression', 1333),
    (r'buffer|overflow|strcpy|strcat|\bgets\b|sprintf|memcpy', 120),
    (r'format.?string', 134), (r'\btemp(file|orary|_?dir)?\b|mktemp|tmpnam', 377),
    (r'chmod|permission', 732),
    (r'reflection|forname|call_user_func|constantize', 470),
    (r'\blog(s|ging|ger)?\b', 532), (r'header', 113),
    (r'http://|cleartext|plaintext|insecure.?transport', 319),
]]


def kb_key(cwe):
    if cwe is None:
        return None
    if cwe in KB:
        return cwe
    return CWE_ALIAS.get(cwe)


def guess_cwe(*texts):
    blob = ' '.join(t for t in texts if t)
    for rx, cwe in KEYWORD_CWE:
        if rx.search(blob):
            return cwe
    return None


def parse_cwes(value):
    """All CWE numbers found in strings / lists / dicts of various tool formats."""
    out = []
    if value is None:
        return out
    if isinstance(value, int):
        return [value]
    if isinstance(value, dict):
        return parse_cwes(value.get('id') or value.get('ID') or value.get('cwe'))
    if isinstance(value, (list, tuple)):
        for v in value:
            for x in parse_cwes(v):
                if x not in out:
                    out.append(x)
        return out
    txt = str(value)
    found = [int(x) for x in re.findall(r'CWE[-_ :]?0*(\d+)', txt, re.I)]
    if not found and re.match(r'^\s*0*(\d+)\s*$', txt):
        found = [int(txt)]
    for x in found:
        if x not in out:
            out.append(x)
    return out


# engines whose CWE metadata is precise enough to be trusted as-is
TRUSTED_CWE_TOOLS = {'builtin', 'shellcheck', 'gitleaks', 'trufflehog', 'codeql', 'brakeman', 'gosec',
                     'progpilot', 'cppcheck', 'flawfinder'}


def choose_cwe(f):
    """Pick the CWE that best describes a tool finding.

    Tool metadata is sometimes wrong (e.g. an upstream 'tainted-sql-string' rule tagged CWE-915),
    so a vulnerability class clearly named by the rule id / title wins; otherwise the first
    tool CWE known to the knowledge base is used."""
    cwes = f.get('cwes') or []
    if f['tool'] in TRUSTED_CWE_TOOLS and cwes:
        for x in cwes:
            if kb_key(x):
                return x
        return cwes[0]
    rule_name = f['rule'].rsplit('.', 1)[-1].replace('-', ' ').replace('_', ' ')
    guess = guess_cwe(rule_name, f['title']) or guess_cwe(f['message'])
    if guess:
        fam = kb_key(guess)
        for x in cwes:
            if kb_key(x) == fam:
                return x
        return guess
    for x in cwes:
        if kb_key(x):
            return x
    if cwes:
        return cwes[0]
    return guess_cwe(f['message'])


def parse_cwe(value):
    """Extract the first CWE number from strings / lists / dicts in various tool formats."""
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, dict):
        return parse_cwe(value.get('id') or value.get('ID') or value.get('cwe'))
    if isinstance(value, (list, tuple)):
        for v in value:
            r = parse_cwe(v)
            if r:
                return r
        return None
    m = re.search(r'CWE[-_ :]?0*(\d+)', str(value), re.I) or re.match(r'^\s*0*(\d+)\s*$', str(value))
    return int(m.group(1)) if m else None


# =========================================================================== #
# File / language classification
# =========================================================================== #
EXT_GROUPS = {}
for _grp, _exts in {
    'python': '.py .pyw',
    'js': '.js .mjs .cjs .jsx .ts .tsx .mts .cts .vue .svelte .ejs',
    'php': '.php .phtml .php3 .php4 .php5 .php7 .phps .inc .blade.php',
    'java': '.java .jsp .jspx .jspf .tag .tagx .kt .kts .scala .groovy .gsp',
    'android': '.java .kt',
    'csharp': '.cs .cshtml .razor .vbhtml .aspx .ascx .master .ashx .asmx .vb',
    'go': '.go .gohtml',
    'ruby': '.rb .rake .erb .rhtml .haml .slim',
    'c': '.c .h .cpp .cc .cxx .hpp .hh .m .mm',
    'shell': '.sh .bash .zsh .ksh',
    'sql': '.sql .pls .pks .pkb .plsql .pck',
    'ios': '.swift .m .mm',
}.items():
    for _e in _exts.split():
        EXT_GROUPS.setdefault(_e, set()).add(_grp)


def file_groups(rec):
    ext = rec['ext']
    groups = set(EXT_GROUPS.get(ext, ())) | {ext, 'any'}
    if rec.get('kind'):
        groups |= {'template', 'tpl-' + rec['kind']}
    return groups


# =========================================================================== #
# Built-in rule engine
# =========================================================================== #
class Rule(object):
    __slots__ = ('id', 'title', 'langs', 'rx', 'sev', 'cwe', 'conf', 'raw', 'unless_file',
                 'only_if_file', 'unless_line', 'boost', 'msg', 'validate')

    def __init__(self, id, title, langs, pattern, sev, cwe, conf='MEDIUM', raw=False,
                 unless_file=None, only_if_file=None, unless_line=None, boost=None, msg=None,
                 validate=None, flags=0):
        self.id, self.title, self.sev, self.cwe, self.conf, self.raw = id, title, sev, cwe, conf, raw
        self.langs = set(langs.split())
        self.rx = re.compile(pattern, flags)
        self.unless_file = re.compile(unless_file, re.I) if unless_file else None
        self.only_if_file = re.compile(only_if_file) if only_if_file else None
        self.unless_line = re.compile(unless_line, re.I) if unless_line else None
        # boost = (regex, severity, confidence) applied when the regex matches the same line
        self.boost = (re.compile(boost[0], re.I), boost[1], boost[2]) if boost else None
        self.msg, self.validate = msg, validate


USER_INPUT = (r'(\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)|getParameter\s*\(|getHeader\s*\(|'
              r'getQueryString|(?<!\w)req\.(query|body|params|headers|cookies)|(?<!\w)request\.(args|form|values|GET|POST|'
              r'FILES|data|json|params|query_params|cookies|headers)|params\[|Request\.(QueryString|Form|'
              r'Query|Cookies|Headers)|\bFormValue\s*\(|URL\.Query\(\)|c\.(Query|Param|PostForm)\s*\()')
SUPERGLOBAL = r'\$_(GET|POST|REQUEST|COOKIE|FILES|SERVER)'

PLACEHOLDER_VAL = re.compile(
    r'^(\$\{?|%\(|%s|\{\{|\{\w*\}|<|\[|\*+$|x{3,}|\.{3}|changeme|change_me|pass(word)?\d*$|passwd|secret$|'
    r'example|sample|test|dummy|null|none|nil|undefined|true|false|your[_-]?|todo|tbd|placeholder|'
    r'redacted|process\.env|os\.environ|getenv|env\(|config\(|settings\.|required|optional|string|'
    r'hidden|enter|insert|type|\*\*\*)', re.I)
SECRET_KEY_NOISE = re.compile(r'(field|label|placeholder|name|param|column|header|url|path|input|'
                              r'type|policy|regex|pattern|message|msg|error|hint|reset|forgot|confirm|'
                              r'length|min|max|rule|valid|strength|prompt|title|text|key_?id|_id$|file)', re.I)


def _valid_secret(m):
    val = m.groupdict().get('val') or ''
    key = m.groupdict().get('key') or ''
    if len(val) < 4 or PLACEHOLDER_VAL.match(val):
        return False
    if key and SECRET_KEY_NOISE.search(key):
        return False
    if re.match(r'^[a-z]+([._-][a-z]+)+$', val):          # i18n / config keys like auth.password.label
        return False
    if len(set(val)) <= 2:
        return False
    return True


def _valid_conn(m):
    val = m.groupdict().get('val') or ''
    return len(val) >= 3 and not PLACEHOLDER_VAL.match(val)


R = Rule
BUILTIN_RULES = [
    # ---------------------------------------------------------------- Python
    R('py-os-system', 'Shell command execution (os.system / os.popen)', 'python',
      r'''\bos\.(system|popen\d?|spawn[lv]p?e?)\s*\((?!\s*["'][^"'+%{]*["']\s*\))''', 'HIGH', 78,
      boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('py-subprocess-shell', 'subprocess called with shell=True', 'python',
      r'\bsubprocess\.\w+\s*\(.*shell\s*=\s*True', 'HIGH', 78, boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('py-eval', 'Dynamic code evaluation (eval / exec)', 'python',
      r'''(?<![\w.])(eval|exec)\s*\((?!\s*["'][^"']*["']\s*\))''', 'HIGH', 95,
      boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('py-deserialization', 'Unsafe deserialization (pickle / marshal / shelve / jsonpickle)', 'python',
      r'\b(pickle|cPickle|_pickle|dill|shelve|jsonpickle|marshal)\.(loads?|Unpickler|open|decode)\b',
      'HIGH', 502),
    R('py-yaml-load', 'yaml.load without SafeLoader', 'python',
      r'\byaml\.(load|load_all|unsafe_load|full_load)\s*\((?![^)]*Loader\s*=\s*(yaml\.)?(C?SafeLoader|BaseLoader))',
      'HIGH', 502),
    R('py-sql', 'SQL query built with string formatting', 'python',
      r'''(\.(execute|executemany|executescript|raw|extra)|\bRawSQL|\btext)\s*\(\s*(f["']|["'][^"']*["']\s*(%|\.format\b|\+)|[A-Za-z_]\w*\s*(%|\+))''',
      'HIGH', 89, boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('py-ssti', 'Template rendered from a dynamic string (SSTI)', 'python',
      r'''\brender_template_string\s*\((?!\s*["'][^"']*["']\s*[,)])|\bjinja2\.Template\s*\((?!\s*["'][^"']*["']\s*\))|\bTemplate\s*\([^)]*request\.''',
      'HIGH', 1336, conf='MEDIUM'),
    R('py-autoescape-off', 'Template auto-escaping disabled', 'python',
      r'autoescape\s*=\s*False', 'MEDIUM', 79),
    R('py-mark-safe', 'HTML marked safe (escaping bypassed)', 'python',
      r'\bmark_safe\s*\((?!\s*["\'])|\bSafeString\s*\((?!\s*["\'])', 'MEDIUM', 79, conf='LOW',
      boost=(USER_INPUT, 'HIGH', 'MEDIUM')),
    R('py-markup', 'Markup() wraps a dynamic value (escaping bypassed)', 'python',
      r'\bMarkup\s*\((?!\s*["\'])', 'LOW', 79, conf='LOW', boost=(USER_INPUT, 'HIGH', 'MEDIUM')),
    R('py-ssrf', 'HTTP request to a user-controlled URL (SSRF)', 'python',
      r'\b(requests|httpx|session)\.(get|post|put|delete|head|request|patch)\s*\([^)]*request\.(args|form|values|json|GET|POST|data|params|query_params)|\burlopen\s*\([^)]*request\.',
      'HIGH', 918),
    R('py-path', 'File path built from request data', 'python',
      r'\b(open|send_file|send_from_directory|os\.path\.join|FileResponse|os\.remove|shutil\.\w+)\s*\([^)]*request\.(args|form|values|GET|POST|FILES|json|params|query_params|data)',
      'HIGH', 22),
    R('py-xml-parser', 'XML parsing with a non-hardened stdlib / lxml parser', 'python',
      r'^\s*(import|from)\s+(xml\.etree|xml\.dom|xml\.sax|lxml)\b', 'LOW', 611, conf='LOW',
      unless_file=r'defusedxml'),
    R('py-lxml-entities', 'lxml parser resolves entities', 'python',
      r'resolve_entities\s*=\s*True|no_network\s*=\s*False', 'HIGH', 611),
    R('py-mktemp', 'Insecure temporary file (tempfile.mktemp)', 'python',
      r'\btempfile\.mktemp\s*\(', 'LOW', 377),
    R('py-assert-auth', 'assert used for a security check (removed with -O)', 'python',
      r'^\s*assert\b.*\b(is_admin|is_authenticated|has_perm|permission|role|authorized|logged)', 'MEDIUM',
      287, conf='LOW'),

    # ---------------------------------------------------------------- JavaScript / TypeScript
    R('js-eval', 'Dynamic code evaluation (eval / new Function / string timers)', 'js',
      r'''(?<![\w.$])eval\s*\((?!\s*["'][^"']*["']\s*\))|\bnew\s+Function\s*\(|\bset(Timeout|Interval)\s*\(\s*["'`]''',
      'HIGH', 95, boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('js-child-process', 'child_process command execution', 'js',
      r'''(?<![\w.$])(exec|execSync)\s*\(\s*(`[^`]*\$\{|["'][^"'\n]*["']\s*\+|[^,)"'`]*\+|[A-Za-z_$][\w$.]*\s*[,)])|\b(child_process|cp|childProcess)\.(exec|execSync)\s*\(|\bspawn(Sync)?\s*\([^)]*shell\s*:\s*true''',
      'HIGH', 78, only_if_file=r'child_process|shelljs|execa', boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('js-xss-sink', 'Raw HTML sink (innerHTML / document.write / v-html / dangerouslySetInnerHTML)', 'js template',
      r'''\.(innerHTML|outerHTML)\s*\+?=(?!=)(?!\s*["'`][^"'`$]*["'`]\s*;?\s*$)|\bdocument\.write(ln)?\s*\(|\.insertAdjacentHTML\s*\(|dangerouslySetInnerHTML|\bv-html\s*=|bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl)\s*\(|\$\([^)]*\)\.html\s*\((?!\s*\))''',
      'MEDIUM', 79, boost=(r'location\.(hash|search|href)|document\.(URL|referrer|cookie)|window\.name|' + USER_INPUT, 'HIGH', 'HIGH')),
    R('js-dom-redirect', 'Client-side redirect from URL data (DOM open redirect / javascript: XSS)', 'js template',
      r'(location(\.href)?\s*=(?!=)|location\.(assign|replace)\s*\(|window\.open\s*\()[^\n;]*(location\.(hash|search)|URLSearchParams|searchParams|getParameter|params\.get|query\.)',
      'MEDIUM', 601),
    R('js-sql', 'SQL query built with template literal / concatenation', 'js',
      r'''\.(query|execute|raw|whereRaw|orderByRaw|havingRaw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(\s*(`[^`]*\$\{|["'][^"']*["']\s*\+|[A-Za-z_$][\w$]*\s*\+)''',
      'HIGH', 89, boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('js-nosql', 'NoSQL query built directly from request data', 'js',
      r'\.(find|findOne|findOneAndUpdate|findOneAndDelete|updateOne|updateMany|deleteOne|deleteMany|count|countDocuments|where|aggregate)\s*\(\s*req\.(body|query|params)|\$where\s*:',
      'HIGH', 943),
    R('js-ssrf', 'HTTP request to a user-controlled URL (SSRF)', 'js',
      r'\b(axios(\.(get|post|put|delete|request|head|patch))?|fetch|got|needle|superagent\.(get|post)|request(\.(get|post))?|https?\.(get|request))\s*\(\s*[^)]*req\.(query|body|params|headers)',
      'HIGH', 918),
    R('js-path', 'File path built from request data', 'js',
      r'\b(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|unlinkSync|sendFile|download|render|require|join|resolve)\s*\([^)]*req\.(query|body|params)',
      'HIGH', 22),
    R('js-prototype-pollution', 'Possible prototype pollution', 'js',
      r'''(\b_\.(merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep)|\$\.extend\s*\(\s*true|\bdeepmerge|\bdeepExtend|\bmerge)\s*\([^)]*req\.(body|query|params)|\[\s*["']__proto__["']\s*\]|\bconstructor\s*\[\s*["']prototype''',
      'MEDIUM', 1321),
    R('js-mass-assignment', 'Model created / updated from the whole request body', 'js',
      r'\.(create|update|insert|build|findOneAndUpdate|updateOne|findByIdAndUpdate)\s*\(\s*(\{\s*\.\.\.)?req\.body\s*\}?\s*[,)]|Object\.assign\s*\([^,]+,\s*req\.body|new\s+\w+\s*\(\s*req\.body\s*\)',
      'MEDIUM', 915),
    R('js-jwt-decode', 'jwt.decode() does not verify the signature', 'js',
      r'\bjwt\.decode\s*\(', 'MEDIUM', 347, conf='LOW'),
    R('js-vm', 'Node vm module used for untrusted code (not a sandbox)', 'js',
      r'\bvm\.(runInNewContext|runInThisContext|runInContext|compileFunction)\s*\(|new\s+vm\.Script\s*\(',
      'MEDIUM', 94, boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('js-deserialization', 'Unsafe deserialization (node-serialize / funcster)', 'js',
      r'''require\s*\(\s*["'](node-serialize|funcster|serialize-to-js)["']\s*\)|\bunserialize\s*\(''', 'HIGH', 502),
    R('js-template-injection', 'Template compiled from request data (SSTI)', 'js',
      r'\b(ejs|pug|jade|handlebars|Handlebars|nunjucks|_|lodash|doT|dot)\.(render|compile|template)\s*\([^)]*req\.(query|body|params)',
      'HIGH', 1336),
    R('js-postmessage-star', 'postMessage to any origin ("*")', 'js template',
      r'''\.postMessage\s*\([^)]*,\s*["']\*["']''', 'LOW', 346),
    R('js-message-no-origin', 'message event handler without origin check', 'js template',
      r'''addEventListener\s*\(\s*["']message["']''', 'LOW', 346, conf='LOW', unless_file=r'\.origin\b'),
    R('js-storage-token', 'Token / secret stored in Web Storage', 'js',
      r'''(localStorage|sessionStorage)\.setItem\s*\(\s*["'][^"']*(token|jwt|auth|session|password|secret)''',
      'LOW', 922),

    # ---------------------------------------------------------------- PHP
    R('php-command', 'Shell command execution', 'php',
      r'(?<![\w>$:])(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(', 'HIGH', 78,
      boost=(SUPERGLOBAL, 'CRITICAL', 'HIGH')),
    R('php-backticks', 'Backtick shell execution with variables', 'php',
      r'`[^`\n]*\$[^`\n]*`', 'HIGH', 78, boost=(SUPERGLOBAL, 'CRITICAL', 'HIGH')),
    R('php-eval', 'Dynamic code evaluation (eval / assert / create_function / preg_replace /e)', 'php',
      r'''(?<![\w>$:])(eval|assert|create_function)\s*\((?!\s*["'][^"'$]*["']\s*\))|preg_replace\s*\(\s*["'](.).*\2[a-zA-Z]*e[a-zA-Z]*["']''',
      'HIGH', 95, boost=(SUPERGLOBAL, 'CRITICAL', 'HIGH')),
    R('php-include', 'Dynamic file inclusion', 'php',
      r'(?<![\w])(include|include_once|require|require_once)\b\s*\(?\s*[^;]*\$', 'LOW', 98, conf='LOW',
      unless_line=r'__DIR__\s*\.\s*["\']|dirname\s*\(\s*__FILE__',
      boost=(SUPERGLOBAL, 'CRITICAL', 'HIGH')),
    R('php-unserialize', 'unserialize() on potentially untrusted data', 'php',
      r'(?<![\w>$:])unserialize\s*\(', 'HIGH', 502,
      unless_line=r'allowed_classes["\']?\s*=>\s*false', boost=(SUPERGLOBAL, 'CRITICAL', 'HIGH')),
    R('php-sql', 'SQL query built with concatenation / interpolation', 'php',
      r'(mysql_query|mysqli_query|mysqli_multi_query|mysqli_real_query|pg_query|sqlite_query|->query|->exec|->prepare|->rawQuery|DB::(select|statement|raw|unprepared|insert|update|delete)|->whereRaw|->selectRaw|->orderByRaw|->havingRaw|->groupByRaw)\s*\((?=[^;]*(\$_(GET|POST|REQUEST|COOKIE)|\.\s*\$|"[^"]*\$\w|\{\$))',
      'HIGH', 89, boost=(SUPERGLOBAL, 'CRITICAL', 'HIGH')),
    R('php-xss-echo', 'Request data echoed without encoding', 'php',
      r'''(?<![\w])(echo|print)\b[^;]*\$_(GET|POST|REQUEST|COOKIE)|(?<![\w])(echo|print)\b[^;]*\$_SERVER\s*\[\s*["'](PHP_SELF|REQUEST_URI|QUERY_STRING|HTTP_\w+)|<\?=\s*\$_(GET|POST|REQUEST|COOKIE)''',
      'HIGH', 79, conf='HIGH',
      unless_line=r'htmlspecialchars|htmlentities|intval|\(int\)|json_encode|filter_var|esc_(html|attr)|\be\s*\(|urlencode'),
    R('php-short-echo', 'Request data printed with <?= without encoding', 'php',
      r'<\?=\s*\$_(GET|POST|REQUEST|COOKIE)', 'HIGH', 79, conf='HIGH', raw=True,
      unless_line=r'htmlspecialchars|htmlentities|intval|\(int\)|json_encode|esc_(html|attr)|\be\s*\('),
    R('php-file-access', 'File operation on a path from request data', 'php',
      r'(file_get_contents|fopen|readfile|file|unlink|file_put_contents|copy|rename|opendir|scandir|highlight_file|show_source|parse_ini_file|simplexml_load_file|move_uploaded_file|mkdir|rmdir|touch)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)',
      'HIGH', 22),
    R('php-ssrf', 'Outgoing request to a URL from request data (SSRF)', 'php',
      r'(curl_init|curl_setopt\s*\([^,]+,\s*CURLOPT_URL|file_get_contents|fsockopen|get_headers|SoapClient|fopen)\s*\(?[^;]*\$_(GET|POST|REQUEST)',
      'HIGH', 918, conf='MEDIUM'),
    R('php-extract', 'Variables extracted from request data', 'php',
      r'\b(extract|parse_str)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)|\bparse_str\s*\(\s*[^,)]+\)|\bimport_request_variables\s*\(',
      'MEDIUM', 621),
    R('php-dynamic-call', 'Function / variable name taken from request data', 'php',
      r'\$\{\s*\$_|\$\$_|call_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST)|\$_(GET|POST|REQUEST)\s*\[[^\]]+\]\s*\(|new\s+\$_(GET|POST|REQUEST)',
      'HIGH', 470),
    R('php-loose-compare', 'Loose comparison in security check (type juggling)', 'php',
      r'(?<![=!<>])==(?!=)\s*(\$_(GET|POST|REQUEST|COOKIE)|md5\s*\(|sha1\s*\(|hash\s*\(|crypt\s*\()|\b(md5|sha1|hash|crypt)\s*\([^)]*\)\s*(?<![=!<>])==(?!=)|\b(strcmp|strcasecmp)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)',
      'MEDIUM', 697, conf='LOW'),
    R('php-xxe', 'XML parser with entity loading enabled', 'php',
      r'libxml_disable_entity_loader\s*\(\s*false|LIBXML_NOENT|LIBXML_DTDLOAD|->substituteEntities\s*=\s*true',
      'HIGH', 611),
    R('php-upload', 'File upload handling (review validation)', 'php',
      r'''\bmove_uploaded_file\s*\(|\$_FILES\s*\[[^\]]+\]\s*\[\s*["']type["']\s*\]''', 'LOW', 434, conf='LOW'),
    R('php-mail-injection', 'mail() with request data (header injection)', 'php',
      r'\bmail\s*\([^;]*\$_(GET|POST|REQUEST)', 'MEDIUM', 93),
    R('php-session-fixation', 'Session ID set from request data', 'php',
      r'session_id\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)', 'HIGH', 384),
    R('php-mass-assignment', 'Mass assignment (Laravel)', 'php',
      r'\$guarded\s*=\s*\[\s*\]|->(fill|forceFill|update|create)\s*\(\s*\$request->(all|input)\(\s*\)\s*\)|::(create|forceCreate|update)\s*\(\s*\$request->(all|input)\(\s*\)',
      'MEDIUM', 915),
    R('php-ldap', 'LDAP query with request data', 'php',
      r'ldap_(search|list|read|bind)\s*\([^;]*\$_(GET|POST|REQUEST)', 'HIGH', 90),
    R('php-header-redirect', 'Redirect / header built from request data', 'php',
      r'''\bheader\s*\(\s*["']Location:[^;]*\$_(GET|POST|REQUEST|SERVER)''', 'MEDIUM', 601),

    # ---------------------------------------------------------------- Java / Kotlin / JVM
    R('java-command', 'OS command execution (Runtime.exec / ProcessBuilder)', 'java',
      r'Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(', 'MEDIUM', 78, conf='LOW',
      boost=(r'\+|' + USER_INPUT, 'HIGH', 'MEDIUM')),
    R('java-sql', 'SQL query built with concatenation', 'java',
      r'''\.(executeQuery|executeUpdate|execute|executeLargeUpdate|addBatch|prepareStatement|prepareCall|createQuery|createNativeQuery|createSQLQuery|queryForObject|queryForList|queryForMap|queryForRowSet|query|update|batchUpdate)\s*\(\s*(["'][^"']*["']\s*\+|[A-Za-z_]\w*\s*\+|String\.format\s*\()''',
      'HIGH', 89, boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('java-xss-writer', 'Request data written to the response', 'java',
      r'\.getWriter\s*\(\s*\)\s*\.(print|println|write|append|printf|format)\s*\([^)]*(getParameter|getHeader|getQueryString|getCookies|getRequestURI)',
      'HIGH', 79),
    R('java-deserialization', 'Unsafe deserialization', 'java',
      r'new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|\bnew\s+XMLDecoder\s*\(|new\s+XStream\s*\(|enableDefaultTyping\s*\(|activateDefaultTyping\s*\(|@JsonTypeInfo\s*\([^)]*Id\.(CLASS|MINIMAL_CLASS)|new\s+Yaml\s*\(\s*\)|\bSerializationUtils\.deserialize\s*\(|\bnew\s+Kryo\s*\(|\bHessian2?Input\s*\(',
      'HIGH', 502),
    R('java-xxe', 'XML parser factory without XXE hardening in this file', 'java',
      r'\b(DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SchemaFactory|SAXTransformerFactory)\.new(Instance|Factory|DefaultFactory)\s*\(|new\s+(SAXReader|SAXBuilder)\s*\(|XMLReaderFactory\.createXMLReader\s*\(',
      'MEDIUM', 611,
      unless_file=r'disallow-doctype-decl|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|external-general-entities|SUPPORT_DTD|IS_SUPPORTING_EXTERNAL_ENTITIES'),
    R('java-path', 'File path built from request data / concatenation', 'java',
      r'new\s+(File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile)\s*\([^)]*(getParameter|getHeader|getOriginalFilename|\+)|(Paths\.get|Path\.of)\s*\([^)]*(getParameter|getOriginalFilename|\+)',
      'MEDIUM', 22, conf='LOW', boost=(r'getParameter|getHeader|getOriginalFilename', 'HIGH', 'MEDIUM')),
    R('java-ssrf', 'Outgoing request to a URL from request data (SSRF)', 'java',
      r'new\s+URL\s*\([^)]*(getParameter|getHeader)|\b(restTemplate|webClient|RestTemplate|WebClient|HttpClient|httpClient)\b[^;]*\.(getForObject|getForEntity|exchange|postForObject|postForEntity|uri|send)\s*\([^)]*(getParameter|\+)',
      'MEDIUM', 918, boost=(r'getParameter|getHeader', 'HIGH', 'MEDIUM')),
    R('java-expression', 'Expression language evaluation (SpEL / OGNL / EL)', 'java',
      r'\bnew\s+SpelExpressionParser\s*\(|\.parseExpression\s*\(|\bOgnl\.(getValue|parseExpression|setValue)\s*\(|\.findValue\s*\(|\bnew\s+ELProcessor\s*\(|\bcreateValueExpression\s*\(|\bMVEL\.(eval|compileExpression)\s*\(',
      'MEDIUM', 917, conf='LOW', boost=(USER_INPUT, 'HIGH', 'MEDIUM')),
    R('java-template', 'Template evaluated from a dynamic string (SSTI)', 'java',
      r'Velocity\.evaluate\s*\(|\bvelocityEngine\.evaluate\s*\(|new\s+Template\s*\([^)]*(getParameter|new\s+StringReader)|\.putTemplate\s*\(',
      'MEDIUM', 1336, boost=(USER_INPUT, 'HIGH', 'MEDIUM')),
    R('java-reflection', 'Class loaded / method invoked from a dynamic name', 'java',
      r'Class\.forName\s*\([^)]*(getParameter|getHeader|\+)|\.getMethod\s*\([^)]*getParameter', 'MEDIUM', 470,
      boost=(r'getParameter|getHeader', 'HIGH', 'MEDIUM')),
    R('java-csrf-disabled', 'Spring Security CSRF protection disabled', 'java',
      r'csrf\s*\(\s*\)\s*\.\s*disable\s*\(|csrf\s*\(\s*(AbstractHttpConfigurer::disable|\w+\s*->\s*\w+\.disable\s*\(\s*\))',
      'MEDIUM', 352),
    R('java-ldap', 'LDAP filter built with concatenation', 'java csharp js python',
      r'''["']\(?[&|]?\(?(uid|cn|mail|sAMAccountName|userPrincipalName|ou|objectClass|member)=["']\s*\+''',
      'HIGH', 90),
    R('java-random-seed', 'SecureRandom with static seed', 'java',
      r'new\s+SecureRandom\s*\(\s*["\w]+\.getBytes|\.setSeed\s*\(\s*\d+', 'MEDIUM', 338),
    R('java-static-iv-key', 'Hard-coded IV / key material', 'java',
      r'''new\s+IvParameterSpec\s*\(\s*(new\s+byte\s*\[\s*\]\s*\{|["'][^"']*["']\.getBytes)|new\s+SecretKeySpec\s*\(\s*["'][^"']*["']\.getBytes''',
      'HIGH', 321),
    R('android-webview', 'WebView JavaScript bridge / file access enabled', 'android',
      r'setJavaScriptEnabled\s*\(\s*true|addJavascriptInterface\s*\(|setAllowFileAccess(FromFileURLs)?\s*\(\s*true|setAllowUniversalAccessFromFileURLs\s*\(\s*true|setAllowContentAccess\s*\(\s*true',
      'MEDIUM', 749),
    R('android-world-readable', 'World readable / writable file mode', 'android',
      r'MODE_WORLD_(READABLE|WRITEABLE)', 'HIGH', 732),
    R('android-external-storage', 'Data written to external storage', 'android',
      r'getExternalStorageDirectory\s*\(|getExternalFilesDir\s*\(|getExternalStoragePublicDirectory\s*\(',
      'LOW', 312, conf='LOW'),
    R('android-ssl-proceed', 'WebView SSL errors ignored (handler.proceed)', 'android',
      r'\.proceed\s*\(\s*\)', 'HIGH', 295, only_if_file=r'onReceivedSslError'),
    R('android-intent-redirect', 'Intent data used to load a URL / start component', 'android',
      r'loadUrl\s*\([^)]*get(String|Data|Parcelable)Extra|startActivity\s*\(\s*get(Intent|Parcelable)', 'MEDIUM', 749),

    # ---------------------------------------------------------------- C# / .NET
    R('cs-command', 'Process execution', 'csharp',
      r'Process\.Start\s*\(|new\s+ProcessStartInfo\s*\(', 'MEDIUM', 78, conf='LOW',
      boost=(r'\+|\$"|' + USER_INPUT, 'HIGH', 'MEDIUM')),
    R('cs-sql', 'SQL command built with concatenation / interpolation', 'csharp',
      r'(new\s+(SqlCommand|OleDbCommand|OdbcCommand|MySqlCommand|NpgsqlCommand|OracleCommand|SqliteCommand|SQLiteCommand)\s*\(|\.CommandText\s*=|\.(ExecuteSqlRaw|ExecuteSqlCommand|FromSqlRaw|SqlQuery|SqlQueryRaw|ExecuteQuery|ExecuteSqlRawAsync|ExecuteSqlCommandAsync|Query|QueryAsync|Execute|ExecuteAsync|QueryFirst|QueryFirstOrDefault|QuerySingle)\s*(<[^>]+>)?\s*\()\s*(\$@?"[^"]*\{|@?"[^"]*"\s*\+|[A-Za-z_]\w*\s*\+|string\.Format\s*\(|String\.Format\s*\()',
      'HIGH', 89, boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('cs-deserialization', 'Unsafe .NET deserializer / type handling', 'csharp',
      r'\b(BinaryFormatter|SoapFormatter|NetDataContractSerializer|LosFormatter|ObjectStateFormatter)\b|JavaScriptSerializer\s*\(\s*new\s+SimpleTypeResolver|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects|Arrays)',
      'HIGH', 502),
    R('cs-xss', 'Raw HTML output (Html.Raw / HtmlString)', 'csharp template',
      r'@?Html\.Raw\s*\(|new\s+(Html|MvcHtml)String\s*\(|MvcHtmlString\.Create\s*\(|Response\.Write\s*\([^)]*Request\.',
      'MEDIUM', 79),
    R('cs-request-validation', 'ASP.NET request validation disabled', 'csharp',
      r'ValidateRequest\s*=\s*"?false|\[ValidateInput\s*\(\s*false\s*\)\]|\[AllowHtml\]|requestValidationMode\s*=\s*"2\.0"',
      'MEDIUM', 79),
    R('cs-xxe', 'XML resolver / DTD processing enabled', 'csharp',
      r'XmlResolver\s*=\s*new\s+XmlUrlResolver|DtdProcessing\s*=\s*DtdProcessing\.Parse|ProhibitDtd\s*=\s*false',
      'HIGH', 611),
    R('cs-path', 'File path built from request data', 'csharp',
      r'(File\.(ReadAllText|ReadAllBytes|OpenRead|Open|WriteAllText|Delete|Exists)|new\s+FileStream|Path\.Combine|PhysicalFile|File\s*\()\s*\([^)]*(Request\.|\bfileName\b|\.FileName)',
      'MEDIUM', 22, conf='LOW', boost=(r'Request\.', 'HIGH', 'MEDIUM')),

    # ---------------------------------------------------------------- Go
    R('go-command', 'OS command execution (exec.Command)', 'go',
      r'\bexec\.Command(Context)?\s*\(', 'MEDIUM', 78, conf='LOW',
      boost=(r'"(sh|bash|zsh|cmd|cmd\.exe|/bin/sh|/bin/bash|powershell)"\s*,\s*"(-c|/c|/C)"|' + USER_INPUT, 'HIGH', 'HIGH')),
    R('go-sql', 'SQL query built with fmt.Sprintf / concatenation', 'go',
      r'\.(Query|QueryRow|Exec|Raw|Where|Order|Select|Having|Joins)\s*\(\s*(fmt\.Sprintf\s*\(|"[^"]*"\s*\+|[A-Za-z_]\w*\s*\+)|\.(QueryContext|QueryRowContext|ExecContext)\s*\(\s*\w+\s*,\s*(fmt\.Sprintf\s*\(|"[^"]*"\s*\+|[A-Za-z_]\w*\s*\+)',
      'HIGH', 89, boost=(USER_INPUT, 'CRITICAL', 'HIGH')),
    R('go-template-unescaped', 'Unescaped content in html/template (template.HTML / JS / URL)', 'go',
      r'template\.(HTML|JS|URL|CSS|HTMLAttr|JSStr|Srcset)\s*\(', 'MEDIUM', 79),
    R('go-text-template-http', 'text/template used in an HTTP handler (no auto-escaping)', 'go',
      r'"text/template"', 'LOW', 79, conf='LOW', only_if_file=r'net/http|gin-gonic|labstack/echo|gofiber'),
    R('go-path', 'File path built from request data', 'go',
      r'(os\.(Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll)|ioutil\.(ReadFile|WriteFile)|http\.ServeFile|filepath\.Join|c\.(File|SaveUploadedFile))\s*\([^)]*(r\.(URL|Form|PostForm)|FormValue\s*\(|Query\(\)\.Get|c\.(Param|Query|PostForm)\s*\(|\.Filename)',
      'HIGH', 22),
    R('go-ssrf', 'HTTP request to a user-controlled URL (SSRF)', 'go',
      r'http\.(Get|Post|Head|NewRequest(WithContext)?)\s*\([^)]*(r\.URL\.Query|FormValue|c\.(Query|Param|PostForm))',
      'HIGH', 918),

    # ---------------------------------------------------------------- Ruby / Rails
    R('rb-command', 'OS command execution with interpolation / params', 'ruby',
      r'''(?<![\w.])(system|exec|spawn|syscall)\s*\(?\s*"[^"\n]*#\{|(?<![\w.])(system|exec|spawn)\s*\(?[^)\n]*params\[|\b(IO\.popen|Open3\.\w+|Kernel\.(system|exec|spawn)|PTY\.spawn)\s*\(|%x[\(\{\[]|`[^`\n]*#\{|(?<![\w.])open\s*\(\s*params''',
      'HIGH', 78, boost=(r'params', 'CRITICAL', 'HIGH')),
    R('rb-eval', 'Dynamic code evaluation / invocation from params', 'ruby',
      r'(?<![\w.])(eval|instance_eval|class_eval|module_eval)\s*\(?[^)\n]*(params|#\{|request\.)|\.(send|public_send|__send__|try)\s*\(?\s*params|\.(constantize|safe_constantize)\b[^\n]*params|params[^\n]*\.(constantize|safe_constantize)',
      'HIGH', 95),
    R('rb-sql', 'SQL built with interpolation / params (ActiveRecord)', 'ruby',
      r'''\.(where|find_by_sql|execute|exec_query|select|order|group|having|joins|pluck|from|calculate|delete_all|update_all|exists\?|lock|reorder|count_by_sql|select_all|select_value|select_rows)\s*\(?\s*"[^"\n]*#\{|\.(where|order|find_by_sql|execute|exec_query|group|pluck|reorder)\s*\(\s*params''',
      'HIGH', 89),
    R('rb-deserialization', 'Unsafe deserialization (Marshal / YAML.load / Oj)', 'ruby',
      r'\b(Marshal\.(load|restore)|YAML\.(load|unsafe_load|load_documents)|Psych\.(load|unsafe_load)|Oj\.(load|object_load))\s*\(',
      'HIGH', 502, unless_line=r'safe_load|permitted_classes|mode:\s*:(strict|null|compat)'),
    R('rb-mass-assignment', 'Mass assignment from params', 'ruby',
      r'''params\.permit!|\.(new|create|create!|update|update!|update_attributes|assign_attributes)\s*\(\s*params\[[:'"]?\w+['"]?\]\s*\)|\battr_accessible\b''',
      'MEDIUM', 915),
    R('rb-file', 'File access with params', 'ruby',
      r'(File\.(open|read|write|readlines|new|delete|unlink|binread)|IO\.(read|readlines)|send_file|send_data\s*\(\s*File|File\.join|Pathname\.new)\s*\(?[^)\n]*params',
      'HIGH', 22),
    R('rb-ssrf', 'Outgoing request to a URL from params (SSRF)', 'ruby',
      r'(Net::HTTP\.(get|get_response|post_form|start|new)|URI\.open|URI\.parse|HTTParty\.(get|post)|Faraday\.(get|post|new)|RestClient\.(get|post)|Excon\.(get|post)|open-uri)\s*\(?[^)\n]*params',
      'HIGH', 918),
    R('rb-render-dynamic', 'render with inline / file / template from params', 'ruby',
      r'render\s*\(?\s*(inline|file|template|partial)\s*:\s*params|render\s*\(?\s*params', 'HIGH', 1336),

    # ---------------------------------------------------------------- C / C++ / Obj-C
    R('c-gets', 'gets() - unbounded read', 'c', r'(?<![\w.>])gets\s*\(', 'HIGH', 120, conf='HIGH'),
    R('c-unbounded-copy', 'Unbounded string copy / format (strcpy, strcat, sprintf...)', 'c',
      r'(?<![\w.>])(strcpy|strcat|sprintf|vsprintf|wcscpy|wcscat|lstrcpy[AW]?|lstrcat[AW]?|StrCpy|StrCat|_mbscpy|_mbscat|stpcpy)\s*\(',
      'MEDIUM', 120, conf='LOW'),
    R('c-scanf-s', 'scanf family with unbounded %s', 'c',
      r'\b(scanf|fscanf|sscanf|vscanf|wscanf)\s*\([^;]*"[^"]*%s', 'HIGH', 120),
    R('c-format-string', 'Non-constant format string', 'c',
      r'(?<![\w.>])(printf|vprintf)\s*\(\s*[A-Za-z_][\w\->.\[\]]*\s*\)|(?<![\w.>])fprintf\s*\(\s*\w+\s*,\s*[A-Za-z_][\w\->.\[\]]*\s*\)|(?<![\w.>])syslog\s*\(\s*[^,]+,\s*[A-Za-z_][\w\->.\[\]]*\s*\)|(?<![\w.>])snprintf\s*\(\s*[^,]+,\s*[^,]+,\s*[A-Za-z_][\w\->.\[\]]*\s*\)|(?<![\w.>])sprintf\s*\(\s*[^,]+,\s*[A-Za-z_][\w\->.\[\]]*\s*\)',
      'HIGH', 134),
    R('c-command', 'Command execution (system / popen / exec*)', 'c',
      r'(?<![\w.>])(system|popen|_popen|execl|execlp|execle|execv|execvp|execvpe|WinExec|ShellExecute[AW]?|CreateProcess[AW]?)\s*\(',
      'MEDIUM', 78, conf='LOW'),
    R('c-tmpfile', 'Insecure temporary file name (tmpnam / mktemp)', 'c',
      r'(?<![\w.>])(tmpnam|tempnam|mktemp|_mktemp)\s*\(', 'LOW', 377),
    R('c-alloca', 'Stack allocation with alloca()', 'c', r'(?<![\w.>])alloca\s*\(', 'LOW', 770, conf='LOW'),

    # ---------------------------------------------------------------- Shell / SQL
    R('sh-eval', 'eval in shell script', 'shell', r'(?<![\w-])eval\s+', 'MEDIUM', 95, conf='LOW'),
    R('sh-curl-pipe', 'Remote script piped to a shell', 'shell any',
      r'(curl|wget)\s[^|\n]*\|\s*(sudo\s+)?(ba|z|k|da)?sh\b', 'MEDIUM', 494),
    R('sql-dynamic', 'Dynamic SQL in stored code (EXEC / EXECUTE IMMEDIATE / sp_executesql)', 'sql',
      r'''(?i)(\bEXEC(UTE)?\s*\(\s*@\w+|\bEXEC(UTE)?\s*\([^)]*\+|\bEXECUTE\s+IMMEDIATE\b|\bsp_executesql\b|\bPREPARE\s+\w+\s+FROM\s+@|\bEXECUTE\s+format\s*\(|\bEXECUTE\s+['"][^'"]*['"]\s*\|\|)''',
      'MEDIUM', 89, conf='LOW'),

    # ---------------------------------------------------------------- Templates
    R('tpl-raw-output', 'Unescaped template output', 'template',
      r'''\{\{\{[^}]+\}\}\}|\{!!\s*.+?!!\}|\|\s*(safe|raw|noescape)\b|\{%\s*autoescape\s+(false|off)|<%==|\.html_safe\b|(?<![\w.])raw\s*\(|\bv-html\s*=|th:utext\s*=|escapeXml\s*=\s*["']false|\$\{\s*(param|header|cookie)\b|<%=\s*request\.getParameter|\{\{\s*[^}]*\|\s*noescape|\{@html\s''',
      'MEDIUM', 79, boost=(USER_INPUT + r'|param\.|request\.', 'HIGH', 'HIGH')),
    R('ejs-unescaped', 'EJS unescaped output (<%- %>)', '.ejs', r'<%-(?!-)', 'MEDIUM', 79),
    R('jsp-scriptlet-output', 'JSP scriptlet expression output (not encoded)', '.jsp .jspx .jspf .tag',
      r'<%=(?!\s*(Encode|ESAPI|StringEscapeUtils|Encoder|fn:escapeXml))', 'MEDIUM', 79, conf='LOW'),

    # ---------------------------------------------------------------- Cross-language
    R('weak-hash', 'Weak hash algorithm (MD5 / SHA-1)', 'any',
      r'''\b(hashlib\.(md5|sha1)|MessageDigest\.getInstance\s*\(\s*"(MD5|MD4|MD2|SHA-?1|SHA)"|DigestUtils\.(md5|sha1|sha)(Hex)?\s*\(|createHash\s*\(\s*["'](md5|sha1|md4)["']|(MD5|SHA1)(CryptoServiceProvider|Managed)?\.Create\s*\(|new\s+(MD5CryptoServiceProvider|SHA1Managed|SHA1CryptoServiceProvider)|"crypto/(md5|sha1)"|Digest::(MD5|SHA1)|hash\s*\(\s*["'](md5|sha1|md4|crc32)["'])|(?<![\w>$:.])(md5|sha1|md5_file|sha1_file)\s*\(''',
      'MEDIUM', 328, boost=(r'passw|pwd|secret|token|sign|auth', 'HIGH', 'MEDIUM')),
    R('weak-cipher', 'Weak cipher or mode (DES / 3DES / RC4 / ECB / AES default)', 'any',
      r'''(?i)(Cipher\.getInstance\s*\(\s*"(DES|DESede|TripleDES|RC2|RC4|ARCFOUR|Blowfish|AES|[^"]*/ECB/[^"]*)"|\bDES3?\.new\s*\(|\bARC[24]\.new\s*\(|\bBlowfish\.new\s*\(|\bAES\.MODE_ECB\b|\bMODE_ECB\b|CipherMode\.ECB|\bnew\s+(DESCryptoServiceProvider|TripleDESCryptoServiceProvider|RC2CryptoServiceProvider)|\b(DES|TripleDES|RC2)\.Create\s*\(|createCipher(iv)?\s*\(\s*["'](des|des-ede3?(-cbc)?|rc4|rc2|bf|blowfish|aes-\d+-ecb)["']|\bcreateCipher\s*\(|\bmcrypt_\w+\s*\(|openssl_(en|de)crypt\s*\([^,]+,\s*["'](des[^"']*|rc4|bf[^"']*|aes-\d+-ecb)["']|"crypto/(des|rc4)"|OpenSSL::Cipher\.new\s*\(\s*["'](des[^"']*|rc4|aes-\d+-ecb)["'])''',
      'HIGH', 327),
    R('insecure-random', 'Non-cryptographic random generator', 'any',
      r'''(\bMath\.random\s*\(|\bnew\s+Random\s*\(|(?<![\w>$:.])(rand|mt_rand|srand|mt_srand|lcg_value|uniqid)\s*\(|\brandom\.(random|randint|randrange|choice|choices|shuffle|getrandbits|uniform)\s*\(|"math/rand"|\bnew\s+System\.Random\b|\bRandom\.new\b|(?<![\w.])Random\.rand\b|\bkotlin\.random\.Random\b)''',
      'LOW', 338, conf='LOW',
      boost=(r'token|passw|secret|nonce|otp|salt|session|csrf|reset|captcha|api_?key|\bkey\b|\biv\b|uuid|guid|verification|code', 'MEDIUM', 'MEDIUM')),
    R('hardcoded-secret', 'Hard-coded password / secret / key', 'any',
      r'''(?i)\b(?P<key>[\w.-]{0,40}(password|passwd|passphrase|pwd|secret|api[_-]?key|apikey|access[_-]?key|auth[_-]?token|access[_-]?token|client[_-]?secret|private[_-]?key|secret[_-]?key|encryption[_-]?key|signing[_-]?key|jwt[_-]?secret|db[_-]?pass)[\w-]{0,20})["']?\s*(=|:|=>|:=)\s*(?P<q>["'`])(?P<val>[^"'`\s]{4,})(?P=q)''',
      'HIGH', 798, raw=True, validate=_valid_secret),
    R('secret-token', 'Known credential / token format', 'any',
      r'''\b(AKIA|ASIA)[0-9A-Z]{16}\b|-----BEGIN ((RSA|EC|DSA|OPENSSH|ENCRYPTED|PGP) )?PRIVATE KEY( BLOCK)?-----|\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{60,}|\bglpat-[A-Za-z0-9_-]{20}\b|\bxox[abposr]-[A-Za-z0-9-]{10,}|hooks\.slack\.com/services/T\w+/B\w+/\w+|\bAIza[0-9A-Za-z_-]{35}\b|\b(sk|rk)_live_[0-9a-zA-Z]{20,}|\bSG\.[\w-]{22}\.[\w-]{43}\b|\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}|AccountKey=[A-Za-z0-9+/=]{40,}|\bnpm_[A-Za-z0-9]{36}\b|\bsk-[A-Za-z0-9_-]{32,}''',
      'HIGH', 798, conf='HIGH', raw=True),
    R('secret-connection-string', 'Credentials embedded in a connection string / URL', 'any',
      r'''(?i)\b(jdbc:[a-z0-9]+:|mongodb(\+srv)?:|mysql:|postgres(ql)?:|redis:|rediss:|amqps?:|mssql:|sqlserver:|ftp:|sftp:|smtp:|ldap:)//[^\s"'/:@]+:(?P<val>[^\s"'@/$%{]{3,})@|\b(user id|uid|user)\s*=\s*[^;"']+;\s*(password|pwd)\s*=\s*(?P<val2>[^;"'\s$%{]{3,})''',
      'HIGH', 798, raw=True, validate=lambda m: _valid_conn(m) if m.group('val') else len(m.group('val2') or '') >= 3),
    R('tls-verification-disabled', 'TLS certificate / hostname verification disabled', 'any',
      r'''(verify\s*=\s*False|verify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE|OpenSSL::SSL::VERIFY_NONE|ssl\._create_unverified_context|\bCERT_NONE\b|check_hostname\s*=\s*False|rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED|strictSSL\s*:\s*false|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)|CURLOPT_SSL_VERIFYHOST\s*,\s*(false|0)|ServerCertificateValidationCallback\s*\+?=|ServerCertificateCustomValidationCallback\s*=|DangerousAcceptAnyServerCertificateValidator|[Tt]rustAll(Certs|Strategy|Manager)|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|TrustSelfSignedStrategy|\bcurl\s[^\n]*\s(-k|--insecure)\b|--no-check-certificate|["']?verify_peer["']?\s*=>\s*false|["']?allow_self_signed["']?\s*=>\s*true|checkServerTrusted\s*\([^)]*\)\s*(throws\s+\w+\s*)?\{\s*\})''',
      'HIGH', 295),
    R('cleartext-http', 'Cleartext http:// endpoint', 'any',
      r'''["']http://(?!localhost|127\.|0\.0\.0\.0|\[::1\]|www\.w3\.org|schemas\.|xmlns|(www\.)?example\.(com|org|net)|java\.sun\.com|maven\.apache|json-schema\.org|ns\.adobe|purl\.org|www\.springframework|jakarta\.ee|xml\.org|www\.apache\.org|java\.sun|docs\.oasis|www\.openarchives)[^"'\s]+["']''',
      'INFO', 319, conf='LOW'),
    R('open-redirect', 'Redirect to a location taken from request data', 'any',
      r'''(sendRedirect|redirect_to|\bredirect|Redirect|RedirectPermanent|LocalRedirect|header\s*\(\s*["']Location:|location\.(href|assign|replace))\s*[\(=]?[^;\n]*''' + USER_INPUT,
      'MEDIUM', 601, unless_line=r'LocalRedirect|url_has_allowed_host_and_scheme|is_safe_url|isLocalUrl|IsLocalUrl'),
    R('header-injection', 'Response header set from request data', 'any',
      r'(setHeader\s*\(|addHeader\s*\(|\bheader\s*\(|Header\(\)\.(Set|Add)\s*\(|AppendHeader\s*\(|AddHeader\s*\(|set_header\s*\(|headers\[[^\]]+\]\s*=)[^;\n]*' + USER_INPUT,
      'MEDIUM', 113, unless_line=r'Location'),
    R('csrf-disabled', 'CSRF protection disabled / bypassed', 'any',
      r'''(@csrf_exempt\b|\bcsrf_exempt\s*\(|WTF_CSRF_ENABLED\s*=\s*False|skip_before_action\s+:verify_authenticity_token|skip_forgery_protection|protect_from_forgery\s+with:\s*:null_session|\[IgnoreAntiforgeryToken|\bcsrf\s*:\s*false|csrfProtection\s*:\s*false|->withoutMiddleware\s*\([^)]*VerifyCsrfToken|protected\s+\$except\s*=\s*\[\s*["']\*["'])''',
      'MEDIUM', 352),
    R('cors-permissive', 'Permissive CORS policy', 'any',
      r'''(Access-Control-Allow-Origin["']?\s*[,:=]\s*["']\*|allowedOrigins?\s*\(\s*"\*"|setAllowedOrigins\s*\([^)]*"\*"|addAllowedOrigin(Pattern)?\s*\(\s*"\*"|allowedOriginPatterns\s*\(\s*"\*"|@CrossOrigin\s*(\(\s*\)|$|\(\s*(origins\s*=\s*)?"\*")|CORS_(ORIGIN_)?ALLOW_ALL(_ORIGINS)?\s*=\s*True|AllowAnyOrigin\s*\(\s*\)|\borigin\s*:\s*(true|["']\*["'])|SetIsOriginAllowed\s*\(\s*_?\w*\s*=>\s*true|Access-Control-Allow-Origin["']?\s*[,:=]\s*[^;\n]*(HTTP_ORIGIN|getHeader\s*\(\s*"Origin"|req\.headers\.origin|headers\[["']Origin))''',
      'MEDIUM', 942, boost=(r'credential', 'HIGH', 'HIGH')),
    R('debug-enabled', 'Debug mode / verbose errors / diagnostic output', 'any',
      r'''(^\s*DEBUG\s*=\s*True\b|\.run\s*\([^)]*debug\s*=\s*True|app\.debug\s*=\s*True|ini_set\s*\(\s*["']display_errors["']\s*,\s*["']?(1|on|true)|error_reporting\s*\(\s*(E_ALL|-1)\s*\)|\bphpinfo\s*\(|UseDeveloperExceptionPage\s*\(|setWebContentsDebuggingEnabled\s*\(\s*true|consider_all_requests_local\s*=\s*true|app\.use\s*\(\s*errorHandler\s*\(|\bvar_dump\s*\(|\bprint_r\s*\(\s*\$_|customErrors\s+mode\s*=\s*"Off")''',
      'LOW', 489),
    R('stacktrace-exposed', 'Stack trace printed / returned', 'any',
      r'\.printStackTrace\s*\(\s*\)|traceback\.(print_exc|format_exc)\s*\(|res\.(send|json)\s*\([^)]*\.stack\b|getTraceAsString\s*\(',
      'LOW', 209, conf='LOW'),
    R('insecure-cookie', 'Cookie without Secure / HttpOnly', 'any',
      r'''(httpOnly\s*[:=]\s*false|HttpOnly\s*=\s*false|\bsecure\s*[:=]\s*false|\bSecure\s*=\s*false|setHttpOnly\s*\(\s*false|setSecure\s*\(\s*false|SESSION_COOKIE_(SECURE|HTTPONLY)\s*=\s*False|CSRF_COOKIE_SECURE\s*=\s*False|session\.cookie_(httponly|secure)["']?\s*,\s*["']?(0|false|off)|sameSite\s*[:=]\s*["']?none)''',
      'LOW', 614),
    R('jwt-weak-validation', 'JWT signature / expiry validation weakened', 'any',
      r'''(algorithms?\s*[:=]\s*\[?\s*["']none["']|["']?verify_signature["']?\s*:\s*False|jwt\.decode\s*\([^)]*verify\s*=\s*False|ignoreExpiration\s*:\s*true|\.parseUnsecuredClaims\s*\(|\.parseClaimsJwt\s*\(|setSigningKey\s*\(\s*""|JWT::decode\s*\([^,]+,\s*(null|["']["'])|["']?verify_exp["']?\s*:\s*False|RequireSignedTokens\s*=\s*false|ValidateIssuerSigningKey\s*=\s*false|ValidateLifetime\s*=\s*false|RequireExpirationTime\s*=\s*false|ValidateIssuer\s*=\s*false|ValidateAudience\s*=\s*false)''',
      'HIGH', 347),
    R('sensitive-logging', 'Sensitive value possibly written to logs', 'any',
      r'''(?i)\b(log(ger)?|console|System\.(out|err)|Log|logging|syslog|error_log|Debug\.Write\w*|Trace\.Write\w*|fmt\.Print\w*)\s*[.(][^;\n]*[+,({]\s*\$?\w*(password|passwd|pwd|secret|credit_?card|cvv|api_?key|private_?key|access_?token)\w*\b''',
      'LOW', 532, conf='LOW'),
    R('broad-permissions', 'World-writable / overly broad permissions', 'any',
      r'(chmod\s*\(?[^;\n]*\b0?o?777\b|chmod\s+(-R\s+)?(0?777|a\+rwx|o\+w)\b|os\.chmod\s*\([^)]*0o?777|umask\s*\(\s*0+\s*\)|setReadable\s*\(\s*true\s*,\s*false\s*\)|setWritable\s*\(\s*true\s*,\s*false\s*\)|PosixFilePermissions\.fromString\s*\(\s*"rwxrwxrwx"|os\.(Chmod|MkdirAll|WriteFile|OpenFile)\s*\([^)]*0?777)',
      'MEDIUM', 732),
    R('regex-user-input', 'Regular expression built from request data (ReDoS / regex injection)', 'any',
      r'(new\s+RegExp|\bRegExp|re\.(compile|match|search|fullmatch|sub|findall|split)|Pattern\.(compile|matches)|new\s+Regex|Regex\.(Match|IsMatch|Replace)|preg_(match|match_all|replace|split)|regexp\.(MustCompile|Compile))\s*\(\s*[^,;\n]*' + USER_INPUT,
      'MEDIUM', 1333),
    R('file-upload', 'File upload handler (review validation)', 'java csharp js python ruby go',
      r'\.getOriginalFilename\s*\(|\bmulter\s*\(|\.save\s*\([^)]*\.filename|\bIFormFile\b|\bFormFile\s*\(|\.SaveAs\s*\(|request\.FILES\b|\.attach\s*\(\s*params',
      'LOW', 434, conf='LOW'),
    R('sql-concat', 'SQL statement assembled with string concatenation / interpolation', 'any',
      r'''(?i)(["'][^"'\n]*\b(select\s[^"'\n]*\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^"'\n]*["']\s*(\+|\.(?!\s*["']))\s*\$?[A-Za-z_]|`[^`\n]*\b(select\s[^`\n]*\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^`\n]*\$\{|\$@?"[^"\n]*\b(select\s[^"\n]*\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^"\n]*\{[A-Za-z_]|f["'][^"'\n]*\b(select\s[^"'\n]*\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^"'\n]*\{[A-Za-z_]|"[^"\n]*\b(select\s[^"\n]*\bfrom|insert\s+into|update\s+\w+\s+set|delete\s+from)\b[^"\n]*(\$[A-Za-z_]|#\{))''',
      'MEDIUM', 89, conf='LOW', boost=(USER_INPUT, 'HIGH', 'MEDIUM')),
    R('auth-anonymous', 'Explicitly anonymous / public endpoint (review access control)', 'any',
      r'(@PermitAll\b|\.permitAll\s*\(\s*\)|\[AllowAnonymous\]|\.AllowAnonymous\s*\(|@login_not_required|skip_before_action\s+:authenticate\w*|->withoutMiddleware\s*\(\s*["\']auth|@Public\s*\(|@SkipAuth|@AllowAnonymous)',
      'INFO', 862),
]
del R


# =========================================================================== #
# Utilities
# =========================================================================== #
_print_lock = threading.Lock()


def log(msg):
    with _print_lock:
        print(msg, flush=True)


class ToolError(Exception):
    pass


def run_cmd(cmd, cwd=None, env=None, timeout=1800, stdin_devnull=True):
    e = dict(os.environ)
    if env:
        e.update(env)
    try:
        p = subprocess.run(cmd, cwd=cwd, env=e, timeout=timeout,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           stdin=subprocess.DEVNULL if stdin_devnull else None)
    except subprocess.TimeoutExpired:
        raise ToolError('timeout after %ds' % timeout)
    except OSError as ex:
        raise ToolError('cannot execute %s: %s' % (cmd[0], ex))
    return p.returncode, p.stdout.decode('utf-8', 'replace'), p.stderr.decode('utf-8', 'replace')


def load_json(text):
    text = (text or '').strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except ValueError:
        i = min([x for x in (text.find('{'), text.find('[')) if x >= 0] or [-1])
        if i > 0:
            try:
                return json.loads(text[i:])
            except ValueError:
                return None
    return None


def last_line(text, n=300):
    lines = [l for l in (text or '').strip().splitlines() if l.strip()]
    return (lines[-1] if lines else '')[:n]


def which_any(names):
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def raw_finding(tool, path, line, rule, title, message, severity, confidence='MEDIUM', cwe=None,
                refs=None, fix=None, end_line=None, base=None):
    try:
        line = int(str(line).split('-')[0]) if line not in (None, '') else 0
    except ValueError:
        line = 0
    try:
        end_line = int(str(end_line).split('-')[-1]) if end_line not in (None, '') else line
    except ValueError:
        end_line = line
    return dict(tool=tool, path=path, base=base, line=line, end_line=max(end_line, line),
                rule=str(rule or ''), title=(title or '').strip(), message=(message or '').strip(),
                severity=norm_sev(severity), confidence=norm_conf(confidence), cwes=parse_cwes(cwe),
                refs=[r for r in (refs or []) if r], fix=(fix or '').strip())


# =========================================================================== #
# Context shared by tool runners
# =========================================================================== #
class Ctx(object):
    def __init__(self, root, stage, work, records, args):
        self.root, self.stage, self.work, self.records, self.args = root, stage, work, records, args
        self.exts = Counter(r['ext'] for r in records)
        self.groups = set()
        for r in records:
            self.groups |= file_groups(r)
        self.timeout = args.tool_timeout

    def has(self, *exts):
        return any(self.exts.get(e) for e in exts)

    def files_with(self, *exts):
        return [os.path.join(self.stage, r['path']) for r in self.records if r['ext'] in exts]


def chunks(seq, n=200):
    for i in range(0, len(seq), n):
        yield seq[i:i + n]


# =========================================================================== #
# Tool runners
# =========================================================================== #
SEMGREP_BASE = ['p/security-audit', 'p/owasp-top-ten', 'p/cwe-top-25', 'p/secrets']
SEMGREP_LANG = [  # (extensions, registry pack, folder in semgrep-rules repo)
    (('.py', '.pyw'), 'p/python', 'python'),
    (('.js', '.mjs', '.cjs', '.jsx', '.vue', '.svelte', '.ejs'), 'p/javascript', 'javascript'),
    (('.ts', '.tsx', '.mts', '.cts'), 'p/typescript', 'typescript'),
    (('.jsx', '.tsx'), 'p/react', None),
    (('.java', '.jsp', '.jspx'), 'p/java', 'java'),
    (('.kt', '.kts'), 'p/kotlin', 'kotlin'),
    (('.go',), 'p/golang', 'go'),
    (('.rb', '.erb', '.rake'), 'p/ruby', 'ruby'),
    (('.php', '.phtml', '.inc', '.blade.php'), 'p/php', 'php'),
    (('.cs', '.cshtml', '.razor'), 'p/csharp', 'csharp'),
    (('.c', '.h', '.cpp', '.cc', '.cxx', '.hpp'), 'p/c', 'c'),
    (('.scala',), 'p/scala', 'scala'),
    (('.rs',), 'p/rust', 'rust'),
    (('.swift',), None, 'swift'),
    (('.sh', '.bash'), None, 'bash'),
    (('.sol',), None, 'solidity'),
    (('.ex', '.exs'), None, 'elixir'),
    (('.html', '.htm', '.jsp', '.twig', '.hbs', '.ejs', '.erb', '.vue'), None, 'html'),
]


def find_semgrep_rules_dir(args):
    cands = [getattr(args, 'semgrep_rules_dir', None), os.environ.get('SEMGREP_RULES_DIR'),
             os.path.join(os.path.dirname(os.path.abspath(__file__)), 'semgrep-rules'),
             os.path.join(os.getcwd(), 'semgrep-rules'), os.path.expanduser('~/semgrep-rules')]
    for d in cands:
        if d and os.path.isdir(os.path.join(d, 'python')) and os.path.isdir(os.path.join(d, 'generic')):
            return os.path.abspath(d)
    return None


def build_local_semgrep_rules(repo, ctx):
    """Copy only real rule files for the detected languages out of a semgrep-rules clone."""
    dest = os.path.join(ctx.work, 'semgrep-local-rules')
    wanted = set()
    for exts, _, folder in SEMGREP_LANG:
        if folder and ctx.has(*exts):
            wanted.add(folder)
    subdirs = [os.path.join(repo, w) for w in sorted(wanted)] + [os.path.join(repo, 'generic', 'secrets')]
    n = 0
    head_rx = re.compile(r'^rules\s*:', re.M)
    sec_rx = re.compile(r'^\s*category\s*:\s*["\']?security', re.M)
    for sd in subdirs:
        for dp, dn, fns in os.walk(sd):
            dn[:] = [d for d in dn if not d.startswith('.')]
            for fn in fns:
                if not fn.endswith(('.yaml', '.yml')) or '.test.' in fn or fn.endswith('.fixed.yaml'):
                    continue
                src = os.path.join(dp, fn)
                try:
                    with open(src, encoding='utf-8', errors='replace') as f:
                        txt = f.read()
                except OSError:
                    continue
                if not head_rx.search(txt) or not sec_rx.search(txt):
                    continue
                out = os.path.join(dest, os.path.relpath(src, repo))
                os.makedirs(os.path.dirname(out), exist_ok=True)
                shutil.copyfile(src, out)
                n += 1
    return dest if n else None


def expand_semgrep_configs(cfgs, ctx):
    out = []
    for cfg in cfgs:
        p = os.path.expanduser(cfg)
        if os.path.isdir(os.path.join(p, 'python')) and os.path.isdir(os.path.join(p, 'generic')):
            local = build_local_semgrep_rules(os.path.abspath(p), ctx)
            if local:
                out.append(local)
        else:
            out.append(p if os.path.exists(p) else cfg)
    return out


def parse_semgrep(data, tool='semgrep'):
    res = []
    for r in (data or {}).get('results', []):
        ex = r.get('extra', {}) or {}
        md = ex.get('metadata', {}) or {}
        refs = md.get('references') or []
        if isinstance(refs, str):
            refs = [refs]
        refs = list(refs) + [md.get('source') or md.get('shortlink')]
        sev = ex.get('severity')
        if str(md.get('impact', '')).upper() == 'HIGH' and str(md.get('likelihood', '')).upper() == 'HIGH' \
                and norm_sev(sev) == 'HIGH':
            sev = 'CRITICAL'
        rule = r.get('check_id', '')
        title = rule.rsplit('.', 1)[-1].replace('-', ' ').replace('_', ' ').capitalize()
        res.append(raw_finding(tool, r.get('path'), (r.get('start') or {}).get('line'), rule, title,
                               ex.get('message'), sev, md.get('confidence', 'MEDIUM'),
                               md.get('cwe'), refs, fix=ex.get('fix') and ('Suggested fix: ' + ex.get('fix')),
                               end_line=(r.get('end') or {}).get('line')))
    return res


_registry_state = {}


def semgrep_registry_reachable(timeout=6):
    """Quick connectivity probe so an offline run does not wait for semgrep's own retries."""
    if 'ok' not in _registry_state:
        import urllib.request
        try:
            urllib.request.urlopen(urllib.request.Request('https://semgrep.dev/c/p/secrets', method='HEAD'),
                                   timeout=timeout)
            _registry_state['ok'] = True
        except Exception as ex:           # HTTPError 4xx still proves the host is reachable
            _registry_state['ok'] = hasattr(ex, 'code') and ex.code not in (403, 407)
    return _registry_state['ok']


def run_semgrep(ctx, exe):
    name = 'opengrep' if 'opengrep' in os.path.basename(exe) else 'semgrep'
    with open(os.path.join(ctx.stage, '.semgrepignore'), 'w') as f:
        f.write('# scope already filtered by codit_estimate.py - disable default ignores\n')
    user_cfg = ctx.args.semgrep_config
    attempts = []
    if user_cfg:
        attempts.append(('--semgrep-config ' + ', '.join(os.path.basename(x.rstrip('/\\')) or x for x in user_cfg),
                         expand_semgrep_configs(user_cfg, ctx)))
    else:
        langs = [pack for exts, pack, _ in SEMGREP_LANG if pack and ctx.has(*exts)]
        if not ctx.args.semgrep_offline and semgrep_registry_reachable():
            attempts.append(('registry', SEMGREP_BASE + sorted(set(langs))))
            attempts.append(('registry-base', SEMGREP_BASE))
        repo = find_semgrep_rules_dir(ctx.args)
        if repo:
            local = build_local_semgrep_rules(repo, ctx)
            if local:
                attempts.append(('local ' + repo, [local]))
    if not attempts:
        raise ToolError('no rules: semgrep registry unreachable/disabled and no semgrep-rules clone found '
                        '(git clone https://github.com/semgrep/semgrep-rules next to this script, '
                        'or pass --semgrep-config / --semgrep-rules-dir)')
    errors = []
    for label, cfgs in attempts:
        cmd = [exe, 'scan', '--json', '--metrics=off', '--disable-version-check', '--no-git-ignore',
               '--timeout', '30', '--max-target-bytes', '5000000', '--quiet']
        if ctx.args.jobs_per_tool:
            cmd += ['--jobs', str(ctx.args.jobs_per_tool)]
        for cf in cfgs:
            cmd += ['--config', cf]
        cmd.append(ctx.stage)
        rc, out, err = run_cmd(cmd, timeout=ctx.timeout,
                               env={'SEMGREP_SEND_METRICS': 'off', 'SEMGREP_ENABLE_VERSION_CHECK': '0'})
        data = load_json(out)
        if isinstance(data, dict) and 'results' in data and (data['results'] or rc == 0):
            return parse_semgrep(data, name), 'rules: %s' % label
        msg = ''
        if isinstance(data, dict) and data.get('errors'):
            msg = str(data['errors'][0].get('message', ''))[:200]
        errors.append('%s: %s' % (label, msg or last_line(err) or 'exit %d' % rc))
    raise ToolError(' | '.join(errors) +
                    ' -> for offline use: git clone https://github.com/semgrep/semgrep-rules '
                    'and pass --semgrep-config ./semgrep-rules')


def run_bandit(ctx, exe):
    rc, out, err = run_cmd([exe, '-r', ctx.stage, '-f', 'json', '-q', '--exit-zero'],
                           timeout=ctx.timeout)
    data = load_json(out)
    if data is None:
        rc, out, err = run_cmd([exe, '-r', ctx.stage, '-f', 'json', '-q'], timeout=ctx.timeout)
        data = load_json(out)
    if data is None:
        raise ToolError(last_line(err) or 'no JSON output')
    res = []
    for r in data.get('results', []):
        res.append(raw_finding('bandit', r.get('filename'), r.get('line_number'), r.get('test_id'),
                               r.get('test_name', '').replace('_', ' ').capitalize(), r.get('issue_text'),
                               r.get('issue_severity'), r.get('issue_confidence'),
                               (r.get('issue_cwe') or {}).get('id'), [r.get('more_info')]))
    return res, None


def run_gosec(ctx, exe):
    mods = []
    for dp, dn, fns in os.walk(ctx.stage):
        if 'go.mod' in fns:
            mods.append(dp)
    if not mods:
        with open(os.path.join(ctx.stage, 'go.mod'), 'w') as f:
            f.write('module sastscan\n\ngo 1.20\n')
        mods = [ctx.stage]
    res, notes = [], []
    for m in mods:
        rc, out, err = run_cmd([exe, '-fmt=json', '-no-fail', '-quiet', './...'], cwd=m,
                               timeout=ctx.timeout, env={'GOTOOLCHAIN': 'local', 'GOFLAGS': '-mod=mod'})
        data = load_json(out)
        if data is None:
            notes.append(last_line(err))
            continue
        for r in data.get('Issues') or []:
            res.append(raw_finding('gosec', r.get('file'), r.get('line'), r.get('rule_id'),
                                   r.get('details'), r.get('details'), r.get('severity'),
                                   r.get('confidence'), (r.get('cwe') or {}).get('id'),
                                   [(r.get('cwe') or {}).get('url')]))
    if not res and notes and len(notes) == len(mods):
        raise ToolError(notes[0] or 'no JSON output')
    return res, None


def run_brakeman(ctx, exe):
    apps = []
    for dp, dn, fns in os.walk(ctx.stage):
        if os.path.isfile(os.path.join(dp, 'config', 'application.rb')) or \
                os.path.isfile(os.path.join(dp, 'config', 'environment.rb')):
            apps.append(dp)
            dn[:] = []
    if not apps:
        return None, 'no Rails application root (config/application.rb) in scope'
    res = []
    for app in apps:
        rc, out, err = run_cmd([exe, '-q', '-f', 'json', '--no-pager', '--no-exit-on-warn',
                                '--no-exit-on-error', '-p', app], timeout=ctx.timeout)
        data = load_json(out)
        if data is None:
            raise ToolError(last_line(err) or 'no JSON output')
        for w in data.get('warnings', []):
            conf = w.get('confidence')
            sev = {'High': 'HIGH', 'Medium': 'MEDIUM', 'Weak': 'LOW'}.get(conf, 'MEDIUM')
            res.append(raw_finding('brakeman', os.path.join(app, w.get('file', '')), w.get('line'),
                                   w.get('check_name') or w.get('warning_type'), w.get('warning_type'),
                                   w.get('message'), sev, conf, w.get('cwe_id'), [w.get('link')]))
    return res, None


def _parse_libsast(data, tool, sections):
    res = []
    for sec in sections:
        for rule_id, body in ((data or {}).get(sec) or {}).items():
            md = body.get('metadata', {}) or {}
            for f in body.get('files', []) or []:
                lines = f.get('match_lines') or [0, 0]
                res.append(raw_finding(tool, f.get('file_path'), lines[0], rule_id,
                                       rule_id.replace('_', ' ').replace('-', ' ').capitalize(),
                                       md.get('description'), md.get('severity'), 'MEDIUM',
                                       md.get('cwe'), [md.get('ref') or md.get('reference')],
                                       end_line=lines[-1] if lines else None))
    return res


def run_njsscan(ctx, exe):
    out_f = os.path.join(ctx.work, 'njsscan.json')
    rc, out, err = run_cmd([exe, '--json', '-o', out_f, ctx.stage], timeout=ctx.timeout)
    data = None
    if os.path.isfile(out_f):
        with open(out_f, encoding='utf-8', errors='replace') as f:
            data = load_json(f.read())
    if data is None:
        raise ToolError(last_line(err) or last_line(out) or 'no JSON output')
    return _parse_libsast(data, 'njsscan', ('nodejs', 'templates')), None


def run_mobsfscan(ctx, exe):
    out_f = os.path.join(ctx.work, 'mobsfscan.json')
    rc, out, err = run_cmd([exe, '--json', '-o', out_f, ctx.stage], timeout=ctx.timeout)
    data = None
    if os.path.isfile(out_f):
        with open(out_f, encoding='utf-8', errors='replace') as f:
            data = load_json(f.read())
    if data is None:
        raise ToolError(last_line(err) or last_line(out) or 'no JSON output')
    return _parse_libsast(data, 'mobsfscan', ('results',)), None


def run_flawfinder(ctx, exe):
    rc, out, err = run_cmd([exe, '--csv', '--quiet', '--dataonly', '--minlevel=1', ctx.stage],
                           timeout=ctx.timeout)
    if not out.strip():
        if rc != 0:
            raise ToolError(last_line(err) or 'exit %d' % rc)
        return [], None
    res = []
    for row in csv.DictReader(out.splitlines()):
        try:
            lvl = int(row.get('Level') or row.get('DefaultLevel') or 1)
        except ValueError:
            lvl = 1
        sev = 'HIGH' if lvl >= 4 else 'MEDIUM' if lvl == 3 else 'LOW'
        name = row.get('Name', '')
        res.append(raw_finding('flawfinder', row.get('File'), row.get('Line'),
                               row.get('RuleId') or name, '%s: %s' % (row.get('Category', ''), name),
                               row.get('Warning'), sev, 'LOW' if lvl <= 2 else 'MEDIUM', row.get('CWEs'),
                               [row.get('HelpUri')],
                               fix=row.get('Suggestion') and 'Flawfinder suggestion: ' + row.get('Suggestion')))
    return res, None


def run_cppcheck(ctx, exe):
    cmd = [exe, '--enable=warning,portability', '--xml', '--xml-version=2', '-q',
           '--suppress=missingIncludeSystem', '--suppress=missingInclude', '--suppress=unmatchedSuppression',
           '-j', str(max(1, (os.cpu_count() or 2) // 2)), ctx.stage]
    rc, out, err = run_cmd(cmd, timeout=ctx.timeout)
    try:
        root = ET.fromstring(err[err.find('<?xml'):] if '<?xml' in err else err)
    except ET.ParseError:
        raise ToolError(last_line(err) or 'no XML output')
    res = []
    skip = {'missingInclude', 'missingIncludeSystem', 'toomanyconfigs', 'syntaxError',
            'unknownMacro', 'checkersReport', 'normalCheckLevelMaxBranches', 'internalAstError'}
    for e in root.iter('error'):
        if e.get('id') in skip or e.get('severity') not in ('error', 'warning', 'portability'):
            continue
        loc = e.find('location')
        if loc is None:
            continue
        sev = {'error': 'HIGH', 'warning': 'MEDIUM', 'portability': 'LOW'}[e.get('severity')]
        conf = 'LOW' if e.get('inconclusive') == 'true' else 'MEDIUM'
        res.append(raw_finding('cppcheck', loc.get('file'), loc.get('line'), e.get('id'), e.get('id'),
                               e.get('verbose') or e.get('msg'), sev, conf, e.get('cwe')))
    return res, None


SC_SECURITY = {2086: (78, 'LOW'), 2046: (78, 'LOW'), 2048: (78, 'LOW'), 2294: (95, 'MEDIUM'),
               2091: (78, 'LOW'), 2029: (78, 'LOW'), 2087: (78, 'LOW'), 2115: (22, 'MEDIUM'),
               2164: (754, 'LOW'), 2216: (78, 'LOW'), 2156: (78, 'LOW')}


def run_shellcheck(ctx, exe):
    files = ctx.files_with('.sh', '.bash', '.ksh')
    res = []
    for ch in chunks(files):
        rc, out, err = run_cmd([exe, '-f', 'json1', '-S', 'info'] + ch, timeout=ctx.timeout)
        data = load_json(out)
        if data is None:
            if rc not in (0, 1):
                raise ToolError(last_line(err) or 'exit %d' % rc)
            continue
        for cm in data.get('comments', []):
            code = cm.get('code')
            if code not in SC_SECURITY:
                continue
            cwe, sev = SC_SECURITY[code]
            res.append(raw_finding('shellcheck', cm.get('file'), cm.get('line'), 'SC%d' % code,
                                   'SC%d: %s' % (code, (cm.get('message') or '')[:80]), cm.get('message'),
                                   sev, 'MEDIUM', cwe,
                                   ['https://www.shellcheck.net/wiki/SC%d' % code], end_line=cm.get('endLine')))
    return res, None


def run_phpcs(ctx, exe):
    rc, out, err = run_cmd([exe, '-i'], timeout=60)
    if 'Security' not in out:
        return None, 'phpcs installed but the "Security" standard (pheromone/phpcs-security-audit) is missing'
    rc, out, err = run_cmd([exe, '--standard=Security', '--report=json', '-q', '--runtime-set',
                            'ParanoiaMode', '1', '--extensions=php,inc,phtml,php5,php7', ctx.stage],
                           timeout=ctx.timeout)
    data = load_json(out)
    if data is None:
        raise ToolError(last_line(err) or last_line(out) or 'no JSON output')
    res = []
    for path, body in (data.get('files') or {}).items():
        for m in body.get('messages', []):
            sev = 'MEDIUM' if m.get('type') == 'ERROR' else 'LOW'
            src = m.get('source', '')
            res.append(raw_finding('phpcs-security', path, m.get('line'), src,
                                   src.split('.')[-1] if src else 'phpcs', m.get('message'), sev, 'LOW',
                                   guess_cwe(src, m.get('message'))))
    return res, None


def run_progpilot(ctx, exe):
    rc, out, err = run_cmd([exe, ctx.stage], timeout=ctx.timeout)
    data = load_json(out)
    if data is None:
        raise ToolError(last_line(err) or last_line(out) or 'no JSON output')
    res = []

    def first(v):
        return v[0] if isinstance(v, list) and v else v

    for r in data if isinstance(data, list) else []:
        src = '%s (line %s)' % (first(r.get('source_name')), first(r.get('source_line')))
        msg = 'Tainted data from %s reaches sink %s.' % (src, r.get('sink_name'))
        res.append(raw_finding('progpilot', r.get('sink_file') or first(r.get('source_file')),
                               r.get('sink_line') or first(r.get('source_line')), r.get('vuln_rule') or r.get('vuln_name'),
                               str(r.get('vuln_name', '')).replace('_', ' ').capitalize(), msg, 'HIGH',
                               'MEDIUM', r.get('vuln_cwe')))
    return res, None


def parse_sarif(data, tool, base):
    res = []
    for run in (data or {}).get('runs', []) or []:
        drv = ((run.get('tool') or {}).get('driver') or {})
        tname = tool or drv.get('name') or 'sarif'
        rules = {}
        for rr in (drv.get('rules') or []):
            rules[rr.get('id')] = rr
        for ext in ((run.get('tool') or {}).get('extensions') or []):
            for rr in ext.get('rules') or []:
                rules.setdefault(rr.get('id'), rr)
        rule_list = drv.get('rules') or []
        for r in run.get('results', []) or []:
            rid = r.get('ruleId') or ((r.get('rule') or {}).get('id'))
            rd = rules.get(rid)
            if rd is None and isinstance(r.get('ruleIndex'), int) and r['ruleIndex'] < len(rule_list):
                rd = rule_list[r['ruleIndex']]
            rd = rd or {}
            props = rd.get('properties') or {}
            tags = props.get('tags') or []
            cwe = parse_cwes([t for t in tags if 'cwe' in str(t).lower()]) or parse_cwes(props.get('cwe'))
            ssev = props.get('security-severity')
            sev = None
            if ssev is not None:
                try:
                    v = float(ssev)
                    sev = 'CRITICAL' if v >= 9 else 'HIGH' if v >= 7 else 'MEDIUM' if v >= 4 else 'LOW'
                except ValueError:
                    pass
            if sev is None:
                lvl = r.get('level') or (rd.get('defaultConfiguration') or {}).get('level') or 'warning'
                sev = (r.get('properties') or {}).get('severity') or props.get('severity') or \
                    {'error': 'HIGH', 'warning': 'MEDIUM', 'note': 'LOW', 'none': 'INFO'}.get(lvl, 'MEDIUM')
            conf = {'very-high': 'HIGH', 'high': 'HIGH', 'medium': 'MEDIUM', 'low': 'LOW'}.get(
                str(props.get('precision', '')).lower(), 'MEDIUM')
            title = ((rd.get('shortDescription') or {}).get('text') or rd.get('name') or rid or '')
            msg = (r.get('message') or {}).get('text') or ((rd.get('fullDescription') or {}).get('text'))
            locs = r.get('locations') or [{}]
            pl = (locs[0] or {}).get('physicalLocation') or {}
            uri = (pl.get('artifactLocation') or {}).get('uri')
            reg = pl.get('region') or {}
            res.append(raw_finding(tname, uri, reg.get('startLine'), rid, title, msg, sev, conf, cwe,
                                   [rd.get('helpUri')], end_line=reg.get('endLine'), base=base))
    return res


def run_devskim(ctx, exe):
    out_f = os.path.join(ctx.work, 'devskim.sarif')
    rc, out, err = run_cmd([exe, 'analyze', '-I', ctx.stage, '-O', out_f, '-f', 'sarif'],
                           timeout=ctx.timeout)
    if not os.path.isfile(out_f):
        raise ToolError(last_line(err) or last_line(out) or 'no SARIF output')
    with open(out_f, encoding='utf-8', errors='replace') as f:
        data = load_json(f.read())
    return parse_sarif(data, 'devskim', ctx.stage), None


CODEQL_LANGS = [  # (codeql language, extensions, build mode)
    ('python', ('.py',), 'none'),
    ('javascript', ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.vue'), 'none'),
    ('ruby', ('.rb', '.erb'), 'none'),
    ('java', ('.java', '.kt'), 'none'),
    ('csharp', ('.cs', '.cshtml', '.razor'), 'none'),
    ('go', ('.go',), 'autobuild'),
]


def run_codeql(ctx, exe):
    res, notes = [], []
    for lang, exts, mode in CODEQL_LANGS:
        if not ctx.has(*exts):
            continue
        db = os.path.join(ctx.work, 'codeql-db-' + lang)
        sarif = os.path.join(ctx.work, 'codeql-%s.sarif' % lang)
        log('  %s codeql: building %s database' % (c('..', C.GREY), lang))
        rc, out, err = run_cmd([exe, 'database', 'create', db, '--language=' + lang, '--source-root',
                                ctx.stage, '--build-mode=' + mode, '--overwrite', '--threads=0'],
                               timeout=ctx.timeout)
        if rc != 0:
            notes.append('%s: %s' % (lang, last_line(err)))
            continue
        suite = 'codeql/%s-queries:codeql-suites/%s-security-extended.qls' % (lang, lang)
        rc, out, err = run_cmd([exe, 'database', 'analyze', db, suite, '--format=sarif-latest',
                                '--output', sarif, '--threads=0', '--download'], timeout=ctx.timeout)
        if rc != 0 or not os.path.isfile(sarif):
            notes.append('%s: %s' % (lang, last_line(err)))
            continue
        with open(sarif, encoding='utf-8', errors='replace') as f:
            res += parse_sarif(load_json(f.read()), 'codeql', ctx.stage)
    if notes and not res:
        raise ToolError('; '.join(notes))
    return res, '; '.join(notes) or None


def run_gitleaks(ctx, exe):
    out_f = os.path.join(ctx.work, 'gitleaks.json')
    base = ['--report-format', 'json', '--report-path', out_f, '--redact', '--exit-code', '0', '--no-banner']
    rc, out, err = run_cmd([exe, 'dir', ctx.stage] + base, timeout=ctx.timeout)
    if not os.path.isfile(out_f):
        rc, out, err = run_cmd([exe, 'detect', '--no-git', '--source', ctx.stage] + base, timeout=ctx.timeout)
    if not os.path.isfile(out_f):
        raise ToolError(last_line(err) or 'no report produced')
    with open(out_f, encoding='utf-8', errors='replace') as f:
        data = load_json(f.read()) or []
    res = []
    for r in data:
        res.append(raw_finding('gitleaks', r.get('File'), r.get('StartLine'), r.get('RuleID'),
                               r.get('Description') or r.get('RuleID'),
                               'Secret detected by rule %s (value redacted).' % r.get('RuleID'),
                               'HIGH', 'HIGH', 798, base=ctx.stage))
    return res, None


def run_trufflehog(ctx, exe):
    cmd = [exe, 'filesystem', ctx.stage, '--json', '--no-update']
    if not ctx.args.verify_secrets:
        cmd.append('--no-verification')
    rc, out, err = run_cmd(cmd, timeout=ctx.timeout)
    res = []
    for ln in out.splitlines():
        ln = ln.strip()
        if not ln.startswith('{'):
            continue
        try:
            r = json.loads(ln)
        except ValueError:
            continue
        fsd = (((r.get('SourceMetadata') or {}).get('Data') or {}).get('Filesystem') or {})
        if not fsd:
            continue
        verified = r.get('Verified')
        res.append(raw_finding('trufflehog', fsd.get('file'), fsd.get('line'), r.get('DetectorName'),
                               '%s credential%s' % (r.get('DetectorName'), ' (VERIFIED LIVE)' if verified else ''),
                               'Secret of type %s detected%s.' % (r.get('DetectorName'),
                                                                  ' and verified as valid' if verified else ''),
                               'CRITICAL' if verified else 'HIGH', 'HIGH', 798))
    if rc not in (0, 183) and not res and err.strip() and 'error' in err.lower():
        raise ToolError(last_line(err))
    return res, None


class Tool(object):
    def __init__(self, name, bins, runner, exts=None, install='', desc='', optin=False):
        self.name, self.bins, self.runner, self.exts = name, bins, runner, exts
        self.install, self.desc, self.optin = install, desc, optin


C_EXTS = ('.c', '.h', '.cpp', '.cc', '.cxx', '.hpp', '.hh')
TOOLS = [
    Tool('semgrep', ['semgrep', 'opengrep'], run_semgrep, None, 'pip install semgrep',
         'multi-language rules (registry packs or local semgrep-rules clone)'),
    Tool('bandit', ['bandit'], run_bandit, ('.py', '.pyw'), 'pip install bandit', 'Python'),
    Tool('gosec', ['gosec'], run_gosec, ('.go',),
         'go install github.com/securego/gosec/v2/cmd/gosec@latest', 'Go'),
    Tool('brakeman', ['brakeman'], run_brakeman, ('.rb', '.erb', '.haml', '.slim'),
         'gem install brakeman', 'Ruby on Rails'),
    Tool('njsscan', ['njsscan'], run_njsscan, ('.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.ejs', '.hbs',
                                                '.handlebars', '.pug', '.jade', '.njk', '.vue'),
         'pip install njsscan', 'Node.js + JS templates'),
    Tool('mobsfscan', ['mobsfscan'], run_mobsfscan, ('.java', '.kt', '.swift', '.m', '.mm'),
         'pip install mobsfscan', 'Android / iOS source'),
    Tool('flawfinder', ['flawfinder'], run_flawfinder, C_EXTS, 'pip install flawfinder', 'C / C++'),
    Tool('cppcheck', ['cppcheck'], run_cppcheck, C_EXTS, 'apt install cppcheck | brew install cppcheck',
         'C / C++ (warnings with CWE)'),
    Tool('shellcheck', ['shellcheck'], run_shellcheck, ('.sh', '.bash', '.ksh'),
         'apt install shellcheck | brew install shellcheck', 'shell (security-relevant codes only)'),
    Tool('phpcs-security', ['phpcs'], run_phpcs, ('.php', '.phtml', '.inc'),
         'composer global require squizlabs/php_codesniffer pheromone/phpcs-security-audit '
         '&& phpcs --config-set installed_paths ~/.composer/vendor/pheromone/phpcs-security-audit',
         'PHP (phpcs-security-audit)'),
    Tool('progpilot', ['progpilot', 'progpilot.phar'], run_progpilot, ('.php', '.phtml', '.inc'),
         'download progpilot.phar from github.com/designsecurity/progpilot/releases, chmod +x, put in PATH',
         'PHP taint analysis'),
    Tool('devskim', ['devskim'], run_devskim, None,
         'dotnet tool install --global Microsoft.CST.DevSkim.CLI', 'multi-language (Microsoft)'),
    Tool('codeql', ['codeql'], run_codeql,
         ('.py', '.js', '.mjs', '.jsx', '.ts', '.tsx', '.rb', '.java', '.kt', '.cs', '.go'),
         'download the CodeQL bundle from github.com/github/codeql-action/releases',
         'deep data-flow analysis (slow, enable with --codeql)', optin=True),
    Tool('gitleaks', ['gitleaks'], run_gitleaks, None,
         'brew install gitleaks | github.com/gitleaks/gitleaks/releases', 'secrets'),
    Tool('trufflehog', ['trufflehog'], run_trufflehog, None,
         'brew install trufflehog | github.com/trufflesecurity/trufflehog/releases', 'secrets'),
]
PIP_TOOLS = {'semgrep': 'semgrep', 'bandit': 'bandit', 'njsscan': 'njsscan',
             'mobsfscan': 'mobsfscan', 'flawfinder': 'flawfinder'}


# =========================================================================== #
# Built-in engine run
# =========================================================================== #
def run_builtin(ctx, records, ignore_rules):
    res = []
    rules = [r for r in BUILTIN_RULES if r.id not in ignore_rules]
    for rec in records:
        groups = file_groups(rec)
        applicable = [r for r in rules if r.langs & groups]
        if not applicable:
            continue
        path = os.path.join(ctx.root, rec['path'])
        try:
            with open(path, 'rb') as f:
                text = f.read().decode('utf-8', 'replace')
        except OSError:
            continue
        raw_lines = text.split('\n')
        code_lines = AS.code_view(text, rec['kind'], rec['grammar'])
        code_text = '\n'.join(code_lines)
        for rule in applicable:
            lines = raw_lines if rule.raw else code_lines
            blob = text if rule.raw else code_text
            if not rule.rx.search(blob):
                continue
            if rule.only_if_file and not rule.only_if_file.search(code_text):
                continue
            if rule.unless_file and rule.unless_file.search(code_text):
                continue
            hits = 0
            for i, line in enumerate(lines):
                if len(line) > 3000:
                    continue
                m = rule.rx.search(line)
                if not m:
                    continue
                if rule.unless_line and rule.unless_line.search(line):
                    continue
                if rule.validate and not rule.validate(m):
                    continue
                sev, conf = rule.sev, rule.conf
                if rule.boost and rule.boost[0].search(line):
                    if SEV_RANK[rule.boost[1]] > SEV_RANK[sev]:
                        sev = rule.boost[1]
                    if CONF_RANK[rule.boost[2]] > CONF_RANK[conf]:
                        conf = rule.boost[2]
                msg = rule.title + '.'
                if rule.id == 'hardcoded-secret':
                    msg = 'Value assigned to "%s" looks like a hard-coded secret.' % m.group('key')
                res.append(raw_finding('builtin', rec['path'], i + 1, rule.id, rule.title, msg, sev, conf,
                                       rule.cwe, base=ctx.root))
                hits += 1
                if hits >= ctx.args.max_per_rule:
                    break
    return res


# =========================================================================== #
# Normalisation, scope filtering, merge
# =========================================================================== #
def to_rel(path, anchors):
    if not path:
        return None
    p = str(path)
    if p.startswith('file://'):
        from urllib.parse import unquote, urlparse
        p = unquote(urlparse(p).path)
        if os.name == 'nt' and re.match(r'^/[A-Za-z]:', p):
            p = p[1:]
    for a in anchors:
        cand = p if os.path.isabs(p) else os.path.join(a, p)
        cand = os.path.realpath(cand)
        ra = os.path.realpath(a)
        if cand == ra or cand.startswith(ra + os.sep):
            return os.path.normpath(os.path.relpath(cand, ra))
    if not os.path.isabs(p):
        return os.path.normpath(p.lstrip('./\\') if p.startswith(('./', '.\\')) else p)
    return None


TOOL_PRIORITY = ['codeql', 'progpilot', 'semgrep', 'opengrep', 'brakeman', 'gosec', 'bandit', 'njsscan',
                 'mobsfscan', 'phpcs-security', 'devskim', 'flawfinder', 'cppcheck', 'shellcheck',
                 'gitleaks', 'trufflehog', 'builtin']


def tool_prio(t):
    return TOOL_PRIORITY.index(t) if t in TOOL_PRIORITY else len(TOOL_PRIORITY) - 1


SECRET_MASK_RXS = [
    re.compile(r'''(["'`])([^"'`\s]{6,})\1'''),
    re.compile(r'''(\b(?:AKIA|ASIA|ghp_|gho_|ghs_|ghu_|github_pat_|glpat-|xox[abposr]-|AIza|sk_live_|rk_live_|SG\.|eyJ|npm_|sk-))([A-Za-z0-9_\-./+=]{6,})'''),
    re.compile(r'''(://[^\s:/@"']+:)([^\s@"'/]+)(@)'''),
    re.compile(r'''((?:password|pwd)\s*=\s*)([^;"'\s]{3,})''', re.I),
]


def mask_secret_line(line):
    def m0(m):
        v = m.group(2)
        return m.group(1) + v[:3] + '*' * min(12, max(4, len(v) - 3)) + m.group(1)

    line = SECRET_MASK_RXS[0].sub(m0, line)
    line = SECRET_MASK_RXS[1].sub(lambda m: m.group(1) + m.group(2)[:2] + '*' * 10, line)
    line = SECRET_MASK_RXS[2].sub(lambda m: m.group(1) + '*****' + m.group(3), line)
    line = SECRET_MASK_RXS[3].sub(lambda m: m.group(1) + '*****', line)
    return line


_file_cache = {}


def file_lines(root, rel):
    if rel not in _file_cache:
        try:
            with open(os.path.join(root, rel), 'rb') as f:
                _file_cache[rel] = f.read().decode('utf-8', 'replace').split('\n')
        except OSError:
            _file_cache[rel] = []
    return _file_cache[rel]


def make_snippet(root, rel, line, end_line, context, secret):
    lines = file_lines(root, rel)
    if not lines or line <= 0:
        return []
    end_line = min(max(end_line, line), line + 6)
    a, b = max(1, line - context), min(len(lines), end_line + context)
    out = []
    for n in range(a, b + 1):
        t = lines[n - 1].rstrip('\r')
        if len(t) > 400:
            t = t[:400] + ' ...'
        if secret:
            t = mask_secret_line(t)
        out.append([n, t, line <= n <= end_line])
    return out


def merge_findings(raws, root, scope, args):
    buckets = {}
    for f in raws:
        cwe = choose_cwe(f)
        key_cwe = kb_key(cwe) or cwe
        f['cwe'] = cwe
        family = key_cwe if key_cwe else 'rule:' + f['tool'] + ':' + f['rule']
        key = (f['rel'], f['line'], family)
        buckets.setdefault(key, []).append(f)

    merged = []
    for (rel, line, family), group in buckets.items():
        group.sort(key=lambda g: (tool_prio(g['tool']), -SEV_RANK[g['severity']]))
        lead = group[0]
        tools = sorted({g['tool'] for g in group}, key=tool_prio)
        sev = max((g['severity'] for g in group), key=lambda s: SEV_RANK[s])
        conf = max((g['confidence'] for g in group), key=lambda s: CONF_RANK[s])
        if len(tools) >= 2:
            conf = 'HIGH'
        cwe = next((g['cwe'] for g in group if g['cwe']), None)
        kb = KB.get(kb_key(cwe)) if cwe else None
        kbv = kb or GENERIC_KB
        messages, seen = [], set()
        for g in group:
            m = g['message'] or g['title']
            if m and m.lower() not in seen:
                seen.add(m.lower())
                messages.append('[%s] %s' % (g['tool'], m))
        fixes = [g['fix'] for g in group if g['fix']]
        refs, rseen = [], set()
        for r in [x for g in group for x in g['refs']] + \
                 ([kbv['ref']] if kbv.get('ref') else []) + \
                 (['https://cwe.mitre.org/data/definitions/%d.html' % cwe] if cwe else []):
            if r and r not in rseen:
                rseen.add(r)
                refs.append(r)
        secret = (kb_key(cwe) == 798) or any(g['tool'] in ('gitleaks', 'trufflehog') for g in group)
        title = lead['title'] or kbv['name']
        if kb and kb['name'].lower() not in title.lower():
            category = kb['name']
        else:
            category = kbv['name'] if kb else (lead['title'] or 'Security weakness')
        merged.append(dict(
            id='', severity=sev, confidence=conf, category=category, title=title,
            cwe=cwe, owasp=kbv['owasp'], file=rel.replace(os.sep, '/'), line=line,
            end_line=max(g['end_line'] for g in group),
            tools=tools, rules=sorted({'%s:%s' % (g['tool'], g['rule']) for g in group}),
            description=messages, explanation=kbv['explain'],
            recommendation=kbv['fix'] + ((' ' + ' '.join(fixes)) if fixes else ''),
            references=refs, secret=secret,
            snippet=make_snippet(root, rel, line, max(g['end_line'] for g in group), args.context, secret)))

    min_rank = SEV_RANK[args.min_severity]
    merged = [m for m in merged if SEV_RANK[m['severity']] >= min_rank]
    merged.sort(key=lambda m: (-SEV_RANK[m['severity']], -CONF_RANK[m['confidence']], m['file'], m['line']))
    for i, m in enumerate(merged, 1):
        m['id'] = 'F-%04d' % i
    return merged


def hotspots(findings, records):
    lines_by_file = {r['path'].replace(os.sep, '/'): r['auditable'] for r in records}
    per_file = defaultdict(lambda: Counter())
    per_dir = defaultdict(lambda: Counter())
    for f in findings:
        per_file[f['file']][f['severity']] += 1
        d = os.path.dirname(f['file']) or '(root)'
        per_dir[d][f['severity']] += 1

    def rows(table, size_of):
        out = []
        for k, cnt in table.items():
            score = sum(SEV_WEIGHT[s] * n for s, n in cnt.items())
            size = size_of(k)
            out.append(dict(name=k, score=score, total=sum(cnt.values()),
                            counts={s: cnt.get(s, 0) for s in SEVERITIES}, lines=size,
                            density=round(1000.0 * score / size, 1) if size else None))
        out.sort(key=lambda r: (-r['score'], -r['total'], r['name']))
        return out

    dir_lines = Counter()
    for p, n in lines_by_file.items():
        dir_lines[os.path.dirname(p) or '(root)'] += n
    return rows(per_file, lambda k: lines_by_file.get(k, 0)), rows(per_dir, lambda k: dir_lines.get(k, 0))


# =========================================================================== #
# Reports
# =========================================================================== #
def write_json(path, meta, findings, hot_files, hot_dirs):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(dict(meta=meta, findings=findings, hotspots=dict(files=hot_files, directories=hot_dirs)),
                  f, indent=2)


def write_csv(path, findings):
    cols = ['id', 'severity', 'confidence', 'category', 'title', 'cwe', 'owasp', 'file', 'line', 'tools',
            'rules', 'description', 'explanation', 'recommendation', 'references']
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f)
        w.writerow(cols)
        for x in findings:
            w.writerow([x['id'], x['severity'], x['confidence'], x['category'], x['title'],
                        ('CWE-%d' % x['cwe']) if x['cwe'] else '', x['owasp'], x['file'], x['line'],
                        ', '.join(x['tools']), ', '.join(x['rules']), ' | '.join(x['description']),
                        x['explanation'], x['recommendation'], ' '.join(x['references'])])


def write_sarif(path, meta, findings):
    rules, index = [], {}
    results = []
    for x in findings:
        rid = 'CWE-%d' % x['cwe'] if x['cwe'] else re.sub(r'[^\w.-]+', '-', x['category']).strip('-')
        if rid not in index:
            index[rid] = len(rules)
            rules.append(dict(id=rid, name=x['category'], shortDescription=dict(text=x['category']),
                              fullDescription=dict(text=x['explanation']),
                              help=dict(text=x['recommendation']),
                              helpUri=(x['references'] or [None])[-1],
                              properties=dict(tags=['security'] + (['external/cwe/cwe-%d' % x['cwe']] if x['cwe'] else []))))
        level = {'CRITICAL': 'error', 'HIGH': 'error', 'MEDIUM': 'warning'}.get(x['severity'], 'note')
        results.append(dict(
            ruleId=rid, ruleIndex=index[rid], level=level,
            message=dict(text='%s - %s' % (x['title'], ' '.join(x['description'])[:1000])),
            locations=[dict(physicalLocation=dict(artifactLocation=dict(uri=x['file'], uriBaseId='SRCROOT'),
                                                  region=dict(startLine=max(1, x['line']),
                                                              endLine=max(1, x['end_line']))))],
            properties=dict(severity=x['severity'], confidence=x['confidence'], tools=x['tools'],
                            rules=x['rules'], findingId=x['id'])))
    doc = {'$schema': 'https://json.schemastore.org/sarif-2.1.0.json', 'version': '2.1.0',
           'runs': [dict(tool=dict(driver=dict(name='codit', version=VERSION,
                                               informationUri='https://owasp.org', rules=rules)),
                         originalUriBaseIds=dict(SRCROOT=dict(uri='file://' + meta['root'].replace(os.sep, '/') + '/')),
                         results=results)]}
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2)


HTML_TEMPLATE = r'''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SAST Report</title>
<style>
:root{--bg:#f6f7f9;--panel:#fff;--text:#1d2330;--muted:#5d6678;--line:#e2e5ea;--code:#f2f4f7;
--crit:#8e1b5c;--high:#c62828;--med:#d97706;--low:#1f6feb;--info:#6b7280;--hl:#fff4cc;--accent:#2952cc}
@media (prefers-color-scheme:dark){:root{--bg:#0f1218;--panel:#171b24;--text:#e6e9ef;--muted:#9aa3b5;
--line:#2a3140;--code:#11151c;--crit:#e060a8;--high:#ff6b6b;--med:#f5a524;--low:#6ea8ff;--info:#9aa3b5;
--hl:#3a3212;--accent:#7b9cff}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1200px;margin:0 auto;padding:24px 16px 64px}
h1{font-size:24px;margin:0 0 4px}h2{font-size:17px;margin:32px 0 12px}
.sub{color:var(--muted);font-size:13px;word-break:break-all}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin-top:18px}
.card{background:var(--panel);border:1px solid var(--line);border-radius:10px;padding:12px 14px}
.card .n{font-size:26px;font-weight:700;font-variant-numeric:tabular-nums}.card .l{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.CRITICAL{--sev:var(--crit)}.HIGH{--sev:var(--high)}.MEDIUM{--sev:var(--med)}.LOW{--sev:var(--low)}.INFO{--sev:var(--info)}
.card.sev{border-left:4px solid var(--sev)}.card.sev .n{color:var(--sev)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);border-radius:10px;overflow:hidden}
th,td{text-align:left;padding:7px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{font-size:12px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;font-weight:600}
td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
.bar{height:8px;border-radius:4px;background:var(--line);min-width:80px;overflow:hidden;display:flex}
.bar span{display:block;height:100%}
.tbl-wrap{overflow-x:auto}
.filters{display:flex;flex-wrap:wrap;gap:8px;align-items:center;background:var(--panel);border:1px solid var(--line);
border-radius:10px;padding:10px 12px;position:sticky;top:0;z-index:5}
.filters label{display:flex;align-items:center;gap:4px;font-size:13px;cursor:pointer;user-select:none}
.filters input[type=search],.filters select{background:var(--bg);color:var(--text);border:1px solid var(--line);
border-radius:6px;padding:6px 8px;font:inherit;min-width:0}
.filters input[type=search]{flex:1 1 200px}
.pill{display:inline-block;font-size:11px;font-weight:700;padding:2px 7px;border-radius:999px;color:#fff;background:var(--sev);letter-spacing:.03em}
.tag{display:inline-block;font-size:11px;padding:1px 6px;border-radius:4px;border:1px solid var(--line);color:var(--muted);margin-right:4px}
details.f{background:var(--panel);border:1px solid var(--line);border-left:4px solid var(--sev);border-radius:8px;margin-top:8px}
details.f>summary{cursor:pointer;padding:10px 12px;display:grid;grid-template-columns:auto 1fr auto;gap:10px;align-items:center;list-style:none}
details.f>summary::-webkit-details-marker{display:none}
.t{font-weight:600}.loc{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px;color:var(--muted);word-break:break-all}
.body{padding:0 14px 14px}.body h4{margin:14px 0 4px;font-size:12px;text-transform:uppercase;color:var(--muted);letter-spacing:.04em}
.body p{margin:4px 0}
pre{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:8px 0;overflow-x:auto;margin:6px 0;
font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
pre div{padding:0 10px;white-space:pre}pre div.hl{background:var(--hl)}pre .ln{display:inline-block;width:4.5em;color:var(--muted);user-select:none}
a{color:var(--accent);overflow-wrap:anywhere;word-break:break-word}.muted{color:var(--muted)}
#sevboxes{display:flex;flex-wrap:wrap;gap:6px 10px}
.body p,.t{overflow-wrap:anywhere}
.count{color:var(--muted);font-size:13px;margin-left:auto}
.st-ok{color:#2e7d32}.st-failed,.st-timeout{color:var(--high)}.st-missing,.st-skipped{color:var(--muted)}
@media (max-width:640px){details.f>summary{grid-template-columns:1fr}.hide-sm{display:none}}
@media print{.filters{display:none}details.f{break-inside:avoid}}
</style>
</head>
<body>
<div class="wrap">
<h1 id="title">SAST Report</h1>
<div class="sub" id="subtitle"></div>
<div class="cards" id="cards"></div>
<h2>Most exposed areas</h2>
<div class="tbl-wrap"><table id="dirs"><thead><tr><th>Directory</th><th class="hide-sm">Breakdown</th><th>Findings</th><th>Score</th><th class="hide-sm">Score / 1k lines</th></tr></thead><tbody></tbody></table></div>
<h2>Most exposed files</h2>
<div class="tbl-wrap"><table id="files"><thead><tr><th>File</th><th class="hide-sm">Breakdown</th><th>Findings</th><th>Score</th><th class="hide-sm">Lines</th></tr></thead><tbody></tbody></table></div>
<h2>Categories</h2>
<div class="tbl-wrap"><table id="cats"><thead><tr><th>Category</th><th>OWASP</th><th>Findings</th></tr></thead><tbody></tbody></table></div>
<h2>Findings</h2>
<div class="filters" id="filters">
<span id="sevboxes"></span>
<select id="ftool"><option value="">All tools</option></select>
<select id="fcat"><option value="">All categories</option></select>
<input type="search" id="fq" placeholder="Search file, rule, text...">
<span class="count" id="count"></span>
</div>
<div id="list"></div>
<h2>Engines</h2>
<div class="tbl-wrap"><table id="tools"><thead><tr><th>Engine</th><th>Status</th><th>Findings in scope</th><th>Time</th><th>Details</th></tr></thead><tbody></tbody></table></div>
<p class="muted" style="margin-top:24px">Generated by codit.py. Automated findings require manual validation; severities are tool estimates before exploitability review.</p>
</div>
<script id="data" type="application/json">__DATA__</script>
<script>
(function(){
var D=JSON.parse(document.getElementById('data').textContent);
var SEV=['CRITICAL','HIGH','MEDIUM','LOW','INFO'];
function el(tag,cls,text){var e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e;}
document.getElementById('title').textContent='SAST Report \u2014 '+D.meta.name;
document.getElementById('subtitle').textContent=D.meta.root+'  \u00b7  '+D.meta.date+'  \u00b7  '+
  D.meta.scope.files+' auditable files, '+D.meta.scope.lines.toLocaleString()+' auditable lines';
var cards=document.getElementById('cards');
SEV.forEach(function(s){var c=el('div','card sev '+s);c.appendChild(el('div','n',String(D.meta.counts[s]||0)));c.appendChild(el('div','l',s));cards.appendChild(c);});
var c2=el('div','card');c2.appendChild(el('div','n',String(D.findings.length)));c2.appendChild(el('div','l','Total findings'));cards.appendChild(c2);
var c3=el('div','card');c3.appendChild(el('div','n',String(D.meta.tools.filter(function(t){return t.status==='ok'}).length)));c3.appendChild(el('div','l','Engines run'));cards.appendChild(c3);
function bar(counts){var b=el('div','bar');var tot=0;SEV.forEach(function(s){tot+=counts[s]||0});
  SEV.forEach(function(s){var n=counts[s]||0;if(!n)return;var sp=el('span',s);sp.style.width=(100*n/tot)+'%';sp.style.background='var(--sev)';sp.title=s+': '+n;b.appendChild(sp);});return b;}
function hot(id,rows,last){var tb=document.querySelector('#'+id+' tbody');rows.slice(0,15).forEach(function(r){
  var tr=el('tr');var td=el('td','loc',r.name);tr.appendChild(td);var tb2=el('td','hide-sm');tb2.appendChild(bar(r.counts));tr.appendChild(tb2);
  tr.appendChild(el('td','num',String(r.total)));tr.appendChild(el('td','num',String(r.score)));
  tr.appendChild(el('td','num hide-sm',last==='density'?(r.density==null?'-':String(r.density)):String(r.lines)));tb.appendChild(tr);});
  if(!rows.length){var tr=el('tr');var td=el('td','muted','No findings');td.colSpan=5;tr.appendChild(td);tb.appendChild(tr);}}
hot('dirs',D.hotspots.directories,'density');hot('files',D.hotspots.files,'lines');
var cats={};D.findings.forEach(function(f){var k=f.category;cats[k]=cats[k]||{n:0,o:f.owasp};cats[k].n++;});
var ctb=document.querySelector('#cats tbody');Object.keys(cats).sort(function(a,b){return cats[b].n-cats[a].n}).forEach(function(k){
  var tr=el('tr');tr.appendChild(el('td',null,k));tr.appendChild(el('td','muted',cats[k].o||''));tr.appendChild(el('td','num',String(cats[k].n)));ctb.appendChild(tr);});
var boxes=document.getElementById('sevboxes');var active={};
SEV.forEach(function(s){active[s]=true;var l=el('label');var cb=el('input');cb.type='checkbox';cb.checked=true;
  cb.addEventListener('change',function(){active[s]=cb.checked;render();});l.appendChild(cb);var p=el('span','pill '+s,s);l.appendChild(p);boxes.appendChild(l);});
var tools={};D.findings.forEach(function(f){f.tools.forEach(function(t){tools[t]=1})});
var ft=document.getElementById('ftool');Object.keys(tools).sort().forEach(function(t){var o=el('option',null,t);o.value=t;ft.appendChild(o);});
var fc=document.getElementById('fcat');Object.keys(cats).sort().forEach(function(t){var o=el('option',null,t);o.value=t;fc.appendChild(o);});
var fq=document.getElementById('fq');[ft,fc].forEach(function(x){x.addEventListener('change',render)});fq.addEventListener('input',render);
function card(f){var d=el('details','f '+f.severity);var s=el('summary');
  s.appendChild(el('span','pill '+f.severity,f.severity));
  var mid=el('div');mid.appendChild(el('div','t',f.title));mid.appendChild(el('div','loc',f.file+':'+f.line));s.appendChild(mid);
  var right=el('div');right.appendChild(el('span','tag',f.id));if(f.cwe)right.appendChild(el('span','tag','CWE-'+f.cwe));
  f.tools.forEach(function(t){right.appendChild(el('span','tag',t))});s.appendChild(right);d.appendChild(s);
  var b=el('div','body');
  var meta=el('p','muted',f.category+(f.owasp?'  \u00b7  '+f.owasp:'')+'  \u00b7  confidence '+f.confidence);b.appendChild(meta);
  if(f.snippet&&f.snippet.length){var pre=el('pre');f.snippet.forEach(function(l){var r=el('div',l[2]?'hl':null);r.appendChild(el('span','ln',String(l[0])));r.appendChild(document.createTextNode(l[1]));pre.appendChild(r);});b.appendChild(pre);}
  b.appendChild(el('h4',null,'What the tools reported'));f.description.forEach(function(m){b.appendChild(el('p',null,m))});
  b.appendChild(el('h4',null,'Why it matters'));b.appendChild(el('p',null,f.explanation));
  b.appendChild(el('h4',null,'Recommendation'));b.appendChild(el('p',null,f.recommendation));
  if(f.references.length){b.appendChild(el('h4',null,'References'));f.references.forEach(function(r){var p=el('p');
    if(/^https?:\/\//.test(r)){var a=el('a',null,r);a.href=r;a.target='_blank';a.rel='noopener noreferrer';p.appendChild(a);}else{p.textContent=r;}b.appendChild(p);});}
  b.appendChild(el('p','muted','Rules: '+f.rules.join(', ')));
  d.appendChild(b);return d;}
var list=document.getElementById('list');var LIMIT=400;
function render(){var q=fq.value.toLowerCase();var t=ft.value,cat=fc.value;
  var res=D.findings.filter(function(f){if(!active[f.severity])return false;if(t&&f.tools.indexOf(t)<0)return false;if(cat&&f.category!==cat)return false;
    if(q){var blob=(f.file+' '+f.title+' '+f.category+' '+f.rules.join(' ')+' '+f.description.join(' ')+' '+f.id+' CWE-'+f.cwe).toLowerCase();if(blob.indexOf(q)<0)return false;}return true;});
  list.textContent='';res.slice(0,LIMIT).forEach(function(f){list.appendChild(card(f))});
  document.getElementById('count').textContent=res.length+' shown'+(res.length>LIMIT?' (first '+LIMIT+' rendered - refine filters)':'');}
render();
var ttb=document.querySelector('#tools tbody');D.meta.tools.forEach(function(t){var tr=el('tr');tr.appendChild(el('td',null,t.name));
  tr.appendChild(el('td','st-'+t.status,t.status));tr.appendChild(el('td','num',t.findings==null?'-':String(t.findings)));
  tr.appendChild(el('td','num',t.seconds==null?'-':t.seconds+'s'));tr.appendChild(el('td','muted',t.detail||''));ttb.appendChild(tr);});
})();
</script>
</body>
</html>
'''


def write_html(path, meta, findings, hot_files, hot_dirs):
    data = json.dumps(dict(meta=meta, findings=findings, hotspots=dict(files=hot_files, directories=hot_dirs)))
    data = data.replace('</', '<\\/').replace('<!--', '<\\!--')
    with open(path, 'w', encoding='utf-8') as f:
        f.write(HTML_TEMPLATE.replace('__DATA__', data))


# =========================================================================== #
# Console output
# =========================================================================== #
def sev_label(s, width=8):
    return c(('%-' + str(width) + 's') % s, *SEV_STYLE[s])


def print_tools_table(statuses):
    print('\n ' + c('Engines', C.BOLD, C.MAGENTA))
    for t in statuses:
        st = t['status']
        col = {'ok': C.BGREEN, 'failed': C.BRED, 'timeout': C.BRED}.get(st, C.GREY)
        n = '' if t['findings'] is None else '%5s findings' % fmt(t['findings'])
        secs = '' if t['seconds'] is None else '%6.1fs' % t['seconds']
        print('   %s %s %s %s  %s' % (c('%-15s' % t['name'], C.CYAN), c('%-8s' % st, col), c('%-15s' % n, C.BOLD),
                                     c('%7s' % secs, C.GREY), c((t['detail'] or '')[:110], C.GREY)))


def print_summary(meta, findings, hot_files, hot_dirs, args):
    w = 100
    rule = c('=' * w, C.BLUE)
    counts = meta['counts']
    total = len(findings)
    print('\n' + rule)
    print(' ' + c('FINDINGS SUMMARY', C.BOLD, C.BCYAN) + c('  (min severity %s)' % args.min_severity, C.GREY))
    print(rule)
    mx = max(counts.values() or [1]) or 1
    for s in SEVERITIES:
        n = counts.get(s, 0)
        barw = int(round(40.0 * n / mx)) if n else 0
        print('   %s %s  %s' % (sev_label(s, 9), c('%6s' % fmt(n), C.BOLD), c('█' * barw, *SEV_STYLE[s])))
    print('   %s %s' % (c('%-9s' % 'TOTAL', C.BOLD), c('%6s' % fmt(total), C.BOLD)))

    if findings:
        print('\n ' + c('Top categories', C.BOLD, C.MAGENTA))
        cats = Counter(f['category'] for f in findings)
        for cat, n in cats.most_common(10):
            worst = min((f['severity'] for f in findings if f['category'] == cat), key=SEVERITIES.index)
            print('   %s %s  %s' % (c('%5s' % fmt(n), C.BOLD), sev_label(worst, 9), cat))

        print('\n ' + c('Most exposed areas (directories)', C.BOLD, C.MAGENTA))
        for r in hot_dirs[:10]:
            dens = '' if r['density'] is None else c('  %6.1f pts/kloc' % r['density'], C.GREY)
            parts = ' '.join(c('%s:%d' % (s[0], r['counts'][s]), *SEV_STYLE[s]) for s in SEVERITIES if r['counts'][s])
            print('   %s %s  %s%s' % (c('%5d pts' % r['score'], C.BOLD), c('%-50s' % r['name'][-50:], C.CYAN), parts, dens))

        print('\n ' + c('Most exposed files', C.BOLD, C.MAGENTA))
        for r in hot_files[:10]:
            parts = ' '.join(c('%s:%d' % (s[0], r['counts'][s]), *SEV_STYLE[s]) for s in SEVERITIES if r['counts'][s])
            print('   %s %s  %s' % (c('%5d pts' % r['score'], C.BOLD), c('%-60s' % r['name'][-60:], C.CYAN), parts))

    show = [f for f in findings if SEV_RANK[f['severity']] >= SEV_RANK[args.console_min]][:args.console_limit]
    if show:
        print('\n' + rule)
        print(' ' + c('TOP FINDINGS', C.BOLD, C.BCYAN) + c('  (%s and above, %d of %d shown - full detail in report.html)'
                                                          % (args.console_min, len(show), total), C.GREY))
        print(rule)
        wrap = textwrap.TextWrapper(width=w, initial_indent=' ' * 12, subsequent_indent=' ' * 12)
        for f in show:
            cwe = ('CWE-%d' % f['cwe']) if f['cwe'] else ''
            print('\n %s %s %s %s' % (sev_label(f['severity'], 8), c(f['id'], C.GREY), c(f['title'], C.BOLD),
                                      c('[%s] %s' % (', '.join(f['tools']), cwe), C.GREY)))
            print('          %s %s' % (c('at', C.GREY), c('%s:%d' % (f['file'], f['line']), C.CYAN)))
            for n, t, hl in f['snippet']:
                if hl:
                    print('          %s %s' % (c('%5d |' % n, C.GREY), c(t.strip()[:w - 20], C.YELLOW)))
            first = f['description'][0] if f['description'] else ''
            print('     ' + c('What:', C.BOLD) + '  ' + wrap.fill(first[:600])[12:])
            print('     ' + c('Why :', C.BOLD) + '  ' + wrap.fill(f['explanation'])[12:])
            print('     ' + c('Fix :', C.BOLD, C.GREEN) + '  ' + wrap.fill(f['recommendation'][:700])[12:])


# =========================================================================== #
# Main
# =========================================================================== #
def list_tools():
    print(c('Available engines', C.BOLD, C.BCYAN))
    for t in TOOLS:
        exe = which_any(t.bins)
        ver = ''
        if exe:
            try:
                rc, out, err = run_cmd([exe, '--version'], timeout=60,
                                       env={'SEMGREP_ENABLE_VERSION_CHECK': '0', 'SEMGREP_SEND_METRICS': 'off'})
                txt = re.sub(r'\x1b\[[0-9;]*m', '', out or err)
                cand = [l.strip() for l in txt.splitlines() if re.search(r'\d+\.\d+', l)]
                ver = (cand[0] if cand else '')[:60]
            except ToolError:
                pass
        st = c('installed', C.BGREEN) if exe else c('missing  ', C.BRED)
        print('  %s %s %s %s' % (c('%-15s' % t.name, C.CYAN), st, c('%-46s' % t.desc[:46], C.GREY),
                                 c(ver, C.GREY) if exe else c('-> ' + t.install, C.YELLOW)))
    print('  %s %s %s' % (c('%-15s' % 'builtin', C.CYAN), c('installed', C.BGREEN),
                          c('%d regex rules shipped with this script' % len(BUILTIN_RULES), C.GREY)))
    print(c('\nNot orchestrated (need a build or a server): SpotBugs+FindSecBugs (Java bytecode), '
            'Security Code Scan (.NET build), SonarQube, Checkmarx, Fortify - import their SARIF with '
            '--import-sarif.', C.GREY))


def install_missing():
    missing = [PIP_TOOLS[t.name] for t in TOOLS if t.name in PIP_TOOLS and not which_any(t.bins)]
    if not missing:
        print('All pip-installable engines are already present.')
        return
    cmd = [sys.executable, '-m', 'pip', 'install', '--upgrade'] + missing
    print('Running: ' + ' '.join(cmd))
    rc = subprocess.call(cmd)
    if rc != 0:
        print('Retrying with --user / --break-system-packages ...')
        subprocess.call(cmd + ['--user', '--break-system-packages'])


def stage_files(root, records, stage):
    ctx_names = {'go.mod', 'go.sum', 'Gemfile', 'Gemfile.lock', 'composer.json', 'composer.lock',
                 'package.json', 'tsconfig.json', 'pom.xml', 'build.gradle', 'build.gradle.kts',
                 'settings.gradle', 'settings.gradle.kts', 'requirements.txt', 'pyproject.toml',
                 'setup.cfg', 'Cargo.toml', 'global.json', 'Directory.Build.props'}
    dirs = set()
    for r in records:
        src = os.path.join(root, r['path'])
        dst = os.path.join(stage, r['path'])
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        try:
            shutil.copy2(src, dst)
        except OSError:
            continue
        d = os.path.dirname(r['path'])
        while True:
            dirs.add(d)
            if not d:
                break
            d = os.path.dirname(d)
    for d in dirs:
        full = os.path.join(root, d)
        try:
            names = os.listdir(full)
        except OSError:
            continue
        for n in names:
            if n in ctx_names or n.endswith(('.csproj', '.vbproj', '.sln')):
                src = os.path.join(full, n)
                dst = os.path.join(stage, d, n)
                if os.path.isfile(src) and not os.path.exists(dst):
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    shutil.copy2(src, dst)


def main():
    ap = argparse.ArgumentParser(
        description='Run all available SAST engines on the auditable files of a code base.',
                formatter_class=argparse.RawDescriptionHelpFormatter, epilog=(__doc__ or '').split('Usage')[1] if 'Usage' in (__doc__ or '') else '')
    ap.add_argument('folder', nargs='?', help='source tree to analyse')
    g = ap.add_argument_group('scope (same options as codit_estimate.py)')
    g.add_argument('--exclude-tests', action='store_true', help='drop unit / e2e test code')
    g.add_argument('--html-scripts', action='store_true', help='include inline scripts of .html files')
    g.add_argument('--skip-dir', action='append', default=[], help='extra folder name to ignore')
    g.add_argument('--keep-dir', action='append', default=[], help='folder name to scan even if ignored by default')
    g.add_argument('--max-kb', type=int, default=2048, help='skip files larger than this (KB)')
    g.add_argument('--rate', type=int, default=3000, help='auditable lines per review day (for the scope summary)')
    g = ap.add_argument_group('engines')
    g.add_argument('--tools', help='comma-separated list of engines to run (default: all installed)')
    g.add_argument('--skip-tools', default='', help='comma-separated list of engines to skip')
    g.add_argument('--codeql', action='store_true', help='also run CodeQL (slow, deep data-flow analysis)')
    g.add_argument('--semgrep-config', action='append',
                   help='semgrep config (registry pack, file or folder; repeatable). A semgrep-rules clone '
                        'is filtered automatically to the detected languages')
    g.add_argument('--semgrep-rules-dir', help='local semgrep-rules clone used when the registry is unreachable')
    g.add_argument('--semgrep-offline', action='store_true', help='never contact the semgrep registry')
    g.add_argument('--verify-secrets', action='store_true',
                   help='let trufflehog verify secrets against live APIs (off by default)')
    g.add_argument('--import-sarif', action='append', default=[], metavar='FILE',
                   help='merge a SARIF file produced by another tool (paths relative to the scanned folder)')
    g.add_argument('--no-builtin', action='store_true', help='disable the built-in rule engine')
    g.add_argument('--ignore-rules', default='', help='comma-separated rule ids to suppress (any engine)')
    g.add_argument('--jobs', type=int, default=2, help='engines running in parallel (default 2)')
    g.add_argument('--jobs-per-tool', type=int, default=0, help='threads given to semgrep (0 = its default)')
    g.add_argument('--tool-timeout', type=int, default=3600, help='timeout per engine in seconds')
    g.add_argument('--max-per-rule', type=int, default=200, help='max built-in hits per rule and file')
    g = ap.add_argument_group('output')
    g.add_argument('--out', help='output folder (default ./sast_<name>_<timestamp>)')
    g.add_argument('--min-severity', default='LOW', type=str.upper, choices=SEVERITIES,
                   help='drop findings below this severity (default LOW)')
    g.add_argument('--console-min', default='HIGH', type=str.upper, choices=SEVERITIES,
                   help='print details of findings from this severity in the console (default HIGH)')
    g.add_argument('--console-limit', type=int, default=40, help='max findings detailed in the console')
    g.add_argument('--context', type=int, default=3, help='lines of code context around each finding')
    g.add_argument('--fail-on', type=str.upper, choices=SEVERITIES,
                   help='exit with code 1 if a finding of this severity or above exists (CI use)')
    g.add_argument('--keep-stage', action='store_true', help='keep the temporary staging folder')
    g.add_argument('--color', choices=('auto', 'always', 'never'), default='auto')
    g.add_argument('--no-color', dest='color', action='store_const', const='never')
    g = ap.add_argument_group('maintenance')
    g.add_argument('--list-tools', action='store_true', help='show engines, versions and install commands')
    g.add_argument('--install', action='store_true', help='pip-install the missing Python-based engines')
    args = ap.parse_args()
    setup_colors(args.color)

    if args.list_tools:
        list_tools()
        return 0
    if args.install:
        install_missing()
        return 0
    if not args.folder:
        ap.error('folder is required')
    root = os.path.abspath(args.folder)
    if not os.path.isdir(root):
        sys.exit(c('error:', C.BRED, C.BOLD) + ' %s is not a directory' % root)

    t0 = time.time()
    name = os.path.basename(root.rstrip(os.sep)) or 'root'
    out_dir = os.path.abspath(args.out or 'sast_%s_%s' % (re.sub(r'[^\w.-]', '_', name),
                                                         datetime.datetime.now().strftime('%Y%m%d_%H%M%S')))
    os.makedirs(out_dir, exist_ok=True)

    # ------------------------------------------------------------------ scope
    records, excluded, pruned = AS.auditable_files(root, args.exclude_tests, args.html_scripts,
                                                   args.skip_dir, args.keep_dir, args.max_kb)
    scope_lines = sum(r['auditable'] for r in records)
    scope = {os.path.normpath(r['path']) for r in records}
    bar = c('=' * 100, C.BLUE)
    print(bar)
    print(' ' + c('SAST SCAN', C.BOLD, C.BCYAN) + c('  -  ', C.GREY) + c(root, C.CYAN))
    print(bar)
    print(' Scope (codit_estimate.py): %s auditable files, %s auditable lines  %s' % (
        c(fmt(len(records)), C.BOLD), c(fmt(scope_lines), C.BOLD, C.BGREEN),
        c('(~%.1f review days at %s lines/day; %d files and %d folders excluded)' % (
            scope_lines / float(args.rate or 1), fmt(args.rate), len(excluded), len(pruned)), C.GREY)))
    if not records:
        print(c(' Nothing auditable found - stopping.', C.BYELLOW))
        return 0

    stage = tempfile.mkdtemp(prefix='sast_stage_')
    work = tempfile.mkdtemp(prefix='sast_work_')
    stage_files(root, records, stage)
    ctx = Ctx(root, stage, work, records, args)

    # ------------------------------------------------------------------ engines
    wanted = set(x.strip().lower() for x in args.tools.split(',')) if args.tools else None
    skipped = set(x.strip().lower() for x in args.skip_tools.split(',') if x.strip())
    statuses, raws = [], []
    jobs = []
    for t in TOOLS:
        st = dict(name=t.name, status='', findings=None, seconds=None, detail='')
        statuses.append(st)
        if (wanted is not None and t.name not in wanted) or t.name in skipped:
            st.update(status='skipped', detail='not selected')
            continue
        if t.optin and not args.codeql and not (wanted and t.name in wanted):
            st.update(status='skipped', detail='opt-in: use --codeql')
            continue
        exe = which_any(t.bins)
        if not exe:
            st.update(status='missing', detail='install: ' + t.install)
            continue
        if t.exts is not None and not ctx.has(*t.exts):
            st.update(status='skipped', detail='no matching files in scope')
            continue
        if t.name == 'semgrep' and 'opengrep' in os.path.basename(exe):
            st['name'] = 'opengrep'
        jobs.append((t, exe, st))

    def execute(job):
        t, exe, st = job
        log('  %s %s' % (c('>>', C.BLUE), c('running %s' % st['name'], C.GREY)))
        start = time.time()
        try:
            res, note = t.runner(ctx, exe)
            if res is None:
                st.update(status='skipped', detail=note or '')
                res = []
            else:
                st.update(status='ok', detail=note or '')
        except ToolError as ex:
            res = []
            st.update(status='timeout' if 'timeout' in str(ex) else 'failed', detail=str(ex)[:400])
        except Exception as ex:           # a broken tool must never kill the whole scan
            res = []
            st.update(status='failed', detail='%s: %s' % (type(ex).__name__, ex))
        st['seconds'] = round(time.time() - start, 1)
        col = C.BGREEN if st['status'] == 'ok' else C.BRED if st['status'] in ('failed', 'timeout') else C.GREY
        log('  %s %s %s %s' % (c('<<', C.BLUE), c('%-14s' % st['name'], C.CYAN), c(st['status'], col),
                               c('%d raw results, %.1fs' % (len(res), st['seconds']), C.GREY)))
        return st, res

    if jobs:
        print('\n ' + c('Running %d engine(s)...' % len(jobs), C.BOLD, C.MAGENTA))
        with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
            for st, res in pool.map(execute, jobs):
                for r in res:
                    r['_status'] = st
                raws += res

    ignore = set(x.strip() for x in args.ignore_rules.split(',') if x.strip())
    if not args.no_builtin and (wanted is None or 'builtin' in wanted) and 'builtin' not in skipped:
        st = dict(name='builtin', status='ok', findings=None, seconds=None,
                  detail='%d rules' % len(BUILTIN_RULES))
        start = time.time()
        res = run_builtin(ctx, records, ignore)
        st['seconds'] = round(time.time() - start, 1)
        for r in res:
            r['_status'] = st
        raws += res
        statuses.append(st)
        log('  %s %s %s %s' % (c('<<', C.BLUE), c('%-14s' % 'builtin', C.CYAN), c('ok', C.BGREEN),
                               c('%d raw results, %.1fs' % (len(res), st['seconds']), C.GREY)))

    for sp in args.import_sarif:
        st = dict(name='sarif:' + os.path.basename(sp), status='ok', findings=None, seconds=0, detail=sp)
        try:
            with open(sp, encoding='utf-8', errors='replace') as f:
                res = parse_sarif(load_json(f.read()), None, root)
        except (OSError, ValueError, AttributeError) as ex:
            res = []
            st.update(status='failed', detail=str(ex))
        for r in res:
            r['_status'] = st
        raws += res
        statuses.append(st)

    # ------------------------------------------------------------------ scope filter
    dropped = 0
    kept = []
    per_tool = Counter()
    for r in raws:
        anchors = [r['base']] if r.get('base') else [stage, root]
        rel = to_rel(r['path'], anchors)
        if rel is None or rel not in scope:
            dropped += 1
            continue
        if r['rule'] in ignore or ('%s:%s' % (r['tool'], r['rule'])) in ignore:
            continue
        r['rel'] = rel
        per_tool[id(r['_status'])] += 1
        kept.append(r)
    for st in statuses:
        if st['status'] == 'ok':
            st['findings'] = per_tool.get(id(st), 0)
    for r in raws:
        r.pop('_status', None)

    findings = merge_findings(kept, root, scope, args)
    hot_files, hot_dirs = hotspots(findings, records)
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f['severity']] += 1

    meta = dict(name=name, root=root, date=datetime.datetime.now().strftime('%Y-%m-%d %H:%M'),
                version=VERSION, scope=dict(files=len(records), lines=scope_lines,
                                            excluded_files=len(excluded), ignored_folders=len(pruned),
                                            review_days=round(scope_lines / float(args.rate or 1), 1)),
                tools=statuses, counts=counts, raw_results=len(raws), out_of_scope_dropped=dropped,
                min_severity=args.min_severity, duration_s=round(time.time() - t0, 1))

    # ------------------------------------------------------------------ outputs
    write_json(os.path.join(out_dir, 'findings.json'), meta, findings, hot_files, hot_dirs)
    write_csv(os.path.join(out_dir, 'findings.csv'), findings)
    write_sarif(os.path.join(out_dir, 'findings.sarif'), meta, findings)
    write_html(os.path.join(out_dir, 'report.html'), meta, findings, hot_files, hot_dirs)

    print_tools_table(statuses)
    print_summary(meta, findings, hot_files, hot_dirs, args)
    print('\n' + bar)
    print(' %s %s raw results -> %s unique findings  %s' % (
        c('RESULT:', C.BOLD), fmt(len(raws)), c(fmt(len(findings)), C.BOLD, C.BGREEN),
        c('(%d outside the auditable scope dropped, %.0fs)' % (dropped, time.time() - t0), C.GREY)))
    print(' %s %s' % (c('Report :', C.BOLD), c(os.path.join(out_dir, 'report.html'), C.CYAN)))
    print(' %s %s' % (c('Data   :', C.BOLD), c('findings.json  findings.csv  findings.sarif', C.GREY)))
    print(bar)

    if args.keep_stage:
        print(c(' staging folder kept: %s' % stage, C.GREY))
    else:
        shutil.rmtree(stage, ignore_errors=True)
    shutil.rmtree(work, ignore_errors=True)

    if args.fail_on and any(SEV_RANK[f['severity']] >= SEV_RANK[args.fail_on] for f in findings):
        return 1
    return 0


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:          # output piped into head / less and closed early
        try:
            sys.stdout = open(os.devnull, 'w')
        except OSError:
            pass
        sys.exit(0)
