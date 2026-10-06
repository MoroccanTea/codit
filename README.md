# Codit
Codit is a simple source code audit tool that helps developers identify potential security vulnerabilities in their codebase. It scans the code for common security issues and provides recommendations for fixing them.

What is removed before counting:
  * comments, docstrings and blank lines (per-language, string-aware)
  * dependency / build / tooling folders (node_modules, vendor, dist, target, .git ...)
  * third-party JS/CSS libraries (by path, file name, license header)
  * minified, bundled, hashed and generated files (protobuf, designer, .d.ts, dumps ...)
  * pure markup and non-code files (.html, .css, .md, .json, images, ...)
  * static markup inside templates (only server-side code blocks, inline <script>
    and lines carrying template expressions are counted in .php/.jsp/.cshtml/.vue ...)
  * lines that cannot hold logic: lone braces/brackets, block closers (end, fi, else),
    import/using/package/include/namespace declarations
  * optionally: unit tests (--exclude-tests)

**IMPORTANT:** Codit is not a replacement for a professional security audit and does not guarantee the identification of all security issues. It is intended to be used as a first step in identifying potential issues in your codebase. False positives may occur, and it is recommended to review the results carefully and consult with a security expert if necessary.

## Features
- Estimates the number of auditable lines of code in a project and the time it would take to audit them
- Scans source code for common security vulnerabilities
- Provides detailed reports with recommendations for fixing issues
- Supports multiple programming languages
- Maps every finding to OWASP Top 10 **2021 and 2025** and reports per-category coverage
- Reports vulnerable dependencies separately from code findings: one entry per package (all engines merged, the
  advisory CWE kept as detail so library CVEs do not inflate code categories such as XSS or SSRF), the exact
  vulnerable installed version, and npm packages only installed through devDependencies flagged and lowered one level

## Engines 
each one is used when installed, skipped otherwise; see `--list-tools`. Engines installed after the terminal was
opened are still found: the persisted user / system PATH and the usual install folders (dotnet tools, go/bin, cargo,
WinGet, scoop, Homebrew, composer) are searched too.

Noise control applied after merging: hard-coded credential hits in test code become INFO (known token formats such as
AWS / GitHub keys and private keys excepted), notoriously noisy rules (find-sec-bugs HARD_CODE_KEY-2/3/4,
CUSTOM_INJECTION-2) are kept only when another engine reports the same spot, and DevSkim's setTimeout-with-a-function,
non-security TODO, http:// namespace and localhost hits are dropped or shown as INFO. trivy falls back to
`--offline-scan` when Maven Central cannot be reached or rate-limits the scan.
  semgrep / opengrep      multi-language (registry packs, a local semgrep-rules clone, + codit's bundled rules);
                          framework / JWT / Docker / nginx / CI packs are added for what the project uses
  bandit                  Python
  gosec                   Go
  brakeman                Ruby on Rails
  njsscan                 Node.js / JS templates
  mobsfscan               Android / iOS source (Java, Kotlin, Swift, Obj-C)
  flawfinder, cppcheck    C / C++
  shellcheck              shell scripts (security-relevant checks only)
  phpcs + security-audit  PHP
  progpilot               PHP taint analysis
  devskim                 multi-language (Microsoft)
  codeql                  deep data-flow analysis (optional: --codeql)
  gitleaks, trufflehog    secrets
  osv-scanner, trivy      vulnerable dependencies (all ecosystems)
  pip-audit, npm audit    vulnerable Python / npm dependencies
  builtin                 always available, no dependency:
                            * ~180 regex rules (codit.py) on source and configuration files
                            * structural analyzers (codit_analyzers.py):
                                access control  route / handler guard analysis for Spring, JAX-RS, Express,
                                                NestJS, Flask (incl. RESTX / RESTful / MethodView class views),
                                                Django / DRF, FastAPI, Laravel, Symfony, plain PHP, WordPress,
                                                ASP.NET Core, Rails and Go routers: endpoints
                                                missing the guard their siblings have, write endpoints guarded
                                                by read permissions, IDOR, permitAll / AllowAny / disabled
                                                method security, client-controlled roles
                                auth / MFA      session issued before the second factor, fail-open / static /
                                                debug OTP bypasses, OTP exposure, 2FA disable without
                                                re-authentication, pending-2FA tokens accepted, 2FA-pending
                                                token claims never enforced (response-manipulation bypass),
                                                OTP brute force and expiry, password reset flows, session fixation
                                taint-lite      request data -> variables -> SQL / command / path / SSRF /
                                                redirect / eval / template / deserialization / XSS sinks
                                dependencies    offline table of well-known vulnerable versions
  --import-sarif          merge results from any other tool (SonarQube, Checkmarx, ...)

Configuration files are scanned too (not counted as auditable lines; `--no-config-scan` to skip):
application.yml / .properties, .env, web.config / appsettings.json, nginx / Apache / Tomcat, Dockerfile,
docker-compose, GitHub / GitLab CI, MyBatis mappers, AndroidManifest, package manifests and lock files.

## Requirements
- Python 3.6 or higher
- go
- pip
- brew
- rubyinstaller

## Installation
To install Codit, follow these steps:
1. Clone the repository:
   ```
   git clone https://github.com/MoroccanTea/codit
   ```
2. Navigate to the project directory:
   ```
    cd codit
    ```
3. Install the required python dependencies:
   ```
   pip install -r requirements.txt
   ```
4. Install the required tools (optional, but recommended):
   ```
   pip install semgrep
   pip install bandit
   go install github.com/securego/gosec/v2/cmd/gosec@latest
   gem install brakeman
   pip install njsscan
   pip install mobsfscan
   pip install flawfinder
   apt install cppcheck | brew install cppcheck
   apt install shellcheck | brew install shellcheck
   composer global require squizlabs/php_codesniffer pheromone/phpcs-security-audit && phpcs --config-set installed_paths ~/.composer/vendor/pheromone/phpcs-security-audit
   download progpilot.phar from github.com/designsecurity/progpilot/releases
   dotnet tool install --global Microsoft.CST.DevSkim.CLI
   download the CodeQL bundle from github.com/github/codeql-action/releases
   brew install gitleaks | github.com/gitleaks/gitleaks/releases
   brew install trufflehog | github.com/trufflesecurity/trufflehog/releases
   go install github.com/google/osv-scanner/v2/cmd/osv-scanner@latest | github.com/google/osv-scanner/releases | winget install Google.OSVScanner
   brew install trivy | github.com/aquasecurity/trivy/releases
   pip install pip-audit
   ```
   codit.py itself only needs the Python standard library.


## Usage
To use Codit, run the following command:
```
python codit_estimate.py /path/to/source
python codit_estimate.py /path/to/source --rate 3000 --exclude-tests --top 15
python codit_estimate.py /path/to/source --list-excluded > excluded.txt
python codit_estimate.py /path/to/source --json report.json
python codit_estimate.py /path/to/source --no-color      (colors are auto-off when piped)
python3 codit.py /path/to/source
python3 codit.py /path/to/source --exclude-tests --out report_dir
python3 codit.py /path/to/source --tools semgrep,bandit,builtin --min-severity MEDIUM
python3 codit.py /path/to/source --semgrep-config ~/semgrep-rules     (offline)
python3 codit.py /path/to/source --codeql --jobs 3
python3 codit.py /path/to/source --semgrep-offline    (registry never contacted: local clone + bundled rules)
python3 codit.py /path/to/source --no-config-scan --no-bundled-rules
python3 codit.py /path/to/source --no-framework-packs    (language packs only, no flask / django / expressjs /
                                                       findsecbugs / jwt / dockerfile / nginx / CI packs)
python3 codit.py --list-tools
python3 codit.py --install         (pip-install the missing Python-based tools)

# Requires codit_estimate.py and codit_analyzers.py in the same folder (rules/semgrep for the bundled rules).
```

## Output
Outputs (in `--out`, default `./sast_<name>_<timestamp>/`)
  report.html   interactive report (filters, code snippets, explanation, fix, OWASP 2021 / 2025 coverage)
  findings.json full machine-readable results (meta.owasp holds the per-category coverage)
  findings.csv  spreadsheet-friendly list
  findings.sarif SARIF 2.1.0 (DefectDojo, GitHub code scanning, VS Code SARIF viewer)
  logs/         per-engine diagnostics (e.g. logs/semgrep.log: every attempt, command, exit code, errors)

## Semgrep troubleshooting
The Engines table always says which rule sources semgrep used, how many files it scanned and how many errors
it reported (`rules: registry + codit rules | 574 files | 0 errors | semgrep 1.172.0`). Codit:
  * finds semgrep / bandit in the Python Scripts folders even when they are not on PATH (pip --user installs),
    and falls back to `python -m semgrep`;
  * does not let a failed connectivity probe (proxy, TLS interception) cancel the run: the registry is still
    tried, then a local semgrep-rules clone, then codit's bundled rules, so semgrep keeps running offline;
  * drops a registry pack that fails to download and retries with the others;
  * reports "scanned 0 files" as a failure instead of a silent ok;
  * writes the full story to logs/semgrep.log in the report folder.

## Tests
Labeled fixture corpora live in tests/fixtures/ (`codit-expect: CWE-n` / `codit-safe: CWE-n` markers in
comments). Each subdirectory is scanned as a separate project and recall / false positives are reported:
```
python tests/run_fixtures.py                                   all corpora, builtin engine
python tests/run_fixtures.py a01_access_control --tools builtin,semgrep --codit-arg=--semgrep-offline
```
Bundled semgrep rules: `semgrep --validate --config rules/semgrep`; rule tests live in rules/semgrep-tests.
