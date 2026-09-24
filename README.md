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

## Engines 
each one is used when installed, skipped otherwise; see `--list-tools`
  semgrep / opengrep      multi-language (registry packs, or a local semgrep-rules clone)
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
  builtin                 ~125 regex rules shipped in this script (always available)
  --import-sarif          merge results from any other tool (SonarQube, Checkmarx, ...)

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
   git clone 
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
   ```


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
python3 codit.py --list-tools
python3 codit.py --install         (pip-install the missing Python-based tools)

# Requires codit_estimate.py in the same folder.
```

## Output
Outputs (in `--out`, default `./sast_<name>_<timestamp>/`)
  report.html   interactive report (filters, code snippets, explanation, fix)
  findings.json full machine-readable results
  findings.csv  spreadsheet-friendly list
  findings.sarif SARIF 2.1.0 (DefectDojo, GitHub code scanning, VS Code SARIF viewer)
