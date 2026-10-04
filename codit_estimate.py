#!/usr/bin/env python3

import argparse
import json
import math
import os
import re
import sys
from collections import defaultdict

# --------------------------------------------------------------------------- #
# Comment / string grammars (strings are matched so that comment markers
# inside string literals are not treated as comments)
# --------------------------------------------------------------------------- #
DQ = r'"(?:\\.|[^"\\\n])*"'
SQ = r"'(?:\\.|[^'\\\n])*'"
BT = r'`(?:\\.|[^`\\])*`'
TDQ = r'"""[\s\S]*?(?:"""|\Z)'
TSQ = r"'''[\s\S]*?(?:'''|\Z)"
SH_HASH = r'(?:^|(?<=[\s;]))#[^\n]*'


def LC(tok):
    return re.escape(tok) + r'[^\n]*'


def BC(a, b):
    return re.escape(a) + r'[\s\S]*?(?:' + re.escape(b) + r'|\Z)'


GRAMMARS = {
    'c':    ([BC('/*', '*/'), LC('//')], [DQ, SQ]),
    'js':   ([BC('/*', '*/'), LC('//')], [BT, DQ, SQ]),
    'php':  ([BC('/*', '*/'), LC('//'), r'#(?!\[)[^\n]*'], [DQ, SQ]),
    'py':   ([LC('#')], [TDQ, TSQ, DQ, SQ]),
    'rb':   ([r'^=begin\b[\s\S]*?(?:^=end\b[^\n]*|\Z)', LC('#')], [DQ, SQ]),
    'sh':   ([SH_HASH], [DQ, SQ]),
    'pl':   ([r'^=[a-zA-Z]\w*[\s\S]*?(?:^=cut\b[^\n]*|\Z)', SH_HASH], [DQ, SQ]),
    'hash': ([LC('#')], [DQ, SQ]),
    'ps1':  ([BC('<#', '#>'), LC('#')], [DQ, SQ]),
    'sql':  ([BC('/*', '*/'), LC('--')], [SQ, DQ]),
    'lua':  ([r'--\[(?P<lq>=*)\[[\s\S]*?\](?P=lq)\]', LC('--')], [DQ, SQ]),
    'vb':   ([r"'[^\n]*", r'^[ \t]*(?i:rem)\b[^\n]*'], [DQ]),
    'erl':  ([LC('%')], [DQ]),
    'hs':   ([BC('{-', '-}'), LC('--')], [DQ]),
}
_COMPILED = {}


def _grammar(name):
    if name not in _COMPILED:
        com, strs = GRAMMARS[name]
        pat = '(?P<c>' + '|'.join(com) + ')|(?P<s>' + '|'.join(strs) + ')'
        _COMPILED[name] = re.compile(pat, re.M)
    return _COMPILED[name]


def blank(s):
    """Replace everything but newlines with spaces (keeps offsets and line numbers)."""
    return re.sub(r'[^\n]', ' ', s)


def strip_comments(text, gname):
    rx = _grammar(gname)
    docstrings = gname == 'py'

    def repl(m):
        tok = m.group(0)
        if m.group('c') is not None:
            return blank(tok)
        if docstrings and tok[:3] in ('"""', "'''"):
            ls = text.rfind('\n', 0, m.start()) + 1
            if not text[ls:m.start()].strip():      # statement-level string = docstring
                return blank(tok)
        return tok

    return rx.sub(repl, text)


# --------------------------------------------------------------------------- #
# File type maps
# --------------------------------------------------------------------------- #
CODE_EXT = {}
for _g, _exts in {
    'js':   '.js .mjs .cjs .jsx .ts .tsx .mts .cts',
    'c':    '.java .kt .kts .scala .groovy .c .h .cpp .cc .cxx .hpp .hh .cs .go '
            '.swift .rs .dart .m .mm .sol .fs .fsx',
    'py':   '.py .pyw',
    'rb':   '.rb .rake',
    'sh':   '.sh .bash .zsh .ksh',
    'pl':   '.pl .pm .cgi',
    'hash': '.ex .exs .cr .r .tcl',
    'ps1':  '.ps1 .psm1',
    'sql':  '.sql .pls .pks .pkb .plsql .pck',
    'lua':  '.lua',
    'vb':   '.vb .vbs .bas .cls',
    'erl':  '.erl .hrl',
    'hs':   '.hs',
}.items():
    for _e in _exts.split():
        CODE_EXT[_e] = _g

# template kinds: server-tag regex, grammar of the server code, expression-line regex
PHP_TAG = re.compile(r'<\?(?:php\b|=)?([\s\S]*?)(?:\?>|\Z)', re.I)
ASP_TAG = re.compile(r'<%(?!--)[!=@#:$]?([\s\S]*?)(?:%>|\Z)')
BLADE_PHP = re.compile(r'@php\b([\s\S]*?)(?:@endphp|\Z)')
RAZOR_BLOCK = re.compile(r'@(?:code|functions)?\s*\{')
SCRIPT_TAG = re.compile(r'<script\b([^>]*)>([\s\S]*?)</script\s*>', re.I)

EXPR_GENERIC = re.compile(r'\{\{|\{%|\{!!|\$!?\{|#\{|<#\w|<@\w|\$!?[A-Za-z_]\w*|'
                          r'#(?:if|set|foreach|elseif|else|end)\b')
EXPR_EL = re.compile(r'\$\{|#\{')
EXPR_AT = re.compile(r'(?<![\w.@])@(?!@)[A-Za-z_(]|\{\{|\{!!')
EXPR_VUE = re.compile(r'\{\{|\bv-[\w-]+|(?<=\s)[:@#][\w.\-\[\]]+=')
EXPR_SVELTE = re.compile(r'\{[^}\n]*\}')

TEMPLATE_KINDS = {
    'php':    dict(tag=PHP_TAG, g='php', expr=None),
    'blade':  dict(tag=PHP_TAG, g='php', expr=EXPR_AT, blade=True),
    'jsp':    dict(tag=ASP_TAG, g='c',   expr=EXPR_EL),
    'asp':    dict(tag=ASP_TAG, g='vb',  expr=None),
    'aspx':   dict(tag=ASP_TAG, g='c',   expr=None),
    'razor':  dict(tag=None,    g='c',   expr=EXPR_AT, razor=True),
    'erb':    dict(tag=ASP_TAG, g='rb',  expr=None),
    'ejs':    dict(tag=ASP_TAG, g='js',  expr=None),
    'vue':    dict(tag=None,    g='js',  expr=EXPR_VUE),
    'svelte': dict(tag=None,    g='js',  expr=EXPR_SVELTE),
    'generic': dict(tag=None,   g='js',  expr=EXPR_GENERIC),
}
TEMPLATE_EXT = {}
for _k, _exts in {
    'php':     '.php .phtml .php3 .php4 .php5 .php7 .phps .inc',
    'jsp':     '.jsp .jspx .jspf .tag .tagx',
    'asp':     '.asp',
    'aspx':    '.aspx .ascx .master .ashx .asmx',
    'razor':   '.cshtml .vbhtml .razor',
    'erb':     '.erb .rhtml',
    'ejs':     '.ejs',
    'vue':     '.vue',
    'svelte':  '.svelte',
    'generic': '.twig .jinja .jinja2 .j2 .njk .hbs .handlebars .mustache .liquid '
               '.ftl .ftlh .vm .gsp .tpl .tmpl .gohtml .jade .pug .haml .slim',
}.items():
    for _e in _exts.split():
        TEMPLATE_EXT[_e] = _k

HTML_EXT = {'.html', '.htm', '.xhtml', '.shtml'}

# --------------------------------------------------------------------------- #
# Exclusion rules
# --------------------------------------------------------------------------- #
SKIP_DIRS = {
    '.git', '.svn', '.hg', '.bzr', 'node_modules', 'bower_components', 'jspm_packages',
    'vendor', 'vendors', 'third_party', 'third-party', 'thirdparty', '3rdparty',
    'dist', 'build', 'out', 'target', 'bin', 'obj', '.next', '.nuxt', '.svelte-kit',
    '.angular', '.cache', '.parcel-cache', 'coverage', '.nyc_output', '__pycache__',
    '.venv', 'venv', 'virtualenv', '.tox', '.mypy_cache', '.pytest_cache',
    'site-packages', '.gradle', '.mvn', '.idea', '.vscode', '.vs', 'Pods', 'Carthage',
    '.terraform', '.serverless', '.dart_tool', '.pub-cache', 'DerivedData', 'elm-stuff',
    'packages.lock', '.yarn', '.pnpm-store', 'wheels', 'eggs', '.eggs',
}
TEST_DIRS = {'test', 'tests', '__tests__', 'spec', 'specs', 'testing', 'e2e',
             'cypress', '__mocks__', 'testdata', 'test-data', 'fixtures', 'androidTest'}
TEST_FILE = re.compile(
    r'(^test_.*\.py$|_tests?\.(py|go|rb|exs?)$|\.(test|spec)\.[cm]?[jt]sx?$|'
    r'(Test|Tests|IT|Spec)\.(java|kt|cs|scala|groovy|php|swift)$|_spec\.rb$|Test\.php$)')

# web asset folders whose "lib"/"plugins" subfolders are almost always third party
WEB_DIRS = {'static', 'public', 'assets', 'wwwroot', 'www', 'web', 'js', 'javascript',
            'scripts', 'resources', 'webapp', 'media', 'content', 'webroot', 'htdocs'}
ASSET_LIB_DIRS = {'lib', 'libs', 'plugins', 'plugin', 'bower', 'jslib', 'js-lib',
                  'external', 'ext', 'thirdparty'}
ASSET_EXT = {'.js', '.mjs', '.cjs', '.ts', '.css', '.map'}

JS_LIBS = (r'jquery(?:[.\-_][\w\-]+)?|bootstrap(?:[.\-_][\w\-]+)?|popper|angular(?:[.\-_]\w+)?|'
           r'react|react-dom|vue|vuex|vue-router|lodash|underscore|backbone|moment(?:-with-locales)?|'
           r'd3|chart|highcharts|echarts|three|leaflet|select2|datatables|jquery\.datatables|tinymce|'
           r'ckeditor|summernote|modernizr|require|knockout|handlebars|mustache|polyfills?|core-js|'
           r'swiper|slick|owl\.carousel|sweetalert2?|toastr|axios|socket\.io|fontawesome|all|'
           r'html5shiv|respond|prism|highlight|codemirror|ace|pdf|pdf\.worker|fabric|konva|hammer|'
           r'gsap|anime|aos|wow|isotope|masonry|fullcalendar|flatpickr|pikaday|dropzone|clipboard|'
           r'cropper|sortable|dragula|video|plyr|hls|mapbox-gl|ol|materialize|foundation|semantic|'
           r'uikit|alpine|htmx|zepto|mootools|prototype|scriptaculous|ext-all|dojo|yui|qrcode|'
           r'jspdf|xlsx|papaparse|crypto-js|jsencrypt|forge|showdown|marked|dompurify|purify|'
           r'bignumber|numeral|luxon|dayjs|date-fns|raphael|morris|sparkline|jvectormap|'
           r'perfect-scrollbar|metismenu|feather|lucide|popper\.js|tether|slimscroll|nprogress|'
           r'pace|waypoints|typed|lightbox|fancybox|magnific-popup|photoswipe|bxslider|'
           r'inputmask|cleave|intl-tel-input|daterangepicker|bootbox|toastify|notyf|izitoast')
LIB_NAME = re.compile(r'^(?:' + JS_LIBS + r')(?:[.\-_]?v?\d[\w.]*)?'
                      r'(?:[.\-_](?:min|slim|bundle|umd|esm|full|all|dev|prod|production|'
                      r'development|pack|packed|core|js))*\.[cm]?js$', re.I)
MIN_NAME = re.compile(r'([.\-_](min|bundle|chunk|packed|compiled)\.[cm]?(js|css)$)|'
                      r'(\.[0-9a-f]{8,}\.(js|css)$)|(\.map$)', re.I)
# file-name patterns of generated code; whole-name entries are anchored (an unanchored "R\.java" used to
# match every *r.java file - Controller, Filter, Handler, User... - and silently drop them from the scope)
GEN_NAME = re.compile(r'(\.pb\.go|_pb2(_grpc)?\.py|\.pb\.(cc|h)|\.g\.(cs|dart)|\.g\.i\.cs|'
                      r'\.designer\.(cs|vb)|\.generated\.\w+|\.freezed\.dart|_generated\.\w+|'
                      r'\.d\.ts|-lock\.\w+|\.lock)$|^(R|BuildConfig)\.java$|^AssemblyInfo\.cs$', re.I)
GEN_HEADER = re.compile(r'@generated|auto-?generated|do not edit|generated by|'
                        r'mysql dump|database dump|phpmyadmin sql dump|<auto-generated', re.I)
LIB_HEADER_LICENSE = re.compile(r'licen[sc]ed?|\bMIT\b|Apache|\bBSD\b|\bGPL\b', re.I)
LIB_HEADER_VERSION = re.compile(r'\bv?\d+\.\d+\.\d+\b')

# lines that cannot carry exploitable logic
TRIVIAL_LINE = re.compile(
    r'^\s*(?:[{}()\[\];,]+|end|fi|done|esac|end(?:if|for|foreach|while|switch|sub|function)\s*;?|'
    r'else\s*:?\s*\{?|\}\s*else\s*\{?|\}?\s*finally\s*\{?|<\?php|\?>)\s*$', re.I)
IMPORT_LINE = re.compile(
    r'^\s*(?:import\s+[\w.*{}\s,\'"@/\-]+;?\s*$|import\s+[\w.*]+(?:\s+as\s+\w+)?\s*$|'
    r'import\s.*\sfrom\s+[\'"][^\'"]+[\'"]\s*;?\s*$|from\s+[\w.]+\s+import\s|'
    r'package\s+[\w.]+\s*;?\s*$|using\s+(?:static\s+)?[\w.]+\s*;\s*$|using\s+\w+\s*=\s*[\w.]+\s*;\s*$|'
    r'#\s*include\b|#\s*import\b|#\s*pragma\b|use\s+[\w\\{},\s]+(?:\s+as\s+\w+)?\s*;\s*$|'
    r'namespace\s+[\w.\\]+\s*;\s*$|require_relative\s|extern\s+crate\s|mod\s+\w+\s*;\s*$)')


# --------------------------------------------------------------------------- #
# Analysis helpers
# --------------------------------------------------------------------------- #
def read_text(path, max_bytes):
    try:
        size = os.path.getsize(path)
        if size > max_bytes:
            return None, 'too large (> %d KB, likely generated or data)' % (max_bytes // 1024)
        with open(path, 'rb') as f:
            raw = f.read()
    except OSError as e:
        return None, 'unreadable (%s)' % e.strerror
    if b'\x00' in raw[:8192]:
        return None, 'binary'
    return raw.decode('utf-8', errors='replace'), None


def looks_minified(text):
    lines = [l for l in text.split('\n') if l.strip()]
    if not lines:
        return False
    longest = max(len(l) for l in lines)
    avg = sum(len(l) for l in lines) / len(lines)
    return longest > 2000 or (avg > 200 and len(lines) > 3)


def looks_js_library(text):
    head = text[:2500]
    if '@license' in head or '@preserve' in head:
        return True
    return bool(LIB_HEADER_VERSION.search(head) and LIB_HEADER_LICENSE.search(head)
                and 'http' in head)


def brace_block_end(text, open_idx):
    depth, i, n = 0, open_idx, len(text)
    while i < n:
        ch = text[i]
        if ch in '"\'':
            j = i + 1
            while j < n and text[j] != ch and text[j] != '\n':
                j += 2 if text[j] == '\\' else 1
            i = j
        elif ch == '{':
            depth += 1
        elif ch == '}':
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return n


def mask_template(text, kind):
    """Keep only server-side code, inline scripts and template-expression lines."""
    spec = TEMPLATE_KINDS[kind]
    out = list(blank(text))

    def put(s, e, g):
        out[s:e] = strip_comments(text[s:e], g)

    for m in SCRIPT_TAG.finditer(text):
        attrs = m.group(1).lower()
        if re.search(r'\bsrc\s*=', attrs) or re.search(r'type\s*=\s*["\']?[^"\'>]*'
                                                       r'(json|template|html|text/x-)', attrs):
            continue
        put(m.start(2), m.end(2), 'js')
    if spec.get('tag'):
        for m in spec['tag'].finditer(text):
            put(m.start(1), m.end(1), spec['g'])
    if spec.get('blade'):
        for m in BLADE_PHP.finditer(text):
            put(m.start(1), m.end(1), 'php')
    if spec.get('razor'):
        for m in RAZOR_BLOCK.finditer(text):
            o = m.end() - 1
            e = brace_block_end(text, o)
            put(o + 1, e, 'c')

    masked = ''.join(out).split('\n')
    if spec.get('expr'):
        orig = text.split('\n')
        for i, line in enumerate(orig):
            if not masked[i].strip() and spec['expr'].search(line):
                masked[i] = line
    return masked


def classify_lines(lines):
    blank_n = trivial = imports = code = 0
    for l in lines:
        if not l.strip():
            blank_n += 1
        elif TRIVIAL_LINE.match(l):
            trivial += 1
        elif IMPORT_LINE.match(l):
            imports += 1
        else:
            code += 1
    return blank_n, trivial, imports, code


def detect_kind(fn, html_scripts=False):
    """Return (template_kind, comment_grammar, exclusion_reason) for a file name."""
    name = fn.lower()
    ext = os.path.splitext(name)[1]
    if name.endswith('.blade.php'):
        return 'blade', None, None
    if ext in TEMPLATE_EXT:
        return TEMPLATE_EXT[ext], None, None
    if ext in CODE_EXT:
        return None, CODE_EXT[ext], None
    if ext in HTML_EXT and html_scripts:
        return 'generic', None, None
    if ext in HTML_EXT:
        return None, None, 'markup (.html/.htm)'
    return None, None, 'not source code (%s)' % (ext or 'no extension')


def code_view(text, kind, g):
    """Lines of the file with comments / static markup blanked (line numbers preserved)."""
    lines = mask_template(text, kind) if kind else strip_comments(text, g).split('\n')
    if text.endswith('\n'):
        lines = lines[:-1]
    return lines


def auditable_files(root, exclude_tests=False, html_scripts=False, skip_dir=(), keep_dir=(),
                    max_kb=2048):
    """Importable API: the exact file set this script counts as auditable.

    Returns (records, excluded_list, pruned_dirs); each record is a dict with
    path (relative), kind, grammar, ext, raw and auditable line counts."""
    args = argparse.Namespace(exclude_tests=exclude_tests, html_scripts=html_scripts,
                              skip_dir=list(skip_dir), keep_dir=list(keep_dir), max_kb=max_kb)
    records = []
    _, _, _, excluded_list, pruned, _ = scan(os.path.abspath(root), args, records)
    return records, excluded_list, pruned


# --------------------------------------------------------------------------- #
# Main scan
# --------------------------------------------------------------------------- #
def scan(root, args, records=None):
    skip_dirs = (SKIP_DIRS | set(args.skip_dir)) - set(args.keep_dir)
    lang = defaultdict(lambda: dict(files=0, raw=0, removed_comments_blank=0,
                                    removed_trivial=0, removed_imports=0, auditable=0))
    by_folder = defaultdict(int)
    excluded = defaultdict(lambda: [0, 0])     # reason -> [files, raw lines]
    excluded_list = []
    pruned_dirs = []
    files = []

    def exclude(rel, reason, text=None):
        excluded[reason][0] += 1
        if text is not None:
            excluded[reason][1] += len(text.splitlines())
        excluded_list.append((rel, reason))

    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        parts = [] if rel_dir == '.' else rel_dir.split(os.sep)
        keep = []
        for d in sorted(dirnames):
            if d in skip_dirs or (args.exclude_tests and d in TEST_DIRS):
                pruned_dirs.append(os.path.join(rel_dir, d) if parts else d)
            else:
                keep.append(d)
        dirnames[:] = keep
        low_parts = [p.lower() for p in parts]
        in_asset_lib = any(p in ASSET_LIB_DIRS and any(q in WEB_DIRS for q in low_parts[:i])
                           for i, p in enumerate(low_parts))

        for fn in sorted(filenames):
            path = os.path.join(dirpath, fn)
            rel = os.path.relpath(path, root)
            ext = os.path.splitext(fn.lower())[1]
            kind, g, why = detect_kind(fn, args.html_scripts)
            if why:
                exclude(rel, why)
                continue

            if os.path.islink(path):
                exclude(rel, 'symlink')
                continue
            if args.exclude_tests and TEST_FILE.search(fn):
                exclude(rel, 'unit test file')
                continue
            if MIN_NAME.search(fn):
                exclude(rel, 'minified / bundled asset')
                continue
            if GEN_NAME.search(fn):
                exclude(rel, 'generated file (by name)')
                continue
            is_js = ext in ('.js', '.mjs', '.cjs')
            if is_js and LIB_NAME.match(fn):
                exclude(rel, 'third-party JS library (by name)')
                continue
            if ext in ASSET_EXT and in_asset_lib:
                exclude(rel, 'third-party asset folder (static/.../lib)')
                continue

            text, err = read_text(path, args.max_kb * 1024)
            if text is None:
                exclude(rel, err)
                continue
            head = '\n'.join(text.split('\n', 12)[:12])
            if GEN_HEADER.search(head):
                exclude(rel, 'generated file / dump (by header)', text)
                continue
            if looks_minified(text):
                exclude(rel, 'minified / data (very long lines)', text)
                continue
            if is_js and looks_js_library(text):
                exclude(rel, 'third-party JS library (license/version header)', text)
                continue

            lines = code_view(text, kind, g)
            raw = len(text.splitlines())
            b, t, imp, code = classify_lines(lines)
            b = max(raw - t - imp - code, 0)
            label = '.blade.php' if kind == 'blade' else ext
            s = lang[label]
            s['files'] += 1
            s['raw'] += raw
            s['removed_comments_blank'] += b
            s['removed_trivial'] += t
            s['removed_imports'] += imp
            s['auditable'] += code
            by_folder[parts[0] if parts else '(root)'] += code
            files.append((code, raw, rel))
            if records is not None:
                records.append(dict(path=rel, kind=kind, grammar=g, ext=label,
                                    raw=raw, auditable=code))

    return lang, by_folder, excluded, excluded_list, pruned_dirs, files


def fmt(n):
    return '{:,}'.format(n).replace(',', ' ')


# --------------------------------------------------------------------------- #
# Terminal colors (auto-disabled when piped, with NO_COLOR, or --no-color)
# --------------------------------------------------------------------------- #
class C:
    on = False
    RESET = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    GREY = '\033[90m'
    BRED = '\033[91m'
    BGREEN = '\033[92m'
    BYELLOW = '\033[93m'
    BCYAN = '\033[96m'


def setup_colors(mode):
    if mode == 'never':
        C.on = False
    elif mode == 'always':
        C.on = True
    else:
        C.on = (sys.stdout.isatty() and 'NO_COLOR' not in os.environ
                and os.environ.get('TERM') != 'dumb')
    if C.on and os.name == 'nt':
        os.system('')          # enables ANSI escape processing on Windows 10+


def c(text, *styles):
    """Color an already padded string (padding first keeps columns aligned)."""
    if not C.on or not styles:
        return text
    return ''.join(styles) + text + C.RESET


def effort_color(days):
    if days <= 5:
        return C.BGREEN
    if days <= 15:
        return C.BYELLOW
    return C.BRED


def bar(frac, width=20):
    n = int(round(frac * width))
    full, empty = '\u2588', '\u2591'
    try:
        (full + empty).encode(sys.stdout.encoding or 'ascii')
    except (UnicodeEncodeError, LookupError):
        full, empty = '#', '.'
    return c(full * n, C.CYAN) + c(empty * (width - n), C.GREY)


def main():
    ap = argparse.ArgumentParser(description='Estimate auditable lines of code and audit days.')
    ap.add_argument('folder', help='source tree to analyze')
    ap.add_argument('--rate', type=int, default=3000, help='auditable lines per day (default 3000)')
    ap.add_argument('--exclude-tests', action='store_true', help='drop unit/e2e test code')
    ap.add_argument('--html-scripts', action='store_true',
                    help='count inline <script> blocks and template expressions in .html files')
    ap.add_argument('--skip-dir', action='append', default=[], help='extra folder name to ignore')
    ap.add_argument('--keep-dir', action='append', default=[],
                    help='folder name to scan even though ignored by default (e.g. --keep-dir lib)')
    ap.add_argument('--max-kb', type=int, default=2048, help='skip files larger than this (KB)')
    ap.add_argument('--top', type=int, default=10, help='show N largest auditable files')
    ap.add_argument('--list-excluded', action='store_true', help='print every excluded file')
    ap.add_argument('--json', metavar='FILE', help='also write the full report as JSON')
    ap.add_argument('--color', choices=('auto', 'always', 'never'), default='auto',
                    help='colored output (default: auto, off when piped or NO_COLOR is set)')
    ap.add_argument('--no-color', dest='color', action='store_const', const='never',
                    help='same as --color never')
    args = ap.parse_args()
    setup_colors(args.color)

    root = os.path.abspath(args.folder)
    if not os.path.isdir(root):
        sys.exit(c('error:', C.BRED, C.BOLD) + ' %s is not a directory' % root)

    lang, by_folder, excluded, excluded_list, pruned, files = scan(root, args)
    total = {k: sum(v[k] for v in lang.values()) for k in
             ('files', 'raw', 'removed_comments_blank', 'removed_trivial',
              'removed_imports', 'auditable')}
    days_exact = total['auditable'] / float(args.rate) if args.rate else 0
    days_rounded = math.ceil(days_exact * 2) / 2.0

    w = 78
    rule = c('=' * w, C.BLUE)
    thin = ' ' + c('-' * (w - 2), C.GREY)

    def section(title):
        print('\n ' + c(title, C.BOLD, C.MAGENTA))

    print(rule)
    print(' ' + c('AUDIT SCOPE ESTIMATION', C.BOLD, C.BCYAN) + c('  -  ', C.GREY) + c(root, C.CYAN))
    print(rule)
    print('\n Source files analyzed : %s   %s' % (
        c(fmt(total['files']), C.BOLD),
        c('(raw lines: %s)' % fmt(total['raw']), C.GREY)))

    row = ' %-12s %7s %10s %12s %9s %8s %11s'
    print('\n' + c(row % ('Extension', 'Files', 'Raw', 'Cmt/Blank/', 'Trivial', 'Imports',
                          'AUDITABLE'), C.BOLD))
    print(c(row % ('', '', '', 'Markup', '', '', ''), C.BOLD))
    print(thin)

    def table_row(label, s, label_style=(C.CYAN,), total_row=False):
        cells = [('%-12s' % label, label_style),
                 ('%7s' % fmt(s['files']), ()),
                 ('%10s' % fmt(s['raw']), ()),
                 ('%12s' % fmt(s['removed_comments_blank']), (C.GREY,)),
                 ('%9s' % fmt(s['removed_trivial']), (C.GREY,)),
                 ('%8s' % fmt(s['removed_imports']), (C.GREY,)),
                 ('%11s' % fmt(s['auditable']), (C.BGREEN, C.BOLD))]
        if total_row:
            cells = [(t, st + (C.BOLD,)) for t, st in cells]
        print(' ' + ' '.join(c(t, *st) for t, st in cells))

    for ext, s in sorted(lang.items(), key=lambda kv: -kv[1]['auditable']):
        table_row(ext, s)
    print(thin)
    table_row('TOTAL', total, label_style=(C.BOLD,), total_row=True)

    if len(by_folder) > 1:
        section('Auditable lines by top-level folder:')
        for d, n in sorted(by_folder.items(), key=lambda kv: -kv[1]):
            if n:
                frac = float(n) / total['auditable'] if total['auditable'] else 0
                print('   %s %s  %s %s' % (c('%-34s' % d[:34], C.CYAN), c('%10s' % fmt(n), C.BOLD),
                                           bar(frac), c('%5.1f%%' % (frac * 100), C.GREY)))

    if files and args.top:
        section('Largest auditable files:')
        biggest = sorted(files, reverse=True)[:args.top]
        for code, raw, rel in biggest:
            style = C.BRED if code >= 1000 else C.BYELLOW if code >= 300 else C.GREEN
            head, tail = os.path.split(rel)
            shown = (c(head + os.sep, C.GREY) if head else '') + tail
            print('   %s  %s' % (c('%8s' % fmt(code), style, C.BOLD), shown))

    section('Excluded files:')
    if excluded:
        for reason, (n, lines) in sorted(excluded.items(), key=lambda kv: -kv[1][0]):
            extra = c('  (%s lines)' % fmt(lines), C.GREY) if lines else ''
            print('   %s  %s%s' % (c('%6s' % fmt(n), C.YELLOW), reason, extra))
    else:
        print('   ' + c('none', C.GREY))
    if pruned:
        print('\n ' + c('Ignored folders (%d):' % len(pruned), C.BOLD, C.MAGENTA) + ' ' +
              c(', '.join(pruned[:15]) + (' ...' if len(pruned) > 15 else ''), C.GREY))

    ecol = effort_color(days_rounded)
    print('\n' + rule)
    print(' %s %s' % (c('AUDITABLE LINES :', C.BOLD), c(fmt(total['auditable']), C.BGREEN, C.BOLD)))
    print(' %s %s  ->  %s %s' % (
        c('ESTIMATED EFFORT:', C.BOLD),
        c('%.2f days' % days_exact, C.GREY),
        c('%.1f days' % days_rounded, ecol, C.BOLD),
        c('(at %s lines/day, rounded up to 0.5)' % fmt(args.rate), C.GREY)))
    print(rule)

    if args.list_excluded:
        section('Excluded file list:')
        for rel, reason in excluded_list:
            print('   %s %s' % (c('[%s]' % reason, C.YELLOW), rel))
        for d in pruned:
            print('   %s %s/' % (c('[ignored folder]', C.YELLOW), d))

    if args.json:
        report = dict(root=root, rate=args.rate, totals=total,
                      days_exact=round(days_exact, 2), days_rounded=days_rounded,
                      by_extension=lang, by_folder=by_folder,
                      excluded_summary={k: dict(files=v[0], lines=v[1]) for k, v in excluded.items()},
                      excluded_files=[dict(path=p, reason=r) for p, r in excluded_list],
                      ignored_folders=pruned,
                      files=[dict(path=r, raw=w_, auditable=n_) for n_, w_, r in
                             sorted(files, reverse=True)])
        with open(args.json, 'w') as f:
            json.dump(report, f, indent=2)
        print('\n ' + c('JSON report written to', C.GREY) + ' ' + c(args.json, C.CYAN))


if __name__ == '__main__':
    main()
