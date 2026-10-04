#!/usr/bin/env python3
"""Structural analyzers used by codit.py.

Line-oriented regex rules cannot see what is *missing* (an endpoint without a guard) nor follow a
value from a request parameter to a sink a few lines later. The analyzers in this module work on
whole files, functions and the project:

  authz     access control (OWASP A01): route / handler guard detection for Spring, JAX-RS,
            Express, NestJS, Flask, Django / DRF, FastAPI, Laravel, Symfony, plain PHP, WordPress,
            ASP.NET Core, Rails and Go routers; sibling / project consistency, write endpoints
            guarded by read permissions, IDOR candidates, globally permissive security
            configuration, method security annotations that are never enabled
  authflow  authentication and MFA flows (OWASP A07): session issued before the second factor,
            fail-open OTP verification, environment bypasses, 2FA disable without
            re-authentication, password reset that logs the user in, OTP verification without
            attempt limiting, guards that accept pending-2FA sessions, session fixation
  taint     intra-procedural taint-lite (A03 / A01 / A10): request data assigned to variables and
            reaching SQL, command, path, URL, redirect, eval, template, deserialization, response,
            header and log sinks a few lines later
  deps      offline dependency checks (A06:2021 / A03:2025): well-known vulnerable versions and
            unpinned / insecure dependency sources in manifests and lock files

Every analyzer returns plain dicts (see finding()) that codit.py turns into findings.
"""

import bisect
import json
import os
import re
from collections import defaultdict

import codit_estimate as AS

LANG_OF_EXT = {}
for _l, _exts in {
    'java': '.java .kt .kts .scala .groovy',
    'js': '.js .mjs .cjs .jsx .ts .tsx .mts .cts .vue .svelte',
    'py': '.py .pyw',
    'php': '.php .phtml .php3 .php4 .php5 .php7 .inc .blade.php',
    'cs': '.cs',
    'rb': '.rb .rake',
    'go': '.go',
}.items():
    for _e in _exts.split():
        LANG_OF_EXT[_e] = _l


def finding(rel, line, rule, title, message, severity, confidence, cwe):
    return dict(path=rel, line=max(1, int(line or 1)), rule=rule, title=title, message=message,
                severity=severity, confidence=confidence, cwe=cwe)


# =========================================================================== #
# Source model: comment-free code, string-masked twin, line mapping
# =========================================================================== #
_STR_RX = {
    'java': re.compile(r'"""[\s\S]*?"""|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\''),
    'cs': re.compile(r'\$?@"(?:""|[^"])*"|@?\$"(?:\\.|""|[^"\\\n])*"|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\''),
    'js': re.compile(r'`(?:\\.|[^`\\])*`|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\''),
    'php': re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''),
    'py': re.compile(r'[rRbBuUfF]{0,2}(?:"""[\s\S]*?"""|\'\'\'[\s\S]*?\'\'\'|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\')'),
    'rb': re.compile(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\''),
    'go': re.compile(r'`[^`]*`|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\''),
}


def _blank(s):
    return re.sub(r'[^\n]', ' ', s)


def mask_strings(code, lang):
    """Same-length copy of the code with string literal contents replaced by spaces."""
    rx = _STR_RX.get(lang)
    if not rx:
        return code

    def rep(m):
        s = m.group(0)
        i = len(s) - len(s.lstrip('rRbBuUfF$@'))
        q = 3 if s[i:i + 3] in ('"""', "'''") else 1
        if len(s) < i + 2 * q:
            return s
        return s[:i + q] + _blank(s[i + q:len(s) - q]) + s[len(s) - q:]
    return rx.sub(rep, code)


class Src(object):
    def __init__(self, rel, text, code, lang):
        self.rel, self.text, self.code, self.lang = rel, text, code, lang
        self.masked = mask_strings(code, lang)
        self.nl = [m.start() for m in re.finditer('\n', code)]
        self.lines = code.split('\n')
        self.raw_lines = text.split('\n')
        self.low_rel = rel.replace('\\', '/').lower()
        self._funcs = None
        self._members = None

    def line_of(self, off):
        return bisect.bisect_left(self.nl, off) + 1

    def off_of_line(self, line):
        return 0 if line <= 1 else (self.nl[line - 2] + 1 if line - 2 < len(self.nl) else len(self.code))

    def line_text(self, line):
        return self.lines[line - 1] if 0 < line <= len(self.lines) else ''

    def raw_line(self, line):
        return self.raw_lines[line - 1] if 0 < line <= len(self.raw_lines) else ''

    def above(self, line, n=6):
        return '\n'.join(self.lines[max(0, line - 1 - n):line - 1])


_PAIR = {'(': ')', '[': ']', '{': '}', '<': '>'}
_BR_RX = {o: re.compile('[%s%s]' % (re.escape(o), re.escape(c))) for o, c in _PAIR.items()}


def match_close(s, i, limit=None):
    """Index of the bracket closing the one at s[i] (strings must already be masked)."""
    o = s[i]
    cl = _PAIR[o]
    end = limit or len(s)
    depth = 0
    for m in _BR_RX[o].finditer(s, i, end):
        if m.group() == o:
            depth += 1
        else:
            depth -= 1
            if depth == 0:
                return m.start()
    return end - 1


def split_top(masked, code=None, sep=',', angle=False):
    """Split on top-level separators; returns slices of `code` (defaults to masked)."""
    code = masked if code is None else code
    out, depth, start = [], 0, 0
    opens, closes = ('([{<', ')]}>') if angle else ('([{', ')]}')
    for i, ch in enumerate(masked):
        if ch in opens:
            depth += 1
        elif ch in closes:
            if not (angle and ch == '>' and i > 0 and masked[i - 1] == '-'):
                depth -= 1
        elif ch == sep and depth <= 0:
            out.append(code[start:i])
            start = i + 1
    out.append(code[start:])
    return [x for x in out if x.strip()]


def strings_in(text):
    return re.findall(r'"((?:\\.|[^"\\\n])*)"|\'((?:\\.|[^\'\\\n])*)\'|`([^`$]*)`', text)


def first_string(text):
    for a, b, c in strings_in(text):
        v = a or b or c
        if v is not None:
            return v
    return None


def all_strings(text):
    return [a or b or c for a, b, c in strings_in(text) if (a or b or c)]


# =========================================================================== #
# Annotations / decorators / attributes and member declarations
# =========================================================================== #
class Ann(object):
    __slots__ = ('name', 'args', 'start', 'end', 'line', 'full')

    def __repr__(self):
        return '@%s(%s)' % (self.name, self.args[:40])


class Member(object):
    """A class or a method / function declaration with the annotations attached to it."""
    __slots__ = ('kind', 'name', 'anns', 'line', 'off', 'name_off', 'params', 'params_masked',
                 'body', 'cls', 'header', 'src', 'name_line')

    def body_text(self):
        return self.src.code[self.body[0]:self.body[1] + 1] if self.body else ''

    def body_masked(self):
        return self.src.masked[self.body[0]:self.body[1] + 1] if self.body else ''

    def ann(self, *names):
        return [a for a in self.anns if a.name in names]


ANN_RX = re.compile(r'@([A-Za-z_][\w.]*)')
_MODS = (r'(?:public|private|protected|internal|static|final|abstract|synchronized|default|native|'
         r'transient|volatile|strictfp|override|open|suspend|inline|operator|infix|tailrec|external|'
         r'async|export|declare|readonly|sealed|data|lateinit|const|virtual|partial|unsafe|extern|new|fun)')
GAP_RX = re.compile(r'^(?:\s|' + _MODS + r'\b)*$')
CLASS_RX = re.compile(r'(?<![\w.$@:])(?:@interface|class|interface|enum|record|object|trait|struct)\s+([A-Za-z_]\w*)')
CALL_RX = re.compile(r'(?<![\w$.@])([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*>\s*)?\(')
# modifiers / return type before a method name (tokens may not be annotation names: "@GetMapping public X")
TYPE_PREFIX_RX = re.compile(r'(?:(?<![@\w$.\[\]])[A-Za-z_$][\w$.<>\[\],?]*(?:<[^()]*?>)?(?:\[\])*\??\s+)*$')
_KW_COMMON = {'if', 'for', 'while', 'switch', 'catch', 'return', 'new', 'throw', 'else', 'do', 'try', 'super',
              'this', 'typeof', 'await', 'yield', 'case', 'synchronized', 'assert', 'instanceof', 'sizeof'}
LANG_KEYWORDS = {
    'java': _KW_COMMON | {'when'},
    'cs': _KW_COMMON | {'using', 'lock', 'foreach', 'fixed', 'nameof', 'checked', 'unchecked', 'default', 'when',
                        'where', 'get', 'set'},
    'js': _KW_COMMON | {'function', 'void', 'with', 'import', 'export'},
    'php': _KW_COMMON | {'elseif', 'match', 'fn', 'echo', 'print', 'isset', 'empty', 'unset', 'list', 'array',
                         'require', 'include', 'require_once', 'include_once', 'declare', 'function', 'foreach'},
    'go': _KW_COMMON | {'func', 'select', 'go', 'defer', 'range'},
}
KEYWORDS = set().union(*LANG_KEYWORDS.values())


def scan_annotations(src):
    """Java / Kotlin / TypeScript style @Name(args)."""
    s, code = src.masked, src.code
    out, pos, n = [], 0, len(s)
    while True:
        m = ANN_RX.search(s, pos)
        if not m:
            break
        st = m.start()
        if st > 0 and (s[st - 1].isalnum() or s[st - 1] in '_.$'):
            pos = m.end()
            continue
        a = Ann()
        a.name = m.group(1).rsplit('.', 1)[-1]
        k = m.end()
        while k < n and s[k] in ' \t':
            k += 1
        if k < n and s[k] == '(':
            c = match_close(s, k)
            a.args, a.end = code[k + 1:c], c + 1
        else:
            a.args, a.end = '', m.end()
        a.start, a.line = st, src.line_of(st)
        a.full = code[st:a.end]
        out.append(a)
        pos = a.end
    return out


def scan_bracket_attributes(src, php=False):
    """C# [Attr(args), Other] groups and PHP 8 #[Attr(args)] groups."""
    s, code = src.masked, src.code
    out = []
    rx = re.compile(r'#\[' if php else r'\[')
    for m in rx.finditer(s):
        st = m.start()
        if not php:
            j = st - 1
            while j >= 0 and s[j] in ' \t\r\n':
                j -= 1
            if j >= 0 and s[j] not in '{};])':
                continue
        ob = m.end() - 1
        cb = match_close(s, ob)
        inner_m, inner_c = s[ob + 1:cb], code[ob + 1:cb]
        if not re.match(r'\s*[A-Za-z_]', inner_m):
            continue
        base = ob + 1
        for part_m, part_c in zip(split_top(inner_m), split_top(inner_m, inner_c)):
            mm = re.match(r'\s*(?:\w+\s*:\s*)?([A-Za-z_][\w.\\]*)\s*(\()?', part_m)
            if not mm:
                continue
            a = Ann()
            a.name = re.split(r'[.\\]', mm.group(1))[-1]
            if a.name.endswith('Attribute') and len(a.name) > 9:
                a.name = a.name[:-9]
            if mm.group(2):
                po = part_m.find('(')
                pc = match_close(part_m, po)
                a.args = part_c[po + 1:pc]
            else:
                a.args = ''
            a.start, a.end = st, cb + 1
            a.line = src.line_of(st)
            a.full = code[st:cb + 1]
            out.append(a)
        del base
    return out


def _attach(anns, s, start):
    """Annotations immediately preceding offset `start` (only whitespace / modifiers between)."""
    got = []
    pos = start
    idx = bisect.bisect_right([a.end for a in anns], start) - 1
    while idx >= 0:
        a = anns[idx]
        if a.end > pos:
            idx -= 1
            continue
        if not GAP_RX.match(s[a.end:pos]):
            break
        got.append(a)
        pos = a.start
        idx -= 1
        while idx >= 0 and anns[idx].start == a.start:      # several attributes of one [A, B] group
            got.append(anns[idx])
            idx -= 1
    got.reverse()
    return got


def parse_members(src):
    """Classes and methods (with attached annotations) of a Java / Kotlin / TS / C# / PHP file."""
    if src._members is not None:
        return src._members
    s, code = src.masked, src.code
    if src.lang == 'cs':
        anns = scan_bracket_attributes(src)
    elif src.lang == 'php':
        anns = scan_bracket_attributes(src, php=True)
    else:
        anns = scan_annotations(src)
    anns.sort(key=lambda a: (a.end, a.start))
    classes, methods = [], []
    for m in CLASS_RX.finditer(s):
        k = m.end()
        stop = re.compile(r'[{;]').search(s, k)
        if not stop or s[stop.start()] != '{':
            continue
        c = Member()
        c.kind, c.name, c.src = 'class', m.group(1), src
        c.header = code[k:stop.start()]
        st = m.start()
        mod = re.search(r'(?:(?:' + _MODS + r')\s+)+$', s[max(0, st - 120):st])
        if mod:
            st -= len(mod.group(0))
        c.off, c.name_off = st, m.start(1)
        c.anns = _attach(anns, s, st)
        c.name_line = src.line_of(m.start())
        c.line = c.anns[0].line if c.anns else c.name_line
        c.body = (stop.start(), match_close(s, stop.start()))
        c.params = c.params_masked = ''
        c.cls = None
        classes.append(c)
    spans = sorted(((c.body[0], c.body[1], c) for c in classes), key=lambda x: (x[0], x[1]))
    kw = LANG_KEYWORDS.get(src.lang, KEYWORDS)
    for m in CALL_RX.finditer(s):
        name = m.group(1)
        if name in kw:
            continue
        po = m.end() - 1
        pc = match_close(s, po)
        after = re.compile(r'\s*(?:throws\s+[\w.,\s<>]+?|:\s*[^{};=()]+(?:\([^()]*\)[^{};=]*)?|where\s[^{;]+)?\s*([{;]|=>)').match(s, pc + 1)
        if not after:
            continue
        term = after.group(1)
        st = m.start()
        before = s[max(0, st - 160):st]
        pre_tok = re.search(r'(\S+)\s*$', before)
        prev = pre_tok.group(1) if pre_tok else ''
        if prev.endswith(('.', '=', '(', ',', '!', '&', '|', '?', ':', '+', '-', '*', '/', '%', '>', '<')) \
                and not prev.endswith(('->', '=>')) and not re.search(r'[\w$>\]]\s*$', before[-2:] or ''):
            if prev.endswith(('.', '=', '(', ',', '!', '&&', '||', '?', '+')):
                continue
        if prev in ('new', 'return', 'throw', 'await', 'yield', 'else', 'case', 'typeof', 'delete',
                    'in', 'of', 'echo', 'print', 'go', 'defer'):
            continue
        if prev == 'void' and src.lang == 'js':          # JS "void expr" operator; in Java / C# it is a return type
            continue
        if prev.endswith('.') or prev.endswith('::') or prev.endswith('->'):
            continue
        has_type = bool(re.search(r'[\w$>\]?]\s+$', before)) and prev not in ('', ';', '{', '}') and \
            not prev.endswith((';', '{', '}', ')'))
        if term == ';' and not has_type:
            continue
        if term == '=>' and src.lang not in ('cs',):
            continue
        if src.lang == 'php' and prev != 'function':
            continue
        if src.lang == 'go':
            continue
        f = Member()
        f.kind, f.name, f.src = 'method', name, src
        mod = TYPE_PREFIX_RX.search(before)
        decl_st = st - (len(mod.group(0)) if mod else 0)
        f.off, f.name_off = decl_st, st
        f.anns = _attach(anns, s, decl_st) or _attach(anns, s, st)
        f.params, f.params_masked = code[po + 1:pc], s[po + 1:pc]
        f.name_line = src.line_of(st)
        f.line = f.anns[0].line if f.anns else f.name_line
        f.header = ''
        if term == '{':
            bo = after.end() - 1
            f.body = (bo, match_close(s, bo))
        else:
            f.body = None
        f.cls = None
        i = bisect.bisect_right([sp[0] for sp in spans], st) - 1
        while i >= 0:
            if spans[i][0] < st <= spans[i][1]:
                f.cls = spans[i][2]
                break
            i -= 1
        methods.append(f)
    src._members = (classes, methods)
    return src._members


def params_list(member):
    """[(annotation names, annotation args text, type, name)] of a Java / TS / C# method."""
    out = []
    pm, pc = member.params_masked, member.params
    for part_m, part_c in zip(split_top(pm, angle=True), split_top(pm, pc, angle=True)):
        anns = re.findall(r'[@\[]\s*([A-Za-z_][\w.]*)\s*(\((?:[^()]|\([^()]*\))*\))?', part_c)
        names = [a[0].rsplit('.', 1)[-1] for a in anns]
        args = ' '.join(a[1] for a in anns)
        rest = re.sub(r'@[\w.]+\s*(\((?:[^()]|\([^()]*\))*\))?|\[[^\]]*\]', ' ', part_c).strip()
        if member.src.lang == 'js':
            mm = re.match(r'(?:public|private|protected|readonly|\s)*([A-Za-z_$][\w$]*)\s*\??\s*(?::\s*(.*))?$', rest, re.S)
            name, typ = (mm.group(1), (mm.group(2) or '').strip()) if mm else (rest, '')
        else:
            toks = re.findall(r'[A-Za-z_$][\w$]*(?:<[^>]*>)?(?:\[\])*\??', rest)
            toks = [t for t in toks if t not in ('final', 'var', 'val', 'in', 'out', 'ref', 'params', 'this')]
            name = toks[-1] if toks else rest
            typ = toks[-2] if len(toks) >= 2 else ''
            if member.src.lang == 'java' and ':' in rest:          # Kotlin "name: Type"
                kk = re.match(r'\s*(?:val|var)?\s*([A-Za-z_]\w*)\s*:\s*([\w.<>?]+)', rest)
                if kk:
                    name, typ = kk.group(1), kk.group(2)
        out.append((names, args, typ, name))
    return out


# =========================================================================== #
# Python blocks (decorators + def / class with indentation-based bodies)
# =========================================================================== #
class PyItem(object):
    __slots__ = ('kind', 'name', 'indent', 'decorators', 'line', 'def_line', 'header', 'body_start',
                 'body_end', 'parent', 'src')

    def body_text(self):
        return '\n'.join(self.src.lines[self.body_start - 1:self.body_end])

    def deco_names(self):
        return [d[0] for d in self.decorators]


def _py_join_balanced(lines, i):
    text = lines[i]
    j = i
    while (text.count('(') + text.count('[') + text.count('{')) > (text.count(')') + text.count(']') + text.count('}')) \
            and j + 1 < len(lines) and j - i < 40:
        j += 1
        text += '\n' + lines[j]
    return text, j


def py_items(src):
    if src._members is not None:
        return src._members
    lines = src.code.split('\n')
    mlines = src.masked.split('\n')
    items, decos, stack = [], [], []
    i, n = 0, len(lines)
    while i < n:
        s = mlines[i].strip()
        if s.startswith('@'):
            txt, j = _py_join_balanced(mlines, i)
            real = '\n'.join(lines[i:j + 1]).strip()[1:]
            name = re.match(r'\s*([\w.]+)', real)
            decos.append((name.group(1) if name else real, real, i + 1))
            i = j + 1
            continue
        m = re.match(r'^(\s*)(async\s+def|def|class)\s+(\w+)', mlines[i])
        if m:
            indent = len(m.group(1).expandtabs())
            hdr, j = _py_join_balanced(mlines, i)
            while not re.search(r':\s*$', hdr) and j + 1 < n and j - i < 40:
                j += 1
                hdr += '\n' + mlines[j]
            k = j + 1
            last = j
            while k < n:
                t = mlines[k]
                if t.strip():
                    if len(t) - len(t.lstrip()) <= indent and not t.lstrip().startswith((')', ']', '}')):
                        break
                    last = k
                k += 1
            it = PyItem()
            it.kind = 'class' if m.group(2) == 'class' else 'def'
            it.name, it.indent, it.decorators, it.src = m.group(3), indent, decos, src
            it.def_line = i + 1
            it.line = decos[0][2] if decos else i + 1
            it.header = '\n'.join(lines[i:j + 1])
            it.body_start, it.body_end = j + 2, last + 1
            while stack and stack[-1].indent >= indent:
                stack.pop()
            it.parent = stack[-1] if stack else None
            stack.append(it)
            items.append(it)
            decos = []
            i = j + 1
            continue
        if s:
            decos = []
        i += 1
    src._members = items
    return items


# =========================================================================== #
# Generic function segmentation (for auth-flow and taint analysis)
# =========================================================================== #
class Func(object):
    __slots__ = ('name', 'line', 'params', 'start', 'end', 'src', 'decor', 'cls')

    def body(self):
        return self.src.code[self.start:self.end]

    def masked(self):
        return self.src.masked[self.start:self.end]

    def body_lines(self):
        """[(line number, code line)] of the function body."""
        a, b = self.src.line_of(self.start), self.src.line_of(max(self.start, self.end - 1))
        return [(k, self.src.line_text(k)) for k in range(a, b + 1)]


_JS_ARROW = re.compile(r'(?:\basync\s+)?(?:\(([^()]*(?:\([^()]*\)[^()]*)*)\)|\b([A-Za-z_$][\w$]*))\s*(?::\s*[\w<>\[\]|,. ]+)?\s*=>\s*\{')
_JS_FUNC = re.compile(r'\bfunction\b\s*\*?\s*([A-Za-z_$][\w$]*)?\s*\(')
_PHP_FUNC = re.compile(r'\b(?:function|fn)\s*&?\s*([A-Za-z_]\w*)?\s*\(')
_GO_FUNC = re.compile(r'\bfunc\s*(?:\([^)]*\)\s*)?([A-Za-z_]\w*)?\s*\(')


def functions(src):
    if src._funcs is not None:
        return src._funcs
    s, code = src.masked, src.code
    out = []
    if src.lang == 'py':
        for it in py_items(src):
            if it.kind != 'def':
                continue
            f = Func()
            f.name, f.line, f.src = it.name, it.def_line, src
            hm = re.search(r'\((.*)\)', it.header, re.S)
            f.params = hm.group(1) if hm else ''
            f.start = src.off_of_line(it.def_line)
            f.end = src.off_of_line(it.body_end + 1)
            f.decor = ' '.join(d[1] for d in it.decorators)
            f.cls = it.parent.name if it.parent is not None and it.parent.kind == 'class' else ''
            out.append(f)
    elif src.lang == 'rb':
        for m in re.finditer(r'^([ \t]*)def\s+(?:self\.)?([\w?!=]+)\s*(\(([^)]*)\))?', s, re.M):
            ind = len(m.group(1).expandtabs())
            eol = s.find('\n', m.end())
            eol = len(s) if eol < 0 else eol
            if re.search(r';\s*end\b|\bend\s*$|=\s*\S', s[m.end():eol]):          # one-line def ... end / endless def
                end = eol
            else:
                endm = re.compile(r'^[ \t]{0,%d}end\b' % ind, re.M).search(s, m.end())
                end = endm.end() if endm else len(s)
            f = Func()
            f.name, f.line, f.src = m.group(2), src.line_of(m.start()), src
            f.params = m.group(4) or ''
            f.start, f.end = m.start(), end
            f.decor = src.above(f.line, 4)
            cm = None
            for cm in re.finditer(r'^\s*class\s+([\w:]+)', s[:m.start()], re.M):
                pass
            f.cls = cm.group(1).split('::')[-1] if cm else ''
            out.append(f)
    else:
        seen = set()
        if src.lang in ('java', 'cs', 'js'):
            classes, methods = parse_members(src)
            for mbr in methods:
                if mbr.body:
                    f = Func()
                    f.name, f.line, f.src = mbr.name, mbr.name_line, src
                    f.params = mbr.params
                    f.start, f.end = mbr.body[0], mbr.body[1] + 1
                    f.decor = ' '.join(a.full for a in mbr.anns)
                    f.cls = mbr.cls.name if mbr.cls else ''
                    out.append(f)
                    seen.add(mbr.body[0])
        rxs = []
        if src.lang == 'js':
            rxs = [_JS_FUNC, _JS_ARROW]
        elif src.lang == 'php':
            rxs = [_PHP_FUNC]
        elif src.lang == 'go':
            rxs = [_GO_FUNC]
        for rx in rxs:
            for m in rx.finditer(s):
                if rx is _JS_ARROW:
                    bo = m.end() - 1
                    params = code[m.start(1):m.end(1)] if m.group(1) is not None else (m.group(2) or '')
                    name = ''
                else:
                    po = m.end() - 1
                    pc = match_close(s, po)
                    nb = re.compile(r'\s*(?:use\s*\([^)]*\)\s*)?(?::\s*[?\w\\|]+\s*)?(?:\([^)]*\)|[\w.*\[\]]+)?\s*\{').match(s, pc + 1)
                    if src.lang == 'go':
                        nb = re.compile(r'[^{};\n]*\{').match(s, pc + 1)
                    if not nb:
                        continue
                    bo = nb.end() - 1
                    params = code[po + 1:pc]
                    name = m.group(1) or ''
                if bo in seen:
                    continue
                seen.add(bo)
                f = Func()
                f.name, f.line, f.src = name, src.line_of(m.start()), src
                f.params = params
                f.start, f.end = bo, match_close(s, bo) + 1
                f.decor = src.above(f.line, 4)
                cm = None
                if src.lang in ('php', 'go'):
                    rxc = r'\bclass\s+(\w+)' if src.lang == 'php' else r'func\s*\(\s*\w+\s+\*?(\w+)\s*\)\s*' + re.escape(name)
                    for cm in re.finditer(rxc, s[:m.end()]):
                        pass
                f.cls = cm.group(1) if cm else ''
                out.append(f)
        if src.lang == 'php' and not re.search(r'\bclass\s+\w+', s):
            f = Func()                                    # plain PHP page: the top-level script is the handler
            f.name = os.path.splitext(os.path.basename(src.rel))[0]
            f.line, f.src, f.params = 1, src, '$_REQUEST'
            f.start, f.end = 0, len(s)
            f.decor, f.cls = '', ''
            out.append(f)
    out.sort(key=lambda f: f.start)
    src._funcs = out
    return out


def enclosing(funcs, off):
    best = None
    for f in funcs:
        if f.start <= off < f.end and (best is None or f.start >= best.start):
            best = f
    return best


# =========================================================================== #
# Shared vocabularies
# =========================================================================== #
# intentionally public endpoints: strong markers always count, weak ones only next to an auth context
AUTH_PATH = re.compile(
    r'(?i)(?:^|/)(?:auth|login|logout|log-in|log-out|signin|signout|sign-in|sign-out|sign_in|sign_out|signup|'
    r'sign-up|sign_up|register|registration|forgot[\w-]*|password[-_]reset[\w-]*|reset[-_]password[\w-]*|'
    r'otp|mfa|2fa|two-factor|totp|oauth2?|sso|saml|csrf|csrf-cookie|health[\w-]*|ready|readiness|liveness|ping|'
    r'captcha|webhooks?|robots\.txt|sitemap|favicon\.ico|swagger[\w-]*|api-docs|openapi[\w-]*|tokens?)(?:[/.{?]|$)')
AUTH_PATH_WEAK = re.compile(r'(?i)(?:^|/)(?:reset[\w-]*|verify[\w-]*|verification|confirm[\w-]*|activate[\w-]*|refresh[\w-]*|'
                            r'callback[\w-]*|status|version|public[\w-]*|error|docs|static|assets|live)(?:[/.{?]|$)')
AUTH_CONTEXT = re.compile(r'(?i)(auth|password|passwd|account|email|session|login|oauth|2fa|mfa|otp|user/?$|'
                          r'identity|jwt|sso)')
SELF_PATH = re.compile(r'(?i)(?:^|/)(?:me|my|mine|self|profile|current|whoami|account/me|users/me|preferences|'
                       r'change-password|update-password|password)(?:/|$)')
AUTH_NAME = re.compile(r'(?i)^(?:log_?in\w*|log_?out|sign_?in|sign_?out|sign_?up|register\w*|registration|'
                       r'forgot\w*|(?:reset|change|update|recover)_?password\w*|password_?reset\w*|otp\w*|mfa\w*|'
                       r'two_?factor\w*|login2fa|refresh_?token|oauth\w*|sso\w*|saml\w*|csrf\w*|health\w*|ping|'
                       r'captcha\w*|webhook\w*|index|home|landing|about|contact|robots|sitemap|swagger\w*|'
                       r'(?:verify|confirm|activate)_?(?:email|account|registration|otp|code|token|mfa|2fa|reset)\w*)$')
SENSITIVE_PATH = re.compile(r'(?i)(?:^|/|_|-)(?:admin\w*|manage\w*|management|role\w*|permission\w*|privilege\w*|'
                            r'users?|accounts?|members?|staff|employees?|config\w*|settings?|setup|system|audit\w*|'
                            r'actuator|internal|tenants?|organi[sz]ations?|billing|payments?|refunds?|transfers?|'
                            r'export\w*|import\w*|backup\w*|reports?|logs?|keys?|secrets?|credentials?|tokens?|'
                            r'invoices?|orders?|customers?|banks?|claims?|files?|download\w*|upload\w*|'
                            r'delete\w*|remove\w*|approve\w*|reject\w*|grant\w*|revoke\w*|impersonat\w*|'
                            r'rollover\w*|holidays?|reset\w*|debug|console|shell|exec\w*)(?:/|$|\{|_|-)')
READ_TOKENS = {'READ', 'GET', 'VIEW', 'LIST', 'SEARCH', 'SHOW', 'FETCH', 'CONSULT', 'CONSULTER', 'LIRE', 'VOIR',
               'BROWSE', 'QUERY', 'DISPLAY', 'VISUALIZE', 'VISUALISER', 'READONLY', 'VIEWER', 'R'}
WRITE_TOKENS = {'WRITE', 'UPDATE', 'EDIT', 'PUT', 'POST', 'CREATE', 'ADD', 'DELETE', 'REMOVE', 'MANAGE', 'ADMIN',
                'MODIFY', 'SAVE', 'CHANGE', 'ASSIGN', 'RESET', 'APPROVE', 'VALIDATE', 'EXECUTE', 'EXEC',
                'IMPORT', 'UPLOAD', 'PATCH', 'SET', 'GRANT', 'REVOKE', 'ROLLOVER', 'ENABLE', 'DISABLE',
                'MANAGER', 'SUPERADMIN', 'OWNER', 'ALL', 'FULL', 'W', 'RW', 'CUD', 'CRUD', 'MAINTAIN',
                'CONFIGURE', 'DESTROY', 'INSERT', 'PUBLISH', 'SUBMIT', 'TRANSFER', 'PAY', 'REFUND', 'AJOUTER',
                'MODIFIER', 'SUPPRIMER', 'CREER', 'GERER', 'GESTION', 'SUPERUSER', 'ROOT', 'EDITOR'}
POST_AS_READ = re.compile(r'(?i)(search|query|filter|find|list|lookup|export|preview|validate|check|count|'
                          r'calculate|simulate|report|kpi|stat|dashboard|graphql|batch-get|fetch|read|view)')
WRITE_VERBS = {'POST', 'PUT', 'PATCH', 'DELETE', 'ANY', None}
PRINCIPAL_TOKENS = re.compile(
    r'(?i)\b(?:principal|authentication\b|securitycontextholder|authenticationprincipal|getuserprincipal|'
    r'getremoteuser|current_?user|getcurrentuser|get_current_user|getconnecteduser|connected_?user|'
    r'authenticated_?user|logged_?(?:in_?)?user|getloggedinuser|owner_?id|ownerid|getowner|isowner|is_owner|'
    r'check_?owner\w*|assert_?owner\w*|verify_?owner\w*|ensure_?owner\w*|ownership|owned_?by|tenant\w*|'
    r'usercontext|user_context|authutils|securityutils|req\.user|req\.auth|res\.locals\.user|request\.user|'
    r'self\.request\.user|g\.user|current_identity|get_jwt_identity|auth\(\)|auth::(?:id|user)|->user\(\)|'
    r'httpcontext\.user|\buser\.(?:identity|findfirst|getclaim|claims)|claimtypes|getuserid|user_?id\s*==|'
    r'useridentity|currentprincipal|policy_scope|authorize\b|can\?|cannot\?|has_object_permission|'
    r'check_object_permissions|authorizeasync|_authorizationservice|isinrole|ctx\.state\.user|c\.get\(\s*"user|'
    r'c\.locals|getsubject|subject\.|jwt_?claims|token\.sub\b|user\.id\s*[!=]==?|\.user_id\s*[!=]=)')
ID_NAME = re.compile(r'(?i)^(?:\w*id|uuid|guid|\w*_?pk|ref|reference|number|num|no)$')


def verb_is_write(verb, path='', name=''):
    if verb in ('GET', 'HEAD', 'OPTIONS'):
        return False
    if verb == 'POST' and POST_AS_READ.search((path or '') + ' ' + (name or '')):
        return False
    return verb in WRITE_VERBS


def is_auth_endpoint(path, name=''):
    if (path and AUTH_PATH.search(path)) or (name and AUTH_NAME.match(name)):
        return True
    if path and AUTH_PATH_WEAK.search(path):
        core = re.sub(r'(?i)^/?(?:api/)?(?:v\d+/)?', '', path).strip('/')
        return bool(AUTH_CONTEXT.search(path)) or core.count('/') == 0
    return False


def is_self_endpoint(path, name=''):
    if path and '{' in path and SELF_PATH.search(path) is None:
        return False
    return bool((path and SELF_PATH.search(path)) or
                re.match(r'(?i)^(?:get|update|edit|change|set)?_?(?:my|own|current|self|me)_?\w*$|'
                         r'^(?:get|update|edit)_?profile\w*$|^(?:change|update|reset)_?password$|^me$', name or ''))


def is_sensitive(path, name=''):
    return bool(SENSITIVE_PATH.search(path or '') or SENSITIVE_PATH.search('/' + re.sub(
        r'([a-z])([A-Z])', r'\1/\2', name or '').lower()))


def perm_tokens(expr):
    return set(t.upper() for t in re.findall(r'[A-Za-z]+', re.sub(r'([a-z])([A-Z])', r'\1_\2', expr or '')))


def read_only_guard(expr):
    """True when an authorization expression only names read-type permissions."""
    toks = perm_tokens(re.sub(r'(?i)hasAuthority|hasAnyAuthority|hasRole|hasAnyRole|hasPermission|'
                              r'roleAccessHandler|Permissions|PERM\b|Policy|Roles|isAuthenticated', ' ', expr or ''))
    return bool(toks & READ_TOKENS) and not (toks & WRITE_TOKENS)


# =========================================================================== #
# Access control (OWASP A01) - endpoint model shared by all frameworks
# =========================================================================== #
LEVEL_RANK = {None: 0, 'public': 0, 'authn': 1, 'authz': 2, 'deny': 3}


def max_level(*levels):
    best = None
    for lv in levels:
        if lv == 'public' and best is None:
            best = 'public'
        elif LEVEL_RANK.get(lv, 0) > LEVEL_RANK.get(best, 0):
            best = lv
    return best


class Endpoint(object):
    __slots__ = ('src', 'line', 'verb', 'path', 'name', 'level', 'expr', 'group', 'fw', 'body', 'body_off',
                 'params', 'note', 'id_params')

    def __init__(self, src, line, verb, path, name, level, expr, group, fw):
        self.src, self.line, self.verb, self.path, self.name = src, line, verb, path or '', name or ''
        self.level, self.expr, self.group, self.fw = level, expr or '', group, fw
        self.body, self.body_off, self.params, self.note, self.id_params = '', 0, '', '', []

    def label(self):
        return '%s %s%s' % (self.verb or 'ANY', self.path or '?', (' (%s)' % self.name) if self.name else '')


INLINE_DENY = re.compile(r'(?i)AccessDenied|Forbidden|\b40[13]\b|HttpStatus\.(?:FORBIDDEN|UNAUTHORIZED)|PermissionDenied|'
                         r'abort\s*\(\s*40[13]|raise\s+\w*(?:Permission|Forbidden|Auth|Denied)|throw\s+new\s+\w*(?:Access|Forbidden|'
                         r'Security|Auth|Permission|Unauthori[sz]ed)|res\.status\(\s*40[13]|Forbid\s*\(|Unauthorized\s*\(|'
                         r'head\s*:?\s*:forbidden|not_authorized|unauthorized!')
INLINE_CHECK = re.compile(r'(?i)\b(?:check|assert|ensure|verify|require|enforce)_?(?:permission|access|role|admin|owner|'
                          r'ownership|authoriz\w*|can)\w*\s*\(|authorizationService|accessDecision|permissionEvaluator|'
                          r'\bhasPermission\s*\(|\.authorize\s*\(|\$this->authorize\s*\(|Gate::(?:authorize|allows|denies)|'
                          r'\bauthorize\s+@?\w+|policy\(|denyAccessUnlessGranted|AuthorizeAsync\s*\(|isGranted\s*\(')
SCOPED_QUERY = re.compile(r'(?i)(?:find\w*|where\w*|filter\w*|query|get\w*|select\w*|count\w*|exists\w*)\s*\([^;{}]*?'
                          r'(?:req\.user|request\.user|current_?user|principal|getConnectedUser|auth\(\)|Auth::|->user\(\)|'
                          r'User\.FindFirst|GetUserId|getName\(\)|owner|tenant)')


def inline_authz(body):
    """Handler that performs its own authorization (programmatic check or ownership comparison)."""
    if INLINE_CHECK.search(body):
        return True
    if PRINCIPAL_TOKENS.search(body) and (INLINE_DENY.search(body) or SCOPED_QUERY.search(body)):
        return True
    return False


def _prefix(path):
    parts = [p for p in re.sub(r'(?i)^/?(?:api/)?(?:v\d+/)?', '', path or '').strip('/').split('/') if p]
    return parts[0] if parts else ''


def evaluate_endpoints(eps, out, fw_label):
    """Sibling / project consistency analysis -> CWE-862 findings."""
    if not eps:
        return
    total = len(eps)
    guarded = [e for e in eps if e.level in ('authz', 'deny')]
    any_guard = [e for e in eps if e.level in ('authz', 'deny', 'authn')]
    ratio = len(guarded) / float(total)
    groups = defaultdict(list)
    for e in eps:
        groups[e.group].append(e)
    for grp, items in groups.items():
        g_authz = [e for e in items if e.level in ('authz', 'deny')]
        g_any = [e for e in items if e.level in ('authz', 'deny', 'authn')]
        for e in items:
            if e.level in ('authz', 'deny', 'public'):
                continue
            if is_auth_endpoint(e.path, e.name):
                continue
            if e.level == 'authn' and is_self_endpoint(e.path, e.name):
                continue
            if e.body and inline_authz(e.body):
                continue
            write = verb_is_write(e.verb, e.path, e.name)
            sens = is_sensitive(e.path, e.name)
            sev = conf = why = None
            same_pfx = [x for x in g_authz if e.path and x.path and
                        _prefix(e.path) == _prefix(x.path)]
            pfx_all = [x for x in items if e.path and x.path and _prefix(e.path) == _prefix(x.path)]
            if e.level is None and g_any:
                ex = (g_authz or g_any)[0]
                sev, conf = ('HIGH' if write or sens else 'MEDIUM'), 'HIGH'
                why = ('has no authentication or authorization check, while %d of %d sibling endpoints in the '
                       'same %s are protected (e.g. %s at line %d: %s)' % (
                           len(g_any), len(items), fw_label, ex.label(), ex.line, (ex.expr or ex.level)[:80]))
            elif g_authz and (len(g_authz) * 2 >= len(items) or
                              (same_pfx and (write or sens) and len(same_pfx) >= 2 and len(same_pfx) * 2 >= len(pfx_all))):
                ex = (same_pfx or g_authz)[0]
                same = bool(same_pfx)
                sev = 'HIGH' if (write or sens) else 'MEDIUM'
                conf = 'HIGH' if same else 'MEDIUM'
                why = ('is only %s, while %d of %d sibling endpoints in the same %s enforce a role / permission '
                       'check (e.g. %s at line %d: %s)' % (
                           'authenticated (any logged-in user)' if e.level == 'authn' else 'unprotected',
                           len(g_authz), len(items), fw_label, ex.label(), ex.line, (ex.expr or ex.level)[:80]))
            elif len(guarded) >= 3 and (ratio >= 0.5 or (write and ratio >= 0.3)) and not g_authz:
                sev = 'HIGH' if write and ratio >= 0.5 else ('MEDIUM' if (write or sens or ratio >= 0.7) else 'LOW')
                conf = 'MEDIUM'
                why = ('has no role / permission check although %d of %d endpoints of this application enforce one '
                       '(%s); any %s user can call it' % (len(guarded), total, guarded[0].expr[:60] or 'role check',
                                                          'authenticated' if e.level == 'authn' else 'anonymous'))
            elif e.level is None and any_guard and (write or sens):
                sev, conf = 'MEDIUM', 'LOW'
                why = ('is not protected while other endpoints of the application require authentication (%d of %d)'
                       % (len(any_guard), total))
            if sev:
                out.append(finding(e.src.rel, e.line, 'authz-missing-%s' % e.fw,
                                   'Endpoint without authorization check (%s)' % fw_label,
                                   '%s %s.%s' % (e.label(), why, (' ' + e.note) if e.note else ''),
                                   sev, conf, 862))


def check_read_guard_on_write(e, out):
    if e.level == 'authz' and e.expr and verb_is_write(e.verb, e.path, e.name) and read_only_guard(e.expr):
        out.append(finding(e.src.rel, e.line, 'authz-read-permission-on-write',
                           'State-changing endpoint guarded by a read-only permission',
                           '%s modifies data but its guard only requires a read / view permission (%s). Users '
                           'allowed to read can perform the write.' % (e.label(), e.expr.strip()[:160]),
                           'HIGH', 'MEDIUM', 863))


FIND_BY_ID = (r'\b([\w$]+)\s*\.\s*(?:findById|findByIdOrNull|getById|getReferenceById|getOne|findOne|deleteById|'
              r'existsById|find\w*ById|get\w*ById|delete\w*ById|update\w*ById|load\w*ById|fetch\w*ById|remove\w*ById|'
              r'findBy(?:Id|Uuid|Reference|Code|Number|Slug)\w*|findByPk|findUnique|findFirst|findByIdAndUpdate|'
              r'findByIdAndDelete|findByIdAndRemove|find|Find|FindAsync|get|retrieve|load|fetch|read|getBy\w*)\s*\(\s*'
              r'(?:[\w$]+\s*\.\s*)?(?:%s)\b')
REPO_RECV = re.compile(r'(?i)(repo\w*|repository|dao|mapper|store|entitymanager|em|jdbc\w*|db|session|model|'
                       r'objects|context|_context|dbcontext|collection|table|prisma\.\w+|knex|sequelize)$')


def idor_check(e, out, extra_ok=None):
    """Handler that loads an object by a client-supplied id without referencing the current user."""
    if e.level in ('authz', 'deny', 'public') or not e.body or not e.id_params:
        return
    body = e.body
    if PRINCIPAL_TOKENS.search(body) or PRINCIPAL_TOKENS.search(e.params or ''):
        return
    if extra_ok and extra_ok.search(body):
        return
    names = '|'.join(re.escape(n) for n in e.id_params if n)
    if not names:
        return
    m = re.search(FIND_BY_ID % names, body)
    if not m:
        return
    recv = m.group(1)
    if recv in ('this', 'self', 'Math', 'Optional', 'Objects', 'String', 'Integer', 'Long', 'UUID', 'map', 'params',
                'request', 'req', 'cache', 'session', 'headers', 'query', 'body', 'config', 'os', 'path'):
        return
    line = e.src.line_of(e.body_off + m.start())
    conf = 'MEDIUM' if REPO_RECV.search(recv) else 'LOW'
    out.append(finding(e.src.rel, line, 'authz-idor-%s' % e.fw, 'Object fetched by client-supplied id without ownership check',
                       '%s loads a record with the client-controlled identifier "%s" (%s) and never checks that it '
                       'belongs to the current user / tenant. Any authenticated user can access or modify other '
                       'users\' objects by changing the id (IDOR).' % (e.label(), m.group(0)[:60].split('(')[-1].strip(),
                                                                     m.group(0)[:80]),
                       'MEDIUM', conf, 639))


# =========================================================================== #
# Spring / JAX-RS / Micronaut (Java, Kotlin)
# =========================================================================== #
SPRING_MAP = {'GetMapping': 'GET', 'PostMapping': 'POST', 'PutMapping': 'PUT', 'DeleteMapping': 'DELETE',
              'PatchMapping': 'PATCH', 'RequestMapping': 'ANY'}
JAXRS_VERB = {'GET': 'GET', 'POST': 'POST', 'PUT': 'PUT', 'DELETE': 'DELETE', 'PATCH': 'PATCH', 'HEAD': 'HEAD',
              'OPTIONS': 'OPTIONS'}
MICRONAUT_VERB = {'Get': 'GET', 'Post': 'POST', 'Put': 'PUT', 'Delete': 'DELETE', 'Patch': 'PATCH'}
J_PUBLIC = {'PermitAll', 'AnonymousAllowed', 'Public', 'SkipAuth', 'NoAuth', 'AllowAnonymous', 'Unsecured',
            'PublicEndpoint', 'PublicApi', 'Anonymous'}
J_NOT_GUARD = {'AuthenticationPrincipal', 'CurrentSecurityContext', 'EnableWebSecurity', 'EnableMethodSecurity',
               'EnableGlobalMethodSecurity', 'EnableReactiveMethodSecurity', 'EnableWebFluxSecurity',
               'SecurityRequirement', 'SecurityRequirements', 'SecurityScheme', 'SecuritySchemes', 'WithMockUser',
               'WithUserDetails', 'WithAnonymousUser', 'WithSecurityContext', 'Role', 'Access', 'Requires',
               'RequiresApi', 'RoleMapping', 'ReadOnly', 'Transactional', 'Accessors', 'Secret', 'SecretKey',
               'JsonProperty', 'Column', 'Table', 'Entity', 'Override', 'Valid', 'Validated', 'Scope', 'Scheduled'}
J_GUARD_FUZZY = re.compile(r'(?i)^(?:pre|post)?(?:authoriz\w*|secured?\w*|has\w*(?:role|perm|authority|access|scope)\w*|'
                           r'is(?:admin|owner|manager|staff|superuser|allowed|authorized)\w*|\w*(?:permission|privilege|'
                           r'entitlement)s?\w*|\w*roles?(?:required|allowed|check\w*)|requires?(?:role|permission|auth|'
                           r'login|user|admin|scope)\w*|(?:admin|staff|owner|manager|internal|super\w*)only|\w*guard(?:ed)?|'
                           r'accesscontrol\w*|accesscheck\w*|check\w*(?:access|perm|role|auth)\w*|restrict\w*|acl\w*|'
                           r'rbac\w*|scopes?required)$')
DECISION_RX = re.compile(r'\s*\.\s*(permitAll|denyAll|authenticated|fullyAuthenticated|anonymous|rememberMe|hasRole|'
                         r'hasAnyRole|hasAuthority|hasAnyAuthority|hasIpAddress|access|not|hasPermission)\s*\(')
MATCHER_RX = re.compile(r'\.\s*(requestMatchers|antMatchers|mvcMatchers|regexMatchers|pathMatchers|anyRequest|anyExchange)\s*\(')
WILDCARD_PAT = re.compile(r'^/?(?:\*\*?|\*\*/\*|api(?:/v\d+)?/\*\*|v\d+/\*\*|[\w-]+/\*\*/\*|/\*\*/\*\.?\w*)$')
ADMIN_PAT = re.compile(r'(?i)(admin|manage|management|internal|console|h2-console|actuator(?!/(?:health|info)\b)|'
                       r'debug|heapdump|env\b|jolokia|users?/\*\*|roles?|permissions?)')


def ant_rx(p):
    p = p.strip()
    if not p.startswith('/'):
        p = '/' + p
    out, i = '', 0
    while i < len(p):
        if p.startswith('/**', i):
            out += '(?:/.*)?'
            i += 3
        elif p.startswith('**', i):
            out += '.*'
            i += 2
        elif p[i] == '*':
            out += '[^/]*'
            i += 1
        elif p[i] == '?':
            out += '[^/]'
            i += 1
        elif p[i] == '{':
            j = p.find('}', i)
            out += '[^/]+'
            i = (j + 1) if j > 0 else i + 1
        else:
            out += re.escape(p[i])
            i += 1
    try:
        return re.compile('^' + out + '/?$')
    except re.error:
        return re.compile('^$')


def norm_path(*parts):
    p = '/'.join(x.strip('/') for x in parts if x and x.strip('/'))
    return '/' + p if p else '/'


def java_guard(anns, custom):
    """(level, expression) of the most restrictive guard among annotations."""
    best, expr = None, ''
    for a in anns:
        n = a.name
        lv = None
        if n in J_NOT_GUARD:
            continue
        if n in J_PUBLIC:
            lv = 'public'
        elif n in ('PreAuthorize', 'PostAuthorize'):
            e = re.sub(r'\s+', ' ', a.args)
            if re.search(r'\bpermitAll\b|\bisAnonymous\s*\(', e) and not re.search(r'has\w+\(|@\w+', e):
                lv = 'public'
            elif re.fullmatch(r'''[\s"'(]*(?:isAuthenticated|isFullyAuthenticated|isRememberMe)\s*\(\s*\)[\s"')]*''', e):
                lv = 'authn'
            else:
                lv = 'authz'
        elif n == 'DenyAll':
            lv = 'deny'
        elif n in ('Secured', 'RolesAllowed', 'RequiresRoles', 'RequiresPermissions'):
            lv = 'authn' if re.search(r'IS_AUTHENTICATED', a.args) and 'ROLE' not in a.args else 'authz'
        elif n in ('RequiresAuthentication', 'RequiresUser', 'Authenticated', 'Secure', 'Protected'):
            lv = 'authn'
        elif n in custom or J_GUARD_FUZZY.match(n):
            lv = 'authz'
        if lv and (LEVEL_RANK.get(lv, 0) > LEVEL_RANK.get(best, 0) or best is None):
            best, expr = lv, ('@%s(%s)' % (n, a.args.strip())) if a.args.strip() else '@' + n
    return best, expr


def _resolve_strings(args, consts, methods_ret):
    vals = all_strings(args)
    for ident in re.findall(r'\b([A-Za-z_]\w*)\b(?:\s*\.\s*clone\s*\(\s*\))?', re.sub(r'"[^"]*"', ' ', args)):
        if ident in consts:
            vals += consts[ident]
        elif ident in methods_ret and methods_ret[ident] in consts:
            vals += consts[methods_ret[ident]]
    return vals


class SpringRule(object):
    __slots__ = ('patterns', 'rxs', 'method', 'level', 'any', 'line', 'decision', 'expr')


def analyze_spring(srcs, out):
    if not srcs:
        return
    consts, methods_ret = {}, {}
    custom_guards = set()
    uses = defaultdict(list)            # annotation name -> [(src, line)]
    enable = {'prepost': False, 'secured': False, 'jsr250': False}
    spring_sec = False
    boot = False
    for src in srcs:
        s, code = src.masked, src.code
        if 'org.springframework.security' in src.text or 'SecurityFilterChain' in s or 'HttpSecurity' in s:
            spring_sec = True
        if re.search(r'@SpringBootApplication|@EnableWebSecurity|@EnableWebFluxSecurity', s):
            boot = True
        for m in re.finditer(r'String\s*\[\s*\]\s*(\w+)\s*=\s*(?:new\s+String\s*\[\s*\]\s*)?\{', s):
            ob = m.end() - 1
            consts[m.group(1)] = all_strings(code[ob:match_close(s, ob)])
        for m in re.finditer(r'(?:val|String)\s+(\w+)\s*(?::\s*String\s*)?=\s*"([^"]*)"', code):
            consts.setdefault(m.group(1), [m.group(2)])
        for m in re.finditer(r'(\w+)\s*\(\s*\)\s*\{\s*return\s+(\w+)(?:\s*\.\s*clone\s*\(\s*\))?\s*;', s):
            methods_ret[m.group(1)] = m.group(2)
        classes, methods = parse_members(src)
        for c in classes:              # project meta-annotations: @interface IsAdmin carrying @PreAuthorize
            if '@interface' in s[max(0, c.name_off - 15):c.name_off] and \
                    java_guard(c.anns, set())[0] in ('authz', 'authn', 'deny'):
                custom_guards.add(c.name)
        for mm in re.finditer(r'@(EnableMethodSecurity|EnableGlobalMethodSecurity|EnableReactiveMethodSecurity)\b'
                              r'(?:\s*\(([^)]*)\))?', code):
            args = mm.group(2) or ''
            if mm.group(1) in ('EnableMethodSecurity', 'EnableReactiveMethodSecurity'):
                if not re.search(r'prePostEnabled\s*=\s*false', args):
                    enable['prepost'] = True
            elif re.search(r'prePostEnabled\s*=\s*true', args):
                enable['prepost'] = True
            if re.search(r'securedEnabled\s*=\s*true', args):
                enable['secured'] = True
            if re.search(r'jsr250Enabled\s*=\s*true', args):
                enable['jsr250'] = True
        for mm in re.finditer(r'@(PreAuthorize|PostAuthorize|Secured|RolesAllowed)\b', s):
            uses[mm.group(1)].append((src, src.line_of(mm.start())))

    # ---- method security never enabled -> every annotation is silently ignored
    if spring_sec and boot:
        checks = [('PreAuthorize', 'prepost', '@EnableMethodSecurity (or @EnableGlobalMethodSecurity(prePostEnabled = true))'),
                  ('PostAuthorize', 'prepost', '@EnableMethodSecurity'),
                  ('Secured', 'secured', '@EnableMethodSecurity(securedEnabled = true)'),
                  ('RolesAllowed', 'jsr250', '@EnableMethodSecurity(jsr250Enabled = true)')]
        done = set()
        for ann, key, need in checks:
            if uses.get(ann) and not enable[key] and ann not in done:
                src, line = uses[ann][0]
                done.add(ann)
                out.append(finding(src.rel, line, 'authz-method-security-disabled',
                                   '@%s used but method security is not enabled' % ann,
                                   '@%s appears on %d method(s) but %s is not declared anywhere in the project, so '
                                   'Spring ignores these annotations and the endpoints are reachable by any '
                                   'authenticated (or anonymous) user.' % (ann, len(uses[ann]), need),
                                   'HIGH', 'MEDIUM', 862))

    # ---- URL based rules in SecurityFilterChain / WebSecurityConfigurerAdapter
    blocks = []
    for src in srcs:
        s, code = src.masked, src.code
        starts = [m.start() for m in re.finditer(r'\b(?:authorizeHttpRequests|authorizeRequests|authorizeExchange)\b', s)]
        bounds = starts + [len(s)]
        for bi, st in enumerate(starts):
            rules = []
            for m in MATCHER_RX.finditer(s, st, bounds[bi + 1]):
                po = m.end() - 1
                pc = match_close(s, po)
                dm = DECISION_RX.match(s, pc + 1)
                if not dm:
                    continue
                dname = dm.group(1)
                dpo = dm.end() - 1
                dargs = code[dpo + 1:match_close(s, dpo)]
                r = SpringRule()
                r.any = m.group(1) in ('anyRequest', 'anyExchange')
                args = code[po + 1:pc]
                r.patterns = [] if r.any else _resolve_strings(args, consts, methods_ret)
                mt = re.search(r'HttpMethod\.(\w+)', args)
                r.method = mt.group(1) if mt else None
                r.rxs = [ant_rx(p) for p in r.patterns]
                r.decision = dname
                r.expr = '%s(%s)' % (dname, dargs.strip())
                if dname in ('permitAll', 'anonymous'):
                    r.level = 'public'
                elif dname == 'denyAll':
                    r.level = 'deny'
                elif dname in ('authenticated', 'fullyAuthenticated', 'rememberMe'):
                    r.level = 'authn'
                elif dname == 'access' and re.search(r'permitAll', dargs):
                    r.level = 'public'
                elif dname == 'access' and re.fullmatch(r'''[\s"']*(isAuthenticated|isFullyAuthenticated)\(\)[\s"']*''', dargs):
                    r.level = 'authn'
                else:
                    r.level = 'authz'
                r.line = src.line_of(m.start())
                rules.append(r)
                fn = enclosing(functions(src), m.start())
                cond = bool(fn and re.search(r'\bif\s*\(|\belse\b|\bwhen\b|\?', src.masked[fn.start:m.start()]))
                if r.level == 'public':
                    pats = r.patterns
                    if r.any:
                        out.append(finding(src.rel, r.line, 'authz-spring-anyrequest-permitall',
                                           'anyRequest().permitAll(): authorization disabled for all other requests',
                                           'Every request not matched by an earlier rule is allowed without '
                                           'authentication%s. Use deny-by-default (anyRequest().authenticated() or '
                                           'denyAll()).' % (' (inside a conditional branch: this applies whenever '
                                                            'that security mode is configured)' if cond else ''),
                                           'HIGH', 'HIGH', 862))
                    elif any(WILDCARD_PAT.match(p.strip()) for p in pats):
                        out.append(finding(src.rel, r.line, 'authz-spring-wildcard-permitall',
                                           'Wildcard path pattern opened to anonymous users',
                                           'Pattern(s) %s are permitAll(): the whole subtree is reachable without '
                                           'authentication.' % ', '.join(pats[:4]), 'HIGH', 'HIGH', 862))
                    else:
                        bad = [p for p in pats if ADMIN_PAT.search(p)]
                        if bad:
                            out.append(finding(src.rel, r.line, 'authz-spring-sensitive-permitall',
                                               'Sensitive path opened to anonymous users',
                                               'Sensitive pattern(s) %s are permitAll().' % ', '.join(bad[:4]),
                                               'HIGH', 'MEDIUM', 862 if not re.search('actuator|heapdump|env|jolokia',
                                                                                       ' '.join(bad)) else 200))
            only_any_public = rules and all(r.any for r in rules) and all(r.level == 'public' for r in rules)
            blocks.append(dict(src=src, rules=rules, trivial=only_any_public, line=src.line_of(st)))
        for m in re.finditer(r'\bignoring\s*\(\s*\)', s):
            seg_end = min(len(s), m.end() + 600)
            mm = re.compile(r'\.\s*(?:requestMatchers|antMatchers|mvcMatchers)\s*\(').search(s, m.end(), seg_end)
            if not mm:
                continue
            po = mm.end() - 1
            pats = _resolve_strings(code[po + 1:match_close(s, po)], consts, methods_ret)
            wild = [p for p in pats if WILDCARD_PAT.match(p.strip()) or ADMIN_PAT.search(p)]
            if wild:
                out.append(finding(src.rel, src.line_of(m.start()), 'authz-spring-web-ignoring',
                                   'Paths excluded from Spring Security entirely (web.ignoring())',
                                   'web.ignoring() removes %s from the security filter chain: no authentication, '
                                   'authorization, CSRF or security headers apply.' % ', '.join(wild[:4]),
                                   'HIGH', 'HIGH', 862))
    real_blocks = [b for b in blocks if b['rules'] and not b['trivial']]

    def url_level(path, verb):
        if not real_blocks or not path:
            return None, ''
        probe = re.sub(r'\{[^}]*\}', 'x', path)
        for r in real_blocks[0]['rules']:
            if r.method and verb and verb not in ('ANY', r.method):
                continue
            if r.any or any(rx.match(probe) for rx in r.rxs):
                return r.level, 'URL rule line %d: %s' % (r.line, r.expr[:80])
        return None, ''

    # ---- controllers and endpoints
    cls_index, methods_of = {}, defaultdict(list)
    entities = set()
    for src in srcs:
        classes, methods = parse_members(src)
        for c in classes:
            cls_index.setdefault(c.name, c)
            if any(a.name in ('Entity', 'Document', 'Table', 'MappedSuperclass') for a in c.anns):
                entities.add(c.name)
        for m in methods:
            if m.cls is not None:
                methods_of[id(m.cls)].append(m)

    def mapping(m):
        for a in m.anns:
            if a.name in SPRING_MAP or a.name in JAXRS_VERB or (a.name in MICRONAUT_VERB and m.src.lang == 'java'):
                return a
        return None

    def ann_path(anns):
        for a in anns:
            if a.name in SPRING_MAP or a.name in ('Path', 'Controller') or a.name in MICRONAUT_VERB:
                vals = re.search(r'(?:value|path)\s*=\s*\{?\s*"([^"]*)"', a.args)
                if vals:
                    return vals.group(1)
                v = first_string(a.args)
                if v is not None:
                    return v
                ident = re.match(r'\s*(?:value\s*=\s*)?([\w.]+)\s*$', a.args or '')
                if ident and ident.group(1).rsplit('.', 1)[-1] in consts:
                    return consts[ident.group(1).rsplit('.', 1)[-1]][0]
        return ''

    def verb_of(anns):
        for a in anns:
            if a.name in SPRING_MAP:
                if a.name == 'RequestMapping':
                    mm = re.search(r'RequestMethod\.(\w+)', a.args)
                    return mm.group(1) if mm else 'ANY'
                return SPRING_MAP[a.name]
            if a.name in JAXRS_VERB:
                return JAXRS_VERB[a.name]
            if a.name in MICRONAUT_VERB:
                return MICRONAUT_VERB[a.name]
        return 'ANY'

    def supers(c):
        names = re.findall(r'\b(?:implements|extends)\s+([\w.<>,\s]+)', c.header or '') + \
            re.findall(r':\s*([\w.<>(),\s]+)$', c.header or '')
        res = []
        for grp in names:
            for n in re.findall(r'([A-Z]\w*)', re.sub(r'<[^>]*>', '', grp)):
                if n in cls_index and cls_index[n] is not c:
                    res.append(cls_index[n])
        return res

    eps = []
    handled = set()
    controllers = [c for c in cls_index.values()
                   if any(a.name in ('RestController', 'Controller', 'Path', 'RequestMapping') for a in c.anns)
                   or any(mapping(m) for m in methods_of[id(c)])]
    for c in controllers:
        is_iface = bool(re.search(r'\binterface\s*$', c.src.masked[c.off:c.name_off]))
        if is_iface and id(c) in handled:
            continue
        chain = supers(c)
        for sup in chain:
            chain += [x for x in supers(sup) if x not in chain]
        if is_iface:
            impls = [k for k in controllers if c in supers(k)]
            if impls:
                continue
        for sup in chain:
            handled.add(id(sup))
        own = methods_of[id(c)]
        candidates = []
        for m in own:
            if mapping(m):
                candidates.append((m, m, None))
        own_names = set(m.name for m in own if mapping(m))
        for sup in chain:
            for im in methods_of[id(sup)]:
                if mapping(im) and im.name not in own_names:
                    impl = next((m for m in own if m.name == im.name), None)
                    candidates.append((impl or im, im, sup))
        cls_anns = list(c.anns) + [a for sup in chain for a in sup.anns]
        prefix = ann_path(c.anns) or next((ann_path(sup.anns) for sup in chain if ann_path(sup.anns)), '')
        for impl, mapm, sup in candidates:
            manns = list(impl.anns) + ([a for a in mapm.anns] if mapm is not impl else [])
            mlevel, mexpr = java_guard(manns, custom_guards)
            clevel, cexpr = java_guard(cls_anns, custom_guards)
            verb = verb_of(mapm.anns)
            path = norm_path(prefix, ann_path([a for a in mapm.anns if a.name != 'RequestMapping' or a is mapping(mapm)]))
            level, expr = (mlevel, mexpr) if mlevel else (clevel, cexpr)
            note = ''
            if level in (None, 'authn'):
                ul, uexpr = url_level(path, verb)
                if ul in ('authz', 'deny', 'public') or (ul == 'authn' and level is None):
                    level, expr, note = ul, uexpr, ''
                elif ul is None and real_blocks:
                    note = 'No URL rule of the security configuration covers it with a role check.'
            mp = mapping(mapm)
            e = Endpoint(mapm.src, mp.line, verb, path, impl.name, level, expr, c.name, 'spring')
            e.note = note
            if impl.body:
                e.body, e.body_off = impl.body_text(), impl.body[0]
            plist = params_list(mapm) or params_list(impl)
            e.params = mapm.params + ' ' + impl.params
            ids = []
            for names, args, typ, pname in plist:
                if any(n in ('PathVariable', 'RequestParam', 'PathParam', 'QueryParam') for n in names):
                    if ID_NAME.match(pname) or re.search(r'(?i)id"', args):
                        ids.append(pname)
            for v in re.findall(r'\{(\w+)[}:]', path):
                if ID_NAME.match(v):
                    ids.append(v)
            e.id_params = ids
            eps.append(e)
            check_read_guard_on_write(e, out)
            idor_check(e, out)
            if impl.body:
                for names, args, typ, pname in params_list(impl) or plist:
                    base_typ = typ.split('<')[0]
                    if 'RequestBody' in names and (base_typ in entities or (not entities and re.match(
                            r'(?:App|Application)?(?:User|Account|Customer|Member|Employee|Profile)$', base_typ))):
                        mm = re.search(r'\.\s*(?:save|saveAndFlush|saveAll|merge|persist|update|insert)\s*\(\s*%s\b'
                                       % re.escape(pname), impl.body_text())
                        if mm:
                            out.append(finding(impl.src.rel, impl.src.line_of(impl.body[0] + mm.start()),
                                               'authz-mass-assignment-entity',
                                               'JPA entity bound directly from the request body and persisted',
                                               '%s binds the whole request body to the persistent entity %s and saves '
                                               'it: clients can set any column (owner, role, status, balances...). '
                                               'Bind a DTO with an explicit field allow-list.' % (e.label(), typ),
                                               'MEDIUM', 'MEDIUM', 915))
    evaluate_endpoints(eps, out, 'controller')
    if eps and not any(e.level in ('authz', 'deny') for e in eps) and len(eps) >= 6 and real_blocks:
        b = real_blocks[0]
        if not any(r.level == 'authz' for r in b['rules']):
            out.append(finding(b['src'].rel, b['line'], 'authz-authentication-only',
                               'No role-based authorization anywhere in the application',
                               '%d endpoints were found and none enforces a role / permission (no @PreAuthorize, '
                               '@Secured, @RolesAllowed or hasRole URL rule): every authenticated user can call every '
                               'endpoint, including administrative ones.' % len(eps), 'MEDIUM', 'LOW', 862))


# =========================================================================== #
# Express / Koa / Fastify style routers and NestJS (JavaScript / TypeScript)
# =========================================================================== #
EXPRESS_ROUTE = re.compile(r'(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(get|post|put|patch|delete|del|all|options|head)\s*\(')
EXPRESS_USE = re.compile(r'(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*(use|register)\s*\(')
EXPRESS_CHAIN = re.compile(r'(?<![\w$.])([A-Za-z_$][\w$]*)\s*\.\s*route\s*\(')
ROUTER_INIT = re.compile(r'\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*(?::\s*[\w.<>]+\s*)?=\s*(?:express\s*\(\s*\)|'
                         r'(?:express\s*\.\s*)?Router\s*\(|new\s+Router\s*\(|require\(\s*["\']express["\']\s*\)\s*'
                         r'(?:\.\s*Router)?\s*\(|fastify\s*\(|Fastify\s*\(|new\s+Koa\s*\(|new\s+Hono\s*\(|'
                         r'new\s+KoaRouter\s*\(|createRouter\s*\()')
EXPRESS_RECV = re.compile(r'(?i)^(?:app|router|api|apirouter|routes?|server|r|admin\w*|\w*router|\w*app|v\d+|srv|web|'
                          r'private\w*|protected\w*|public\w*|secure\w*|\w*routes|fastify|instance)$')
AUTHN_MW = re.compile(r'(?i)(?<![\w$])(?:auth\w*|authenticate\w*|is_?auth\w*|ensure_?(?:auth|logged|login|user|session|'
                      r'admin|role|perm)\w*|require_?(?:auth|login|user|session|token|admin|role|perm|scope)\w*|'
                      r'verify_?(?:token|jwt|auth|user|session|access)\w*|check_?(?:auth|token|jwt|session|login|user)\w*|'
                      r'protect\w*|guard\w*|passport\s*\.\s*authenticate|jwt\w*|express_?jwt|logged_?in\w*|'
                      r'is_?logged\w*|login_?required|with_?auth\w*|require_?session|validate_?(?:token|jwt|session|'
                      r'user)\w*|bearer\w*|api_?key\w*|firebase_?auth|clerk\w*|secured?\w*|session_?required)(?![\w$])')
AUTHZ_MW = re.compile(r'(?i)(?<![\w$])(?:is_?admin\w*|admin\w*|require_?(?:admin|role|permission|perm|scope|owner|staff)\w*|'
                      r'ensure_?(?:admin|role|permission|owner)\w*|check_?(?:role|permission|perm|admin|access|scope|'
                      r'owner)\w*|has_?(?:role|permission|perm|scope|access)\w*|authoriz\w*|permit\w*|acl\w*|rbac\w*|'
                      r'can(?:[A-Z_]\w*)?|roles?(?:[A-Z_]\w*)?|restrict\w*|is_?owner\w*|only_?\w+|\w+_?only|scope\w*|'
                      r'polic(?:y|ies)\w*|abilit\w*|grant\w*|allow_?roles?\w*|access_?control\w*|permission\w*)(?![\w$])')


def mw_level(text):
    if AUTHZ_MW.search(text):
        return 'authz'
    if AUTHN_MW.search(text):
        return 'authn'
    if re.search(r'req\.(?:user|isAuthenticated\s*\(|session\.user)', text) and re.search(r'\b(?:401|403|next)\b', text):
        return 'authn'
    return None


def js_resolve(rel, spec, known):
    base = os.path.normpath(os.path.join(os.path.dirname(rel), spec))
    for cand in (base, base + '.js', base + '.ts', base + '.mjs', base + '.cjs', base + '.jsx', base + '.tsx',
                 os.path.join(base, 'index.js'), os.path.join(base, 'index.ts')):
        k = os.path.normcase(cand)
        if k in known:
            return known[k]
    return None


def js_imports(src):
    res = {}
    for m in re.finditer(r'(?:const|let|var)\s+(\{[^}]*\}|[\w$]+)\s*=\s*require\(\s*["\'](\.{1,2}/[^"\']+)["\']\s*\)', src.code):
        for n in re.findall(r'[\w$]+', m.group(1)):
            res[n] = m.group(2)
    for m in re.finditer(r'import\s+([\w$]+)?\s*,?\s*(\{[^}]*\})?\s*from\s*["\'](\.{1,2}/[^"\']+)["\']', src.code):
        for n in ([m.group(1)] if m.group(1) else []) + re.findall(r'(?:\w+\s+as\s+)?([\w$]+)\s*(?:,|$)', (m.group(2) or '').strip('{} ')):
            res[n] = m.group(3)
    return res


def analyze_express(srcs, out):
    known = {os.path.normcase(os.path.normpath(s.rel)): s for s in srcs}
    file_level = defaultdict(lambda: None)
    parsed = []
    for src in srcs:
        s, code = src.masked, src.code
        routers = set(m.group(1) for m in ROUTER_INIT.finditer(s))
        if not routers and not re.search(r'\bexpress\b|\bRouter\s*\(|koa|fastify|hono', src.text):
            continue
        imports = js_imports(src)
        uses, routes = [], []
        recv_level = {}
        for m in EXPRESS_USE.finditer(s):
            recv = m.group(1)
            if recv not in routers and not EXPRESS_RECV.match(recv):
                continue
            po = m.end() - 1
            pc = match_close(s, po)
            args_m, args_c = split_top(s[po + 1:pc]), split_top(s[po + 1:pc], code[po + 1:pc])
            path = None
            if args_c and re.match(r'\s*["\'`]', args_c[0]):
                path = first_string(args_c[0]) or ''
                args_c, args_m = args_c[1:], args_m[1:]
            mounted, mws = [], []
            for a in args_c:
                at = a.strip()
                rq = re.match(r'require\(\s*["\'](\.{1,2}/[^"\']+)["\']\s*\)', at)
                if rq:
                    mounted.append(('mod', rq.group(1)))
                elif re.fullmatch(r'[\w$]+', at) and (at in imports and not AUTHN_MW.fullmatch(at) and not AUTHZ_MW.fullmatch(at)
                                                       or at in routers or re.search(r'(?i)(router|routes)$', at)):
                    mounted.append(('mod', imports[at]) if at in imports else ('var', at))
                else:
                    mws.append(at)
            lv = max_level(*[mw_level(x) for x in mws]) if mws else None
            uses.append(dict(recv=recv, path=path, level=lv, off=m.start(), mounted=mounted))
        for rx, chain in ((EXPRESS_ROUTE, False), (EXPRESS_CHAIN, True)):
            for m in rx.finditer(s):
                recv = m.group(1)
                if recv not in routers and not EXPRESS_RECV.match(recv):
                    continue
                po = m.end() - 1
                pc = match_close(s, po)
                args_c = split_top(s[po + 1:pc], code[po + 1:pc])
                if not args_c or not re.match(r'\s*["\'`]\s*/|\s*["\'`]\*', args_c[0]):
                    continue
                path = first_string(args_c[0]) or ''
                if chain:
                    pos = pc + 1
                    while True:
                        cm = re.compile(r'\s*\.\s*(get|post|put|patch|delete|all)\s*\(').match(s, pos)
                        if not cm:
                            break
                        cpo = cm.end() - 1
                        cpc = match_close(s, cpo)
                        cargs = split_top(s[cpo + 1:cpc], code[cpo + 1:cpc])
                        routes.append(dict(recv=recv, verb=cm.group(1).upper(), path=path, off=m.start(),
                                           mws=cargs[:-1], handler=cargs[-1] if cargs else '', hoff=cpo + 1))
                        pos = cpc + 1
                    continue
                verb = m.group(2).upper()
                verb = 'DELETE' if verb == 'DEL' else ('ANY' if verb == 'ALL' else verb)
                routes.append(dict(recv=recv, verb=verb, path=path, off=m.start(), mws=args_c[1:-1],
                                   handler=args_c[-1] if len(args_c) > 1 else '', hoff=po + 1))
        parsed.append((src, routes, uses, imports, recv_level))
        for u in uses:
            if not u['mounted']:
                continue
            prior = [x['level'] for x in uses if x['recv'] == u['recv'] and x['off'] < u['off'] and not x['mounted']
                     and (x['path'] is None or (u['path'] or '').startswith(x['path']))]
            lv = max_level(u['level'], *prior)
            for kind, ref in u['mounted']:
                if kind == 'mod':
                    tgt = js_resolve(src.rel, ref, known)
                    if tgt is not None:
                        file_level[tgt.rel] = max_level(file_level[tgt.rel], lv)
                else:
                    recv_level[ref] = max_level(recv_level.get(ref), lv)
    eps = []
    for src, routes, uses, imports, recv_level in parsed:
        for r in routes:
            prior = [u['level'] for u in uses if u['recv'] == r['recv'] and u['off'] < r['off'] and not u['mounted']
                     and (u['path'] is None or r['path'].startswith(u['path']))]
            lv = max_level(max_level(*[mw_level(x) for x in r['mws']]) if r['mws'] else None, recv_level.get(r['recv']),
                           file_level[src.rel], *prior)
            expr = ', '.join(x.strip() for x in r['mws'])[:100] or ('router-level middleware' if lv else '')
            e = Endpoint(src, src.line_of(r['off']), r['verb'], r['path'], '', lv, expr, src.rel, 'express')
            h = r['handler']
            if re.search(r'=>|function', h):
                e.body, e.body_off = h, r['hoff'] + (code_find(src.code, h, r['hoff']))
                e.params = h[:120]
            e.id_params = re.findall(r':(\w+)', r['path'])
            eps.append(e)
    evaluate_endpoints(eps, out, 'router module')
    js_idor_pass(srcs, out)


def code_find(code, piece, start):
    i = code.find(piece, start)
    return (i - start) if i >= 0 else 0


JS_IDOR_RX = re.compile(r'\.\s*(?:findById|findByPk|findOne|findUnique|findFirst|findByIdAndUpdate|findByIdAndDelete|'
                        r'findByIdAndRemove|findOneAndUpdate|findOneAndDelete|deleteOne|updateOne|destroy|update|'
                        r'delete|findAndCountAll|get)\s*\(\s*(?:\{\s*(?:where\s*:\s*\{\s*)?["\']?(?:_?id|\w+Id)["\']?\s*:\s*)?'
                        r'(?:req\.(?:params|query|body)\.(\w+)|(?:Number|parseInt|String)\(\s*req\.(?:params|query)\.(\w+)\s*\)|(%s)\b)')


def js_idor_pass(srcs, out):
    seen = set((f['path'], f['line']) for f in out if f['cwe'] == 639)
    for src in srcs:
        for f in functions(src):
            if not re.search(r'\breq\b', f.params or ''):
                continue
            body = f.body()
            if PRINCIPAL_TOKENS.search(body):
                continue
            ids = []
            for m in re.finditer(r'(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req\.(?:params|query)', body):
                ids += [n.split(':')[-1].strip() for n in m.group(1).split(',') if n.strip()]
            for m in re.finditer(r'(?:const|let|var)\s+(\w+)\s*=\s*(?:Number\(|parseInt\()?\s*req\.(?:params|query)\.\w+', body):
                ids.append(m.group(1))
            ids = [i for i in ids if ID_NAME.match(i) or i.lower().endswith('id')]
            rx = re.compile(JS_IDOR_RX.pattern % ('|'.join(map(re.escape, ids)) if ids else r'(?!x)x'))
            m = rx.search(body)
            if not m:
                continue
            idname = m.group(1) or m.group(2) or m.group(3)
            if not (ID_NAME.match(idname or '') or (idname or '').lower().endswith('id')):
                continue
            line = src.line_of(f.start + m.start())
            if (src.rel, line) in seen:
                continue
            seen.add((src.rel, line))
            out.append(finding(src.rel, line, 'authz-idor-js', 'Object fetched by client-supplied id without ownership check',
                               'The handler loads / modifies a record using the request parameter "%s" and never refers '
                               'to the authenticated user (req.user / ownership filter): any user can access other '
                               'users\' objects by changing the id (IDOR).' % idname, 'MEDIUM', 'MEDIUM', 639))


NEST_VERB = {'Get': 'GET', 'Post': 'POST', 'Put': 'PUT', 'Patch': 'PATCH', 'Delete': 'DELETE', 'All': 'ANY',
             'Options': 'OPTIONS', 'Head': 'HEAD'}
NEST_PUBLIC = {'Public', 'SkipAuth', 'AllowAnonymous', 'IsPublic', 'Unprotected', 'NoAuth', 'PublicRoute', 'Anonymous'}
NEST_AUTHZ = {'Roles', 'Permissions', 'RequirePermissions', 'RequirePermission', 'Policies', 'CheckPolicies', 'HasRoles',
              'RequireRoles', 'Scopes', 'Authorize', 'Auth', 'AdminOnly', 'RequiresRole', 'Permission', 'Role'}


def nest_guard(anns):
    best, expr = None, ''
    for a in anns:
        lv = None
        if a.name in NEST_PUBLIC:
            lv = 'public'
        elif a.name == 'UseGuards':
            lv = 'authz' if re.search(r'(?i)role|permission|polic|admin|casl|abilit|acl|owner|scope|claim', a.args) else 'authn'
        elif a.name in NEST_AUTHZ:
            lv = 'authz'
        if lv and (best is None or LEVEL_RANK[lv] > LEVEL_RANK.get(best, 0)):
            best, expr = lv, a.full[:100]
    return best, expr


def analyze_nest(srcs, out):
    glob = any(re.search(r'\bAPP_GUARD\b|useGlobalGuards\s*\(', s.code) for s in srcs)
    eps = []
    roles_used, roles_guarded = [], False
    for src in srcs:
        if '@Controller' not in src.code and 'UseGuards' not in src.code:
            continue
        classes, methods = parse_members(src)
        for m in methods:
            for a in m.anns:
                if a.name in ('Roles', 'RequireRoles', 'HasRoles'):
                    roles_used.append((src, a.line))
                if a.name == 'UseGuards' and re.search(r'(?i)role', a.args):
                    roles_guarded = True
        for c in classes:
            ctl = [a for a in c.anns if a.name == 'Controller']
            if not ctl:
                continue
            prefix = first_string(ctl[0].args) or ''
            for a in c.anns:
                if a.name == 'UseGuards' and re.search(r'(?i)role', a.args):
                    roles_guarded = True
            clv, cexpr = nest_guard(c.anns)
            for m in methods:
                if m.cls is not c:
                    continue
                va = next((a for a in m.anns if a.name in NEST_VERB), None)
                if not va:
                    continue
                mlv, mexpr = nest_guard(m.anns)
                lv, expr = (mlv, mexpr) if mlv else (clv, cexpr)
                if lv is None and glob:
                    lv, expr = 'authn', 'global APP_GUARD'
                path = norm_path(prefix, first_string(va.args) or '')
                e = Endpoint(src, va.line, NEST_VERB[va.name], path, m.name, lv, expr, c.name, 'nestjs')
                if m.body:
                    e.body, e.body_off = m.body_text(), m.body[0]
                e.params = m.params
                e.id_params = [p[3] for p in params_list(m) if 'Param' in p[0] and (ID_NAME.match(p[3]) or 'id' in p[1].lower())]
                eps.append(e)
                if lv == 'public' and glob and not is_auth_endpoint(path, m.name) and \
                        (verb_is_write(e.verb, path, m.name) or is_sensitive(path, m.name)):
                    out.append(finding(src.rel, e.line, 'authz-public-sensitive-nestjs',
                                       'Sensitive endpoint explicitly excluded from the global guard',
                                       '%s is marked public (%s) and therefore bypasses the global authentication guard, '
                                       'although it is state-changing / sensitive.' % (e.label(), expr), 'HIGH', 'MEDIUM', 862))
                check_read_guard_on_write(e, out)
                idor_check(e, out)
    roles_guarded = roles_guarded or any(re.search(r'APP_GUARD[\s\S]{0,120}?Roles?Guard|useGlobalGuards\s*\([^)]*Role', s.code)
                                         for s in srcs)
    if roles_used and not roles_guarded:
        src, line = roles_used[0]
        out.append(finding(src.rel, line, 'authz-nest-roles-without-guard', '@Roles metadata without a RolesGuard',
                           '@Roles(...) only attaches metadata; no RolesGuard is registered (UseGuards or APP_GUARD), so '
                           'the role requirement is never enforced (%d usages).' % len(roles_used), 'HIGH', 'LOW', 862))
    evaluate_endpoints(eps, out, 'controller')


# =========================================================================== #
# Python: Flask, FastAPI, Django, Django REST framework
# =========================================================================== #
PY_GUARD = re.compile(r'(?i)(?:^|\.)(?:login_required|jwt_required|auth\w*_required|token_required|roles?_(?:required|accepted)|'
                      r'permission\w*|requires?_\w+|admin\w*|staff\w*|superuser\w*|has_(?:role|permission|perm|scope)\w*|'
                      r'verify_jwt\w*|authenticated|protected|secured|scopes?_required|api_key\w*|'
                      r'check_\w*(?:auth|role|perm|admin|access)\w*|authoriz\w*|access_required|restricted|user_required|'
                      r'fresh_(?:login|jwt)_required|require_login|require_oauth|oidc\.require_login|login_or_\w+|'
                      r'auth_required|must_be_\w+|only_\w+|\w+_only|user_passes_test|staff_member_required|'
                      r'permission_classes|method_decorator|group_required|requires_auth|auth\.login_required)$')
PY_AUTHZ = re.compile(r'(?i)(role|permission|perm\b|admin|staff|superuser|scope|authoriz|access_required|restricted|has_|'
                      r'group|owner|only|user_passes_test|IsAdmin)')
PY_NOT_GUARD = re.compile(r'(?i)(optional|csrf|cache|limiter|limit|route|exempt|property|staticmethod|classmethod|'
                          r'wraps|lru_cache|retry|transaction|atomic|validate|marshal|doc|swag|login_manager\.user_loader)')
AUTH_DEP = re.compile(r'(?i)(current_?user|get_?user|active_?user|auth|token|jwt|verify|login|oauth2?_scheme|api_?key|bearer|'
                      r'admin|require|permission|role|scope|principal|identity|session_user|security|guard)')
NOT_AUTH_DEP = re.compile(r'(?i)^(?:get_db|get_session|db|session|settings|get_settings|config|get_config|pagination|paginate|'
                          r'common_parameters|get_redis|get_cache)$')


def py_deco_level(decos):
    best, expr = None, ''
    for name, full, line in decos:
        if PY_NOT_GUARD.search(name) and not re.search(r'login|auth|perm|role|admin', name, re.I):
            continue
        lv = None
        if name.endswith('permission_classes'):
            lv = drf_level(full)
        elif name.endswith('method_decorator'):
            if PY_GUARD.search(re.sub(r'method_decorator', '', full)):
                lv = 'authz' if PY_AUTHZ.search(full) else 'authn'
        elif PY_GUARD.search(name):
            lv = 'authz' if PY_AUTHZ.search(name) or PY_AUTHZ.search(full) else 'authn'
        if lv and (best is None or LEVEL_RANK[lv] > LEVEL_RANK.get(best, 0)):
            best, expr = lv, '@' + full.strip()[:90]
    return best, expr


def drf_level(text):
    names = re.findall(r'([A-Z]\w+)', text)
    if not names or re.search(r'=\s*[\[(]\s*[\])]', text):
        return 'public'
    if all(n in ('AllowAny',) for n in names):
        return 'public'
    if all(n in ('IsAuthenticated', 'IsAuthenticatedOrReadOnly', 'TokenHasReadWriteScope') for n in names):
        return 'authn'
    if 'AllowAny' in names and len(set(names)) == 1:
        return 'public'
    return 'authz'


FLASK_DEC = re.compile(r'^([\w.]+?)\.(route|get|post|put|patch|delete)\s*\(\s*[rbuf]?["\']([^"\']*)["\'](.*)$', re.S)
FASTAPI_DEC = re.compile(r'^([\w.]+?)\.(get|post|put|patch|delete|api_route|head|options)\s*\(\s*[rbuf]?["\']([^"\']*)["\'](.*)$', re.S)
DRF_BASE = re.compile(r'\b(?:APIView|GenericAPIView|ViewSet|ModelViewSet|GenericViewSet|ReadOnlyModelViewSet|\w+APIView|\w+ViewSet)\b')
DRF_MUTATING = re.compile(r'\b(?:ModelViewSet|CreateModelMixin|UpdateModelMixin|DestroyModelMixin|CreateAPIView|UpdateAPIView|'
                          r'DestroyAPIView|ListCreateAPIView|RetrieveUpdateAPIView|RetrieveDestroyAPIView|'
                          r'RetrieveUpdateDestroyAPIView)\b')
DRF_RETRIEVE = re.compile(r'\b(?:ModelViewSet|ReadOnlyModelViewSet|RetrieveModelMixin|RetrieveAPIView|RetrieveUpdateAPIView|'
                          r'RetrieveDestroyAPIView|RetrieveUpdateDestroyAPIView|UpdateAPIView|DestroyAPIView)\b')
DJ_MIXIN = re.compile(r'\b(?:LoginRequiredMixin|PermissionRequiredMixin|UserPassesTestMixin|StaffuserRequiredMixin|'
                      r'SuperuserRequiredMixin|AccessMixin|GroupRequiredMixin|LoginRequired|StaffRequiredMixin|'
                      r'AdminRequiredMixin|\w*PermissionMixin|\w*RequiredMixin)\b')
PY_AUTHVIEW_NAME = re.compile(r'(?i)^(?:log_?in|log_?out|sign_?(?:in|up|out)|register\w*|password_?reset\w*|reset_?password\w*|'
                              r'forgot\w*|activate\w*|verify\w*|confirm\w*|home|index|landing|about|contact|health\w*|'
                              r'robots|sitemap|public\w*|webhook\w*|callback\w*|csrf\w*|token\w*|otp\w*|mfa\w*|'
                              r'two_?factor\w*|oauth\w*|status|ping|privacy|terms|faq|error\w*|handler\d+|page_not_found|'
                              r'server_error)$')
PY_ID_FETCH = re.compile(r'(?:get_object_or_404\s*\(\s*\w+\s*,|\b\w+\.objects\.(?:get|filter)\s*\(|\.query\.get(?:_or_404)?\s*\(|'
                         r'\.get_or_404\s*\(|\.filter_by\s*\(|session\.get\s*\(\s*\w+\s*,|db\.get\s*\(\s*\w+\s*,|'
                         r'\.query\(\s*\w+\s*\)\.(?:get|filter)\s*\()([^)\n]*)\)')
PY_OWNER = re.compile(r'(?i)\b(user|owner|tenant|account|organi[sz]ation|company|created_by|author|current_user|request\.user|'
                      r'g\.user|customer|member)\b')


def _py_idor(src, it, ids, label, out, fw):
    body = it.body_text()
    if not ids or PRINCIPAL_TOKENS.search(re.sub(r'request\.user\.is_authenticated', '', body)):
        if not ids or re.search(r'(?:==|!=|is not|is)\s*(?:request\.user|current_user|g\.user)|check_object_permissions|'
                                r'has_perm|\.user_id\s*[!=]=|owner', body):
            return
    for m in PY_ID_FETCH.finditer(body):
        args = m.group(1)
        if not any(re.search(r'\b%s\b' % re.escape(i), args) for i in ids):
            continue
        if PY_OWNER.search(args):
            continue
        line = it.body_start + body[:m.start()].count('\n')
        out.append(finding(src.rel, line, 'authz-idor-%s' % fw, 'Object fetched by client-supplied id without ownership check',
                           '%s loads a record with the client-controlled id (%s) without filtering on, or comparing with, '
                           'the current user: any user can read / modify other users\' objects (IDOR).'
                           % (label, m.group(0)[:70]), 'MEDIUM', 'MEDIUM', 639))
        return


def analyze_python(srcs, out):
    flask_eps, fast_eps, dj_eps = [], [], []
    settings_srcs = [s for s in srcs if re.search(r'\bINSTALLED_APPS\s*=|\bREST_FRAMEWORK\s*=', s.code)]
    drf_default = None            # level of DEFAULT_PERMISSION_CLASSES ('public' when DRF falls back to AllowAny)
    uses_drf = any('rest_framework' in s.text for s in srcs)
    login_mw = False
    for st in settings_srcs:
        code = st.code
        if re.search(r'LoginRequiredMiddleware', code):
            login_mw = True
        rm = re.search(r'\bREST_FRAMEWORK\s*=\s*\{', st.masked)
        if rm:
            ob = rm.end() - 1
            block = code[ob:match_close(st.masked, ob) + 1]
            dm = re.search(r'["\']DEFAULT_PERMISSION_CLASSES["\']\s*:\s*([\[(][^\])]*[\])])', block)
            if dm:
                drf_default = drf_level(dm.group(1))
                if drf_default == 'public':
                    out.append(finding(st.rel, st.line_of(ob + dm.start()), 'authz-drf-default-allowany',
                                       'Django REST framework default permission is AllowAny',
                                       'DEFAULT_PERMISSION_CLASSES is AllowAny: every API view that does not set '
                                       'permission_classes itself is reachable anonymously. Use IsAuthenticated as the '
                                       'default and open views explicitly.', 'HIGH', 'HIGH', 862))
            else:
                drf_default = 'public'
                out.append(finding(st.rel, st.line_of(rm.start()), 'authz-drf-default-allowany',
                                   'Django REST framework without DEFAULT_PERMISSION_CLASSES',
                                   'REST_FRAMEWORK does not define DEFAULT_PERMISSION_CLASSES, so DRF falls back to '
                                   'AllowAny for every view that does not set permission_classes.', 'MEDIUM', 'MEDIUM', 862))
        elif uses_drf and re.search(r'["\']rest_framework["\']', code):
            drf_default = 'public'
            im = re.search(r'["\']rest_framework["\']', code)
            out.append(finding(st.rel, st.line_of(im.start()), 'authz-drf-default-allowany',
                               'Django REST framework installed without a default permission',
                               'rest_framework is installed but no REST_FRAMEWORK / DEFAULT_PERMISSION_CLASSES setting '
                               'exists: DRF defaults to AllowAny.', 'MEDIUM', 'MEDIUM', 862))
    # guarded names from urls.py: path('x', login_required(view))
    url_guarded = set()
    for s in srcs:
        for m in re.finditer(r'\b(login_required|staff_member_required|permission_required\([^)]*\)|user_passes_test\([^)]*\))'
                             r'\s*\(\s*([\w.]+)', s.code):
            url_guarded.add(m.group(2).split('.')[-1])
    # FastAPI router-level dependencies
    fast_guarded_vars, fast_guarded_mods = {}, {}
    for s in srcs:
        for m in re.finditer(r'(\w+)\s*=\s*(?:fastapi\.)?(?:APIRouter|FastAPI)\s*\(', s.masked):
            po = m.end() - 1
            args = s.code[po + 1:match_close(s.masked, po)]
            deps = re.findall(r'(?:Depends|Security)\(\s*([\w.]+)', args)
            deps = [d for d in deps if AUTH_DEP.search(d) and not NOT_AUTH_DEP.match(d.split('.')[-1])]
            if deps:
                fast_guarded_vars[(s.rel, m.group(1))] = ('authz' if PY_AUTHZ.search(' '.join(deps)) else 'authn', ', '.join(deps))
        for m in re.finditer(r'include_router\s*\(\s*([\w.]+)([^)]*(?:\([^)]*\)[^)]*)*)\)', s.code):
            deps = [d for d in re.findall(r'(?:Depends|Security)\(\s*([\w.]+)', m.group(2))
                    if AUTH_DEP.search(d) and not NOT_AUTH_DEP.match(d.split('.')[-1])]
            if deps:
                parts = m.group(1).split('.')
                key = parts[-2] if parts[-1] == 'router' and len(parts) > 1 else parts[-1]
                fast_guarded_mods[key] = ('authz' if PY_AUTHZ.search(' '.join(deps)) else 'authn', ', '.join(deps))
    for src in srcs:
        items = py_items(src)
        text = src.code
        is_fast = bool(re.search(r'\bfastapi\b', src.text))
        is_django = bool(re.search(r'\bdjango\b|rest_framework', src.text))
        bp_guard = {}
        for it in items:
            for name, full, line in it.decorators:
                bm = re.match(r'([\w.]+)\.before(?:_app)?_request$', name)
                if bm and re.search(r'is_authenticated|abort\s*\(\s*40[13]|verify_jwt|current_user|g\.user|login|'
                                    r'session\.get\(|redirect\(', it.body_text()):
                    bp_guard[bm.group(1)] = 'authz' if re.search(r'(?i)admin|role|permission|is_staff|is_superuser|has_role',
                                                                 it.body_text()) else 'authn'
        for m in re.finditer(r'(\w+)\.before(?:_app)?_request\s*\(\s*(\w+)\s*\)', text):
            fn = next((i for i in items if i.name == m.group(2)), None)
            if fn is not None and re.search(r'is_authenticated|abort|verify_jwt|current_user|login', fn.body_text()):
                bp_guard[m.group(1)] = 'authn'
        global_app_guard = bp_guard.get('app')
        for it in items:
            if it.kind == 'class':
                continue
            for name, full, line in it.decorators:
                fm = (FASTAPI_DEC if is_fast else FLASK_DEC).match(full)
                if not fm:
                    continue
                var, meth, path, rest = fm.group(1), fm.group(2), fm.group(3), fm.group(4)
                if is_fast:
                    verb = meth.upper() if meth not in ('api_route',) else 'ANY'
                else:
                    ms = re.search(r'methods\s*=\s*[\[(]([^\])]*)', rest)
                    vs = [v.upper() for v in re.findall(r'["\'](\w+)["\']', ms.group(1))] if ms else []
                    verb = meth.upper() if meth != 'route' else (next((v for v in vs if v != 'GET'), vs[0] if vs else 'GET'))
                lv, expr = py_deco_level([d for d in it.decorators if d[0] != name])
                if it.parent is not None and it.parent.kind == 'class':
                    pdec = re.search(r'decorators\s*=\s*\[([^\]]*)\]', it.parent.body_text())
                    if pdec and PY_GUARD.search(pdec.group(1)):
                        lv = max_level(lv, 'authn')
                if is_fast:
                    deps = re.findall(r'(?:Depends|Security)\(\s*([\w.]+)', it.header + ' ' + rest)
                    deps = [d for d in deps if AUTH_DEP.search(d) and not NOT_AUTH_DEP.match(d.split('.')[-1])]
                    scopes = re.findall(r'scopes\s*=\s*\[([^\]]*)\]', it.header + ' ' + rest)
                    if deps:
                        lv = max_level(lv, 'authz' if (PY_AUTHZ.search(' '.join(deps)) or scopes) else 'authn')
                        expr = expr or 'Depends(%s)%s' % (', '.join(deps), (' scopes=[%s]' % ', '.join(scopes)) if scopes else '')
                    rv = fast_guarded_vars.get((src.rel, var))
                    mv = fast_guarded_mods.get(os.path.splitext(os.path.basename(src.rel))[0]) or fast_guarded_mods.get(var)
                    for g in (rv, mv):
                        if g:
                            lv = max_level(lv, g[0])
                            expr = expr or 'router dependencies: ' + g[1]
                else:
                    g = bp_guard.get(var) or global_app_guard
                    if g:
                        lv = max_level(lv, g)
                        expr = expr or '%s.before_request guard' % var
                e = Endpoint(src, line, verb, path, it.name, lv, expr, (src.rel, var), 'fastapi' if is_fast else 'flask')
                e.body = it.body_text()
                e.params = it.header
                ids = re.findall(r'<(?:\w+:)?(\w+)>|\{(\w+)\}', path)
                e.id_params = [a or b for a, b in ids]
                (fast_eps if is_fast else flask_eps).append(e)
                check_read_guard_on_write(e, out)
                if e.level not in ('authz', 'deny'):
                    req_ids = re.findall(r'request\.(?:args|form|values|json)(?:\.get)?\s*[\[(]\s*["\'](\w*id)["\']', e.body)
                    _py_idor(src, it, [i for i in e.id_params if ID_NAME.match(i) or i.endswith('id')] +
                             [r for r in req_ids], e.label(), out, e.fw)
                break
        if not is_django or is_fast:
            continue
        # ---------------- Django / DRF
        for it in items:
            if it.kind == 'class' and DRF_BASE.search(it.header):
                body = it.body_text()
                pm = re.search(r'permission_classes\s*=\s*([\[(][^\])]*[\])])', body)
                deco_pc = next((d for d in it.decorators if d[0].endswith('permission_classes')), None)
                if pm:
                    lv = drf_level(pm.group(1))
                    pline = it.body_start + body[:pm.start()].count('\n')
                elif deco_pc:
                    lv, pline = drf_level(deco_pc[1]), deco_pc[2]
                else:
                    lv, pline = (drf_default or 'public'), it.def_line
                mutating = bool(DRF_MUTATING.search(it.header) or re.search(r'^\s*def\s+(post|put|patch|delete|create|update|'
                                                                            r'destroy|partial_update)\b', body, re.M))
                authish = re.search(r'(?i)login|register|signup|token|password|reset|verify|activate|public|health|webhook|'
                                    r'callback|otp|captcha|csrf|auth', it.name)
                if lv == 'public' and not authish:
                    if pm or deco_pc:
                        out.append(finding(src.rel, pline, 'authz-drf-allowany', 'API view explicitly open to anonymous users',
                                           '%s sets permission_classes to AllowAny%s.' % (
                                               it.name, ' although it creates / updates / deletes data' if mutating else ''),
                                           'HIGH' if mutating else 'INFO', 'HIGH', 862))
                    else:
                        out.append(finding(src.rel, pline, 'authz-drf-no-permission',
                                           'API view without permission_classes while the default is AllowAny',
                                           '%s does not set permission_classes and the project default is AllowAny%s.' % (
                                               it.name, ' (the view modifies data)' if mutating else ''),
                                           'MEDIUM' if mutating else 'LOW', 'MEDIUM', 862))
                pcs = pm.group(1) if pm else (deco_pc[1] if deco_pc else '')
                admin_only = re.search(r'IsAdminUser|DjangoModelPermissions|DjangoObjectPermissions|Owner|IsStaff|IsSuperuser', pcs)
                if DRF_RETRIEVE.search(it.header) and not admin_only:
                    qs = re.search(r'^\s*queryset\s*=\s*(\w+)\.objects\.all\(\)', body, re.M)
                    gq = re.search(r'^\s*def\s+get_queryset\s*\(', body, re.M)
                    go = re.search(r'^\s*def\s+get_object\s*\(', body, re.M)
                    if qs and not gq and not go:
                        out.append(finding(src.rel, it.body_start + body[:qs.start()].count('\n') + 1, 'authz-idor-drf',
                                           'Object-level access not restricted (queryset = Model.objects.all())',
                                           '%s retrieves / modifies %s objects by primary key from an unfiltered queryset '
                                           'and has no get_queryset / object permission: any user can access every '
                                           'record by id (IDOR).' % (it.name, qs.group(1)), 'MEDIUM', 'MEDIUM', 639))
                    elif gq:
                        gbody = body[gq.start():]
                        nxt = re.search(r'^\s*def\s', gbody[10:], re.M)
                        gbody = gbody[:nxt.start() + 10] if nxt else gbody
                        if not re.search(r'request\.user|owner|tenant|user=|user_id|organization|account', gbody):
                            out.append(finding(src.rel, it.body_start + body[:gq.start()].count('\n') + 1, 'authz-idor-drf',
                                               'get_queryset does not filter by the requesting user',
                                               '%s.get_queryset returns objects without filtering on request.user / tenant: '
                                               'object-level authorization is missing (IDOR).' % it.name, 'MEDIUM', 'LOW', 639))
                continue
            if it.kind == 'class' and re.search(r'\b(?:View|TemplateView|DetailView|UpdateView|DeleteView|CreateView|FormView|'
                                                r'ListView|RedirectView)\b', it.header):
                lv = 'authn' if DJ_MIXIN.search(it.header) else None
                lv = max_level(lv, py_deco_level(it.decorators)[0])
                if login_mw and lv is None and not any('login_not_required' in d[0] for d in it.decorators):
                    lv = 'authn'
                e = Endpoint(src, it.line, 'POST' if re.search(r'Update|Delete|Create|Form', it.header) else 'GET',
                             '', it.name, lv, (DJ_MIXIN.search(it.header).group(0) if DJ_MIXIN.search(it.header) else ''),
                             src.rel, 'django')
                dj_eps.append(e)
                continue
            if it.kind == 'def' and it.parent is None and re.match(r'\s*(?:async\s+)?def\s+\w+\s*\(\s*request\b', it.header) \
                    and not it.name.startswith('_'):
                lv, expr = py_deco_level(it.decorators)
                if it.name in url_guarded:
                    lv, expr = max_level(lv, 'authn'), expr or 'wrapped in urls.py'
                if login_mw and lv is None and not any('login_not_required' in d[0] for d in it.decorators):
                    lv, expr = 'authn', 'LoginRequiredMiddleware'
                if any(d[0].endswith('api_view') for d in it.decorators) and lv is None:
                    lv = drf_default
                body = it.body_text()
                write = bool(re.search(r'request\.method\s*==\s*["\']POST|request\.POST|\.save\(\)|\.delete\(\)|\.update\(',
                                       body) or re.search(r'(?i)delete|remove|update|edit|create|add|upload|import|approve|'
                                                          r'reject|assign|grant|reset|change|set_|transfer|pay|refund', it.name))
                e = Endpoint(src, it.line, 'POST' if write else 'GET', '', it.name,
                             None if lv == 'public' and not expr else lv, expr, src.rel, 'django')
                if PY_AUTHVIEW_NAME.match(it.name):
                    e.level = 'public'
                dj_eps.append(e)
                staff = re.search(r'staff|superuser|permission_required|admin', ' '.join(d[1] for d in it.decorators))
                if not staff:
                    kw = re.findall(r'\b(\w*(?:pk|id))\b', it.header.split('(', 1)[1] if '(' in it.header else '')
                    req_ids = re.findall(r'request\.(?:GET|POST|data|query_params)(?:\.get)?\s*[\[(]\s*["\'](\w*id)["\']', body)
                    _py_idor(src, it, [k for k in kw if k != 'request'] + req_ids, 'View %s' % it.name, out, 'django')
    evaluate_endpoints(flask_eps, out, 'Flask module / blueprint')
    evaluate_endpoints(fast_eps, out, 'FastAPI router')
    evaluate_endpoints(dj_eps, out, 'Django views module')


# =========================================================================== #
# PHP: Laravel routes & controllers, Symfony, WordPress, plain PHP pages
# =========================================================================== #
LARAVEL_AUTH_MW = re.compile(r'(?i)^(?:auth(?::\w+)?|auth\.basic|can:.+|role:.+|permission:.+|ability:.+|abilities:.+|admin|is_?admin|'
                             r'jwt(?:\.\w+)?|sanctum|passport|scope:.+|scopes:.+|staff|superadmin|acl|rbac|verified)$')


def laravel_mw_level(names):
    lv = None
    for n in names:
        n = n.strip()
        if LARAVEL_AUTH_MW.match(n):
            lv = max_level(lv, 'authz' if re.match(r'(?i)can:|role:|permission:|ability:|abilities:|admin|is_?admin|staff|'
                                                   r'superadmin|acl|rbac|scope', n) else ('authn' if n != 'verified' else None))
    return lv


def analyze_php(srcs, out):
    eps = []
    ctrl_guard = {}
    for src in srcs:
        s, code = src.masked, src.code
        for cm in re.finditer(r'class\s+(\w+)', s):
            ob = s.find('{', cm.end())
            if ob < 0:
                continue
            body = code[ob:match_close(s, ob)]
            mws = re.findall(r'\$this\s*->\s*middleware\s*\(\s*([^;]*)\)', body)
            if mws:
                names = all_strings(' '.join(mws))
                ctrl_guard[cm.group(1)] = laravel_mw_level(names)
            if re.search(r'authorizeResource\s*\(', body):
                ctrl_guard[cm.group(1)] = 'authz'
    for src in srcs:
        s, code = src.masked, src.code
        if 'Route::' in code:
            groups = []
            for gm in re.finditer(r'Route::(?:middleware|prefix|group|name|domain|controller|namespace|as)\b', s):
                st_end = s.find(';', gm.start())
                gpos = s.find('function', gm.start(), st_end if st_end > 0 else len(s))
                if gpos < 0 or '->group' not in s[gm.start():gpos] and not s[gm.start():gpos].startswith('Route::group'):
                    continue
                ob = s.find('{', gpos)
                if ob < 0:
                    continue
                cb = match_close(s, ob)
                attrs = code[gm.start():ob]
                mw = []
                for mm in re.finditer(r'middleware\s*\(\s*([^)]*)\)|["\']middleware["\']\s*=>\s*(\[[^\]]*\]|["\'][^"\']*["\'])', attrs):
                    mw += all_strings(mm.group(1) or mm.group(2) or '')
                pfx = re.search(r'prefix\s*\(\s*["\']([^"\']*)["\']|["\']prefix["\']\s*=>\s*["\']([^"\']*)["\']', attrs)
                groups.append((ob, cb, mw, (pfx.group(1) or pfx.group(2)) if pfx else ''))
            for rm in re.finditer(r'(?:Route::|->)(get|post|put|patch|delete|any|match|options|resource|apiResource)\s*\(\s*'
                                  r'(?:\[[^\]]*\]\s*,\s*)?["\']([^"\']*)["\']', s):
                verb = rm.group(1).upper()
                st = rm.start()
                stmt_start = s.rfind(';', 0, st)
                stmt_start = max(stmt_start, s.rfind('{', 0, st), s.rfind('}', 0, st)) + 1
                stmt_end = s.find(';', st)
                stmt = code[stmt_start:stmt_end if stmt_end > 0 else len(code)]
                if re.search(r'->group\s*\(', stmt):
                    continue
                path = code[rm.start(2):rm.end(2)]
                mw = []
                for mm in re.finditer(r'middleware\s*\(\s*([^)]*)\)', stmt):
                    mw += all_strings(mm.group(1))
                prefix = ''
                for ob, cb, gmw, gp in groups:
                    if ob < st < cb:
                        mw += gmw
                        prefix = '/'.join(x for x in (prefix, gp) if x)
                lv = laravel_mw_level(mw)
                act = re.search(r'\[\s*\\?([\w\\]+)::class\s*,\s*["\'](\w+)["\']|["\']([\w\\]+)@(\w+)["\']|,\s*\\?([\w\\]+)::class', stmt)
                ctl = (act.group(1) or act.group(3) or act.group(5) or '').split('\\')[-1] if act else ''
                if ctl and ctrl_guard.get(ctl):
                    lv = max_level(lv, ctrl_guard[ctl])
                if verb in ('RESOURCE', 'APIRESOURCE'):
                    verb = 'ANY'
                e = Endpoint(src, src.line_of(st), verb, norm_path(prefix, path), (act.group(2) or act.group(4) or '') if act else '',
                             lv, ', '.join(mw)[:200], src.rel, 'laravel')
                eps.append(e)
            twofa = re.compile(r'(?i)2fa|two[-_.]?factor|mfa|otp|google2fa')
            file_eps = [e for e in eps if e.src is src]
            has_2fa_mw = [e for e in file_eps if twofa.search(e.expr)]
            global_throttle = bool(re.search(r'(?i)throttle|RateLimiter', code))
            for e in file_eps:
                label = e.path + ' ' + e.name
                if has_2fa_mw and e.level in ('authn', 'authz') and not twofa.search(e.expr) and not twofa.search(label) and \
                        not is_auth_endpoint(e.path, e.name) and not is_self_endpoint(e.path, e.name):
                    out.append(finding(src.rel, e.line, 'mfa-route-missing-2fa-middleware',
                                       'Route reachable without the second factor',
                                       '%s only requires "%s" while sibling routes also require the 2FA middleware (%s): a '
                                       'session that never passed the second factor can use it.' % (
                                           e.label(), e.expr or 'auth', has_2fa_mw[0].expr[:60]), 'MEDIUM', 'MEDIUM', 308))
                if twofa.search(label) and (e.verb == 'DELETE' or re.search(r'(?i)disable|destroy|remove|/off|reset', label)) and \
                        not re.search(r'(?i)password\.confirm|reauth|confirm', e.expr):
                    out.append(finding(src.rel, e.line, 'mfa-disable-without-reauth', '2FA can be disabled without re-authentication',
                                       '%s removes / resets the second factor without the password.confirm middleware (or an '
                                       'equivalent re-authentication step).' % e.label(), 'MEDIUM', 'MEDIUM', 308))
                if re.search(r'(?i)(?:2fa|two[-_]?factor|mfa|otp|totp|verify[-_]?code|challenge)', label) and e.verb in ('POST', 'ANY') \
                        and not re.search(r'(?i)throttle|rate|limit', e.expr) and not global_throttle and \
                        not re.search(r'(?i)disable|destroy|remove|enable|setup|qr|send|resend', label):
                    out.append(finding(src.rel, e.line, 'mfa-route-no-throttle', 'OTP verification route without rate limiting',
                                       '%s verifies one-time codes but has no throttle middleware: the code can be brute-forced.'
                                       % e.label(), 'MEDIUM', 'MEDIUM', 307))
        # Symfony attributes / annotations
        if re.search(r'#\[Route\b|@Route\s*\(', src.text):
            classes, methods = parse_members(src)
            sy = []
            for m in methods:
                ra = [a for a in m.anns if a.name == 'Route']
                doc_route = None
                if not ra:
                    pre = '\n'.join(src.raw_lines[max(0, m.name_line - 12):m.name_line])
                    doc_route = re.search(r'@Route\(\s*["\']([^"\']*)["\'][^)]*?(?:methods\s*=\s*\{?["\']?(\w+))?', pre)
                    if not doc_route:
                        continue
                path = first_string(ra[0].args) if ra else doc_route.group(1)
                margs = ra[0].args if ra else (doc_route.group(0))
                vm = re.search(r'methods\s*[:=]\s*[\[{]?\s*["\'](\w+)', margs)
                lv = None
                pre = '\n'.join(src.raw_lines[max(0, m.name_line - 12):m.name_line])
                if any(a.name in ('IsGranted', 'Security') for a in m.anns) or re.search(r'@(?:IsGranted|Security)\(', pre) or \
                        re.search(r'denyAccessUnlessGranted|isGranted\s*\(', m.body_text()):
                    lv = 'authz'
                if m.cls is not None and (any(a.name in ('IsGranted', 'Security') for a in m.cls.anns)):
                    lv = 'authz'
                e = Endpoint(src, (ra[0].line if ra else m.name_line), (vm.group(1).upper() if vm else 'ANY'), path or '',
                             m.name, lv, 'IsGranted' if lv else '', (src.rel, m.cls.name if m.cls else ''), 'symfony')
                sy.append(e)
            eps += sy
        # Laravel IDOR in controller methods
        if re.search(r'extends\s+\w*Controller', s):
            for f in functions(src):
                body = f.body()
                if re.search(r'\$this\s*->\s*authorize|Gate::|->can\s*\(|->cannot\s*\(|auth\(\)\s*->\s*(?:id|user)|Auth::(?:id|user)|'
                             r'\$request\s*->\s*user\(\)|->user\(\)|policy|authorizeResource|->where\(\s*["\']user_id', body):
                    continue
                pm = re.search(r'\b([A-Z]\w+)::(?:find|findOrFail|firstOrFail|findMany)\s*\(\s*\$(\w+)\s*\)', body)
                if pm and (ID_NAME.match(pm.group(2)) or pm.group(2).lower().endswith('id')):
                    out.append(finding(src.rel, src.line_of(f.start + pm.start()), 'authz-idor-laravel',
                                       'Model loaded by client-supplied id without authorization',
                                       '%s() loads %s by the request id $%s and never calls $this->authorize / a policy / '
                                       'an ownership check (IDOR).' % (f.name, pm.group(1), pm.group(2)), 'MEDIUM', 'MEDIUM', 639))
                    continue
                bind = re.findall(r'\b([A-Z]\w+)\s+\$(\w+)', f.params or '')
                for typ, var in bind:
                    if typ in ('Request', 'FormRequest', 'Response', 'Collection') or typ.endswith('Request'):
                        continue
                    wm = re.search(r'\$%s\s*->\s*(update|delete|forceDelete|fill|save|destroy)\s*\(' % re.escape(var), body)
                    if wm:
                        out.append(finding(src.rel, src.line_of(f.start + wm.start()), 'authz-idor-laravel',
                                           'Route-model-bound record modified without authorization',
                                           '%s() receives %s $%s through route model binding and calls ->%s() without '
                                           '$this->authorize / policy / ownership check (IDOR).' % (f.name, typ, var, wm.group(1)),
                                           'MEDIUM', 'LOW', 639))
                        break
        # WordPress
        for m in re.finditer(r'register_rest_route\s*\(', s):
            po = m.end() - 1
            args = code[po + 1:match_close(s, po)]
            if re.search(r'["\']permission_callback["\']\s*=>\s*["\']__return_true["\']', args):
                out.append(finding(src.rel, src.line_of(m.start()), 'authz-wp-rest-public', 'Public WordPress REST route',
                                   'permission_callback is __return_true: the route is callable anonymously.',
                                   'HIGH' if re.search(r'POST|PUT|DELETE|EDITABLE|CREATABLE|DELETABLE', args) else 'MEDIUM',
                                   'HIGH', 862))
            elif 'permission_callback' not in args:
                out.append(finding(src.rel, src.line_of(m.start()), 'authz-wp-rest-no-permission',
                                   'WordPress REST route without permission_callback',
                                   'register_rest_route() without permission_callback is public (WordPress only emits a notice).',
                                   'MEDIUM', 'MEDIUM', 862))
        for m in re.finditer(r'add_action\s*\(\s*["\']wp_ajax_(nopriv_)?(\w+)["\']\s*,\s*(?:["\'](\w+)["\']|\[\s*\$this\s*,\s*["\'](\w+)["\']\s*\])', code):
            fn = m.group(3) or m.group(4)
            fd = re.search(r'function\s+%s\s*\(' % re.escape(fn or 'x_x'), s)
            body = ''
            if fd:
                ob = s.find('{', fd.end())
                body = code[ob:match_close(s, ob)] if ob > 0 else ''
            if fd and not re.search(r'current_user_can|check_ajax_referer|wp_verify_nonce|check_admin_referer', body):
                out.append(finding(src.rel, src.line_of(m.start()), 'authz-wp-ajax-unchecked',
                                   'WordPress AJAX handler without capability / nonce check',
                                   'wp_ajax_%s%s -> %s() performs no current_user_can() or nonce verification%s.' % (
                                       m.group(1) or '', m.group(2), fn, ' and is reachable anonymously' if m.group(1) else ''),
                                   'HIGH' if m.group(1) else 'MEDIUM', 'MEDIUM', 862))
        # plain PHP pages in admin areas
        if re.search(r'(?i)(?:^|/)(?:admin|administration|backoffice|back-office|manage|management|dashboard)(?:/|[\w-]*\.php$)',
                     src.low_rel) and not re.search(r'(?i)/(?:header|footer|nav\w*|menu|sidebar|layout|config|db|database|'
                                                    r'connect\w*|functions?|init|bootstrap|helpers?|template|partials?|'
                                                    r'login|logout|auth\w*|session\w*|check\w*|guard\w*|security)[\w-]*\.php$',
                                                    src.low_rel) and 'class ' not in s and 'Route::' not in s:
            entry = re.search(r'\$_(?:GET|POST|REQUEST)|\becho\b|\bprint\b|mysqli_query|->query\s*\(|->exec\s*\(|unlink\s*\(|'
                              r'file_put_contents|header\s*\(', code)
            guard = re.search(r'\$_SESSION|session_start|is_?admin|isAdmin|check_?auth|require_?login|is_?logged|isLogged|'
                              r'logged_?in|\bauth\s*\(|Auth::|current_user|wp_get_current_user|current_user_can|'
                              r'is_user_logged_in|check_?admin|(?:require|include)(?:_once)?\b[^;\n]*(?:auth|session|'
                              r'check|guard|secure|login|protect|acl|permission)[^;\n]*;', code, re.I)
            if entry and not guard:
                first = next((i + 1 for i, l in enumerate(src.lines) if l.strip()), 1)
                out.append(finding(src.rel, first, 'authz-php-admin-page-unprotected',
                                   'Administrative page without session / role check',
                                   'This page lives in an administrative area and processes requests / outputs data, but '
                                   'contains no session, login or role check and includes no auth guard file.',
                                   'HIGH', 'MEDIUM', 862))
        pi = re.search(r'(?i)["\'][^"\'\n]*\b(?:select|update|delete)\b[^"\'\n]*\bwhere\b[^"\'\n]*\b\w*id\s*=\s*[^"\'\n]*["\']?\s*\.?\s*'
                       r'(?:\$_(?:GET|REQUEST|POST)\s*\[\s*["\'](\w*id)["\']|\$(\w*id)\b)', code)
        if pi and not re.search(r'user_?id|owner|\$_SESSION', code[max(0, pi.start() - 200):pi.end() + 200], re.I) and \
                'class ' not in s:
            out.append(finding(src.rel, src.line_of(pi.start()), 'authz-idor-php', 'Record selected by request id without owner filter',
                               'The SQL statement selects / modifies a row by the client-supplied id without restricting it '
                               'to the current user (no user_id / owner condition, no session check nearby): IDOR.',
                               'MEDIUM', 'LOW', 639))
    evaluate_endpoints(eps, out, 'routes file / controller')


# =========================================================================== #
# ASP.NET Core (C#)
# =========================================================================== #
CS_HTTP = {'HttpGet': 'GET', 'HttpPost': 'POST', 'HttpPut': 'PUT', 'HttpDelete': 'DELETE', 'HttpPatch': 'PATCH', 'Route': None,
           'AcceptVerbs': 'ANY'}
CS_AUTH_FUZZY = re.compile(r'(?i)^(?:authoriz\w*|require\w*(?:permission|role|scope|policy|auth)\w*|has\w*(?:permission|role|scope)\w*|'
                           r'\w*permission\w*|\w*roles?(?:required|allowed|auth\w*)|admin\w*only|\w*authoriz\w*)$')


def cs_guard(anns):
    best, expr = None, ''
    for a in anns:
        lv = None
        if a.name == 'AllowAnonymous':
            lv = 'public'
        elif a.name == 'Authorize':
            lv = 'authz' if re.search(r'Roles\s*=|Policy\s*=|^\s*"', a.args) else 'authn'
        elif a.name in ('TypeFilter', 'ServiceFilter') and re.search(r'(?i)auth|permission|role', a.args):
            lv = 'authz'
        elif CS_AUTH_FUZZY.match(a.name):
            lv = 'authz'
        if lv and (best is None or LEVEL_RANK[lv] > LEVEL_RANK.get(best, 0)):
            best, expr = lv, a.full[:100]
    return best, expr


def analyze_csharp(srcs, out):
    glob = any(re.search(r'AuthorizeFilter\s*\(|MapControllers\s*\(\s*\)\s*\.\s*RequireAuthorization|'
                         r'MapControllerRoute\s*\([^;]*?\)\s*\.\s*RequireAuthorization|FallbackPolicy\s*=\s*new|'
                         r'SetFallbackPolicy\s*\(', s.code) for s in srcs)
    eps = []
    for src in srcs:
        s, code = src.masked, src.code
        classes, methods = parse_members(src)
        for c in classes:
            is_ctl = c.name.endswith('Controller') or any(a.name in ('ApiController', 'Controller') for a in c.anns) or \
                re.search(r':\s*(?:\w+\.)*(?:Controller|ControllerBase|ApiController)\b', c.header)
            if not is_ctl:
                continue
            clv, cexpr = cs_guard(c.anns)
            prefix = next((first_string(a.args) or '' for a in c.anns if a.name == 'Route'), '')
            prefix = prefix.replace('[controller]', re.sub(r'Controller$', '', c.name).lower())
            mine = [m for m in methods if m.cls is c and m.body is not None]
            for m in mine:
                if any(a.name == 'NonAction' for a in m.anns):
                    continue
                hv = [a for a in m.anns if a.name in CS_HTTP]
                pre = code[max(0, m.off - 60):m.name_off]
                if not hv and not re.search(r'\bpublic\b', pre):
                    continue
                if not hv and not re.search(r'IActionResult|ActionResult|Task<|JsonResult|ViewResult|IResult', pre):
                    continue
                verb = next((CS_HTTP[a.name] for a in hv if CS_HTTP[a.name]), None)
                if verb is None:
                    verb = 'DELETE' if m.name.startswith(('Delete', 'Remove')) else 'POST' if m.name.startswith(
                        ('Create', 'Post', 'Update', 'Edit', 'Add', 'Save', 'Put')) else 'GET'
                path = norm_path(prefix, next((first_string(a.args) or '' for a in hv), ''))
                mlv, mexpr = cs_guard(m.anns)
                lv, expr = (mlv, mexpr) if mlv else (clv, cexpr)
                if mlv == 'authn' and clv == 'authz':
                    lv, expr = 'authz', cexpr
                if lv is None and glob:
                    lv, expr = 'authn', 'global authorization policy'
                e = Endpoint(src, (hv[0].line if hv else m.line), verb, path, m.name, lv, expr, c.name, 'aspnet')
                e.body, e.body_off, e.params = m.body_text(), m.body[0], m.params
                e.id_params = [p[3] for p in params_list(m) if ID_NAME.match(p[3]) or p[3].lower().endswith('id')]
                eps.append(e)
                if mlv == 'public' and not is_auth_endpoint(path, m.name) and (verb_is_write(verb, path, m.name) or
                                                                                is_sensitive(path, m.name) or clv):
                    out.append(finding(src.rel, e.line, 'authz-allowanonymous-sensitive',
                                       '[AllowAnonymous] on a sensitive / state-changing action',
                                       '%s is marked [AllowAnonymous]%s, so it is reachable without authentication.' % (
                                           e.label(), ' and overrides the controller-level %s' % cexpr if clv else ''),
                                       'HIGH', 'HIGH', 862))
                    e.level = 'public'
                check_read_guard_on_write(e, out)
                if e.level not in ('authz', 'deny', 'public') and e.id_params:
                    body = e.body
                    if not re.search(r'User\.|userId|UserId|OwnerId|GetUserId|ClaimTypes|_currentUser|CurrentUser|IsInRole|'
                                     r'AuthorizeAsync|_authorizationService|TenantId', body):
                        ids = '|'.join(map(re.escape, e.id_params))
                        fm = re.search(r'\.(?:Find|FindAsync)\s*\(\s*(?:%s)\s*\)|\.(?:FirstOrDefault|SingleOrDefault|First|Single|Where)'
                                       r'(?:Async)?\s*\(\s*(\w+)\s*=>\s*\1\.\w*Id\s*==\s*(?:%s)\s*\)' % (ids, ids), body)
                        if fm:
                            out.append(finding(src.rel, src.line_of(e.body_off + fm.start()), 'authz-idor-aspnet',
                                               'Entity loaded by client-supplied id without ownership check',
                                               '%s loads the record by the route id and never compares it with the current '
                                               'user (User / claims / owner filter): IDOR.' % e.label(), 'MEDIUM', 'MEDIUM', 639))
            # role inconsistency: siblings use Roles / Policy, this write action only plain [Authorize]
            ctl_eps = [x for x in eps if x.group == c.name]
            roled = [x for x in ctl_eps if 'Roles' in x.expr or 'Policy' in x.expr]
            if roled and clv != 'authz':
                for x in ctl_eps:
                    if x.level == 'authn' and 'Authorize' in x.expr and (verb_is_write(x.verb, x.path, x.name) or
                                                                         re.search(r'(?i)delete|remove|admin|manage|approve|grant',
                                                                                   x.name)):
                        out.append(finding(src.rel, x.line, 'authz-aspnet-missing-role',
                                           'Privileged action only requires authentication',
                                           '%s uses a plain [Authorize] while sibling actions require %s: any authenticated '
                                           'user can perform it.' % (x.label(), roled[0].expr[:80]), 'HIGH', 'MEDIUM', 863))
                        x.level = 'authz-checked'
        # minimal APIs
        groups = {}
        for gm in re.finditer(r'(?:var\s+)?(\w+)\s*=\s*(\w+)\s*\.\s*MapGroup\s*\(([^;]*);', code):
            groups[gm.group(1)] = 'authn' if 'RequireAuthorization' in gm.group(3) else None
        for mm in re.finditer(r'\b(\w+)\s*\.\s*Map(Get|Post|Put|Delete|Patch|Methods)\s*\(\s*"', s):
            po = s.find('(', mm.start())
            pc = match_close(s, po)
            pos = pc + 1
            while True:                                   # follow the fluent chain .RequireAuthorization(...)...
                cm = re.compile(r'\s*\.\s*\w+\s*(?:<[^>]*>)?\s*\(').match(s, pos)
                if not cm:
                    break
                pos = match_close(s, cm.end() - 1) + 1
            stmt = code[pc:pos]
            path = first_string(code[po:po + 300]) or ''
            lv = None
            ra = re.search(r'\.RequireAuthorization\s*\(([^)]*)\)', stmt)
            if ra:
                lv = 'authz' if ra.group(1).strip() else 'authn'
            if '.AllowAnonymous()' in stmt:
                lv = 'public'
            lv = max_level(lv, groups.get(mm.group(1)), 'authn' if glob and lv is None else None)
            verb = {'Methods': 'ANY'}.get(mm.group(2), mm.group(2).upper())
            eps.append(Endpoint(src, src.line_of(mm.start()), verb, path, '', lv,
                                (ra.group(0)[:60] if ra else ''), (src.rel, 'minimal'), 'aspnet'))
    evaluate_endpoints([e for e in eps if e.level != 'authz-checked'], out, 'controller / endpoint group')


# =========================================================================== #
# Ruby on Rails
# =========================================================================== #
RB_AUTH_FILTER = re.compile(r'(?i):(?:authenticate\w*!?|require_(?:login|user|admin|authentication|sign_in)\w*|logged_in_user|'
                            r'ensure_\w*(?:logged|login|user|admin|auth)\w*|authorize\w*!?|require_admin|admin_required|'
                            r'check_admin\w*|ensure_admin|verify_admin|doorkeeper_authorize!|authenticate_request|'
                            r'authenticate_api\w*|require_authentication|signed_in_user|must_be_\w+|admin_only|staff_only)\b')
RB_PUBLIC_CTL = re.compile(r'(?i)(?:Sessions|Registrations|Passwords|Confirmations|Unlocks|OmniauthCallbacks|Home|Pages|Static|'
                           r'Health\w*|Errors?|Public\w*|Webhooks?|Callbacks?|Landing|Welcome)Controller$')


def analyze_rails(srcs, out):
    ctls = {}
    for src in srcs:
        for m in re.finditer(r'^\s*class\s+([\w:]+)\s*<\s*([\w:]+)', src.code, re.M):
            name = m.group(1).split('::')[-1]
            if not name.endswith('Controller'):
                continue
            nxt = re.compile(r'^\s*class\s+[\w:]+\s*<', re.M).search(src.code, m.end())
            body = src.code[m.end():nxt.start() if nxt else len(src.code)]
            before = [x for x in re.finditer(r'^\s*(?:before_action|before_filter|prepend_before_action)\s+([^\n]+)', body, re.M)]
            skips = [x for x in re.finditer(r'^\s*skip_before_(?:action|filter)\s+([^\n]+)', body, re.M)]
            authz = bool(re.search(r'\bauthorize\b|load_and_authorize_resource|authorize_resource|verify_authorized|policy_scope',
                                   body))
            ctls[name] = dict(src=src, parent=m.group(2).split('::')[-1], line=src.line_of(m.start()),
                              auth=any(RB_AUTH_FILTER.search(x.group(1)) for x in before), authz=authz,
                              skips=[(x, src.line_of(m.end() + x.start())) for x in skips if RB_AUTH_FILTER.search(x.group(1))],
                              body=body, off=m.end(),
                              writes=bool(re.search(r'^\s*def\s+(?:create|update|destroy|delete)\b', body, re.M)))

    def eff(n, depth=0):
        c = ctls.get(n)
        if not c or depth > 8:
            return False
        return c['auth'] or eff(c['parent'], depth + 1)

    any_auth = any(eff(n) for n in ctls)
    for n, c in ctls.items():
        src = c['src']
        for x, line in c['skips']:
            only = re.search(r'only:\s*(\[[^\]]*\]|:\w+)', x.group(1))
            acts = re.findall(r':(\w+)', only.group(1)) if only else []
            if RB_PUBLIC_CTL.search(n):
                continue
            if not only or set(acts) & {'create', 'update', 'destroy', 'delete', 'edit', 'new'} or \
                    re.search(r'(?i)admin', n):
                out.append(finding(src.rel, line, 'authz-rails-skip-auth', 'Authentication filter skipped for sensitive actions',
                                   '%s skips its authentication filter %s.' % (
                                       n, 'for every action' if not only else 'for %s' % ', '.join(acts)),
                                   'HIGH', 'HIGH', 862))
        if any_auth and not eff(n) and not RB_PUBLIC_CTL.search(n) and n != 'ApplicationController' and \
                re.search(r'^\s*def\s+\w+', c['body'], re.M):
            out.append(finding(src.rel, c['line'], 'authz-rails-controller-unprotected',
                               'Controller without authentication filter',
                               '%s inherits no authentication before_action while other controllers of the application '
                               'require one%s.' % (n, '; it defines create / update / destroy actions' if c['writes'] else ''),
                               'HIGH' if c['writes'] else 'MEDIUM', 'MEDIUM', 862))
        admin_ctl = any(re.search(r'(?i)admin|staff|superuser', x.group(1)) for x in
                        re.finditer(r'^\s*(?:before_action|before_filter)\s+([^\n]+)', c['body'], re.M))
        for m in re.finditer(r'(?<![\w.])([A-Z]\w*)\.(?:find|find_by!?|where)\s*\(\s*(?:id:\s*)?params\[:?["\']?(\w*id)["\']?\]', c['body']):
            pre = c['body'][max(0, m.start() - 30):m.start()]
            if re.search(r'current_\w+\.\s*$|policy_scope\(\s*$|@current_\w+\.\s*$', pre) or admin_ctl:
                continue
            dstart = c['body'].rfind('\n', 0, max(0, c['body'].rfind('def ', 0, m.start())))
            dend = re.compile(r'^\s*def\s|^\s*private\b|^\s*protected\b', re.M).search(c['body'], m.end())
            action = c['body'][dstart:dend.start() if dend else len(c['body'])]
            if re.search(r'\bauthorize\b|authorize!|policy_scope|load_and_authorize_resource', action) or \
                    re.search(r'load_and_authorize_resource|authorize_resource', c['body']):
                continue
            out.append(finding(src.rel, src.line_of(c['off'] + m.start()), 'authz-idor-rails',
                               'Record loaded by params id without scoping to the current user',
                               '%s.%s(params[:%s]) is not scoped to current_user and the controller performs no '
                               'authorize / policy check: IDOR.' % (m.group(1), m.group(0).split('.')[1].split('(')[0], m.group(2)),
                               'MEDIUM', 'MEDIUM', 639))


# =========================================================================== #
# Go routers (gin, echo, fiber, chi, gorilla/mux, net/http)
# =========================================================================== #
GO_ROUTE = re.compile(r'\b(\w+)\s*\.\s*(GET|POST|PUT|PATCH|DELETE|Any|Handle|HandleFunc|Get|Post|Put|Patch|Delete|Methods)\s*\(')
GO_GROUP = re.compile(r'\b(\w+)\s*:?=\s*(\w+)\s*\.\s*(?:Group|Route|PathPrefix\([^)]*\)\s*\.\s*Subrouter)\s*\(')
GO_USE = re.compile(r'\b(\w+)\s*\.\s*Use\s*\(')


def analyze_go(srcs, out):
    eps = []
    for src in srcs:
        s, code = src.masked, src.code
        events = []
        for m in GO_GROUP.finditer(s):
            po = s.find('(', m.end() - 1)
            args = code[po + 1:match_close(s, po)]
            events.append((m.start(), 'group', m.group(1), m.group(2), mw_level(','.join(split_top(args)[1:]))))
        for m in GO_USE.finditer(s):
            po = m.end() - 1
            events.append((m.start(), 'use', m.group(1), None, mw_level(code[po + 1:match_close(s, po)])))
        for m in GO_ROUTE.finditer(s):
            po = m.end() - 1
            pc = match_close(s, po)
            args = split_top(s[po + 1:pc], code[po + 1:pc])
            if not args or not re.match(r'\s*"/', args[0]):
                continue
            events.append((m.start(), 'route', m.group(1), m.group(2), args))
        events.sort(key=lambda x: x[0])
        lvl = {}
        for off, kind, a, b, x in events:
            if kind == 'group':
                lvl[a] = max_level(lvl.get(b), x)
            elif kind == 'use':
                lvl[a] = max_level(lvl.get(a), x)
            else:
                verb = b.upper() if b.upper() in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE') else 'ANY'
                path = first_string(x[0]) or ''
                chain_with = re.search(r'\.\s*With\s*\(([^)]*)\)\s*\.\s*\w+\s*\(\s*$', code[max(0, off - 120):off + len(a) + 8])
                lv = max_level(lvl.get(a), mw_level(','.join(x[1:-1])) if len(x) > 2 else None,
                               mw_level(x[-1]) if re.search(r'\(\s*\w', x[-1]) and len(x) > 1 else None,
                               mw_level(chain_with.group(1)) if chain_with else None)
                eps.append(Endpoint(src, src.line_of(off), verb, path, '', lv, '', src.rel, 'go'))
        for f in functions(src):
            body = f.body()
            if not re.search(r'\*gin\.Context|echo\.Context|\*fiber\.Ctx|http\.ResponseWriter', f.params or '') or \
                    re.search(r'(?i)user_?id|owner|tenant|claims|c\.Get\(\s*"user|ctx\.Value\(|c\.Locals\(|GetString\(\s*"user', body):
                continue
            m = re.search(r'\.(?:First|Find|Take|Delete|Last)\s*\(\s*&?\w+\s*,\s*(?:c\.Param|c\.Params|chi\.URLParam|mux\.Vars\(r\))'
                          r'|\.Where\(\s*"\s*id\s*=\s*\?\s*"\s*,\s*(?:c\.Param|c\.Params|chi\.URLParam|mux\.Vars)', body)
            if m:
                out.append(finding(src.rel, src.line_of(f.start + m.start()), 'authz-idor-go',
                                   'Record loaded by path id without ownership condition',
                                   'Handler %s loads a record by the client-supplied id without a user / tenant condition '
                                   '(IDOR).' % (f.name or '(anonymous)'), 'MEDIUM', 'MEDIUM', 639))
    evaluate_endpoints(eps, out, 'router setup')


def analyze_authz(by_lang, out):
    analyze_spring(by_lang.get('java', []), out)
    js = by_lang.get('js', [])
    analyze_express(js, out)
    analyze_nest(js, out)
    analyze_python(by_lang.get('py', []), out)
    analyze_php(by_lang.get('php', []), out)
    analyze_csharp(by_lang.get('cs', []), out)
    analyze_rails(by_lang.get('rb', []), out)
    analyze_go(by_lang.get('go', []), out)


# =========================================================================== #
# Authentication / MFA flows (OWASP A07)
# =========================================================================== #
MFA_SIGNAL = re.compile(r'''(?ix)
    \b(?:requires?_?(?:2fa|mfa|otp|two_?factor|totp)|(?:2fa|mfa|otp|two_?factor|totp)_?(?:required|needed|pending|challenge)|
       need(?:s)?_?(?:2fa|mfa|otp)|require2FA|requireMfa|mfaRequired|twoFactorRequired|otpRequired|isMfaRequired)\w*\b
       ["']?\s*(?:[:=,]|=>|\()\s*(?:true|True|1|yes)\b
  | ["'](?:mfa|2fa|otp|two_?factor|totp)[_-]?(?:required|needed|pending|challenge)["']
  | (?:redirect|redirect_to|url_for|res\.redirect|sendRedirect|RedirectToAction|RedirectToPage|Redirect|header\s*\(\s*["']Location:)
       \s*\(?[^\n;]{0,80}(?:2fa|mfa|otp|two[_-]?factor|totp|verify[_-]?code|second[_-]?factor|challenge)''')
SESSION_ISSUE = re.compile(r'''(?x)
    \blogin_user\s*\(|\blogin\s*\(\s*request\s*,|\bAuth::(?:login|loginUsingId|guard\([^)]*\)->login)\s*\(|\bauth\(\)\s*->\s*login\s*\(|
    \breq\.(?:login|logIn)\s*\(|\breq\.session\.(?:user\w*|uid|authenticated|logged\w*|is_?auth\w*|account\w*)\s*=(?!=)|
    \bguard\s*\([^)]*\)\s*->\s*login\s*\(|->\s*loginUsingId\s*\(|\bsession\s*\(\s*\[\s*["'](?:user_?id|uid)["']|
    \bsession\s*\[\s*["'](?:user_?id|uid|user|logged_?in|authenticated|is_?auth\w*|account_?id|username)["']\s*\]\s*=(?!=)|
    \$_SESSION\s*\[\s*["'](?:user_?id|uid|user|logged_?in|authenticated|auth\w*|account_?id|username)["']\s*\]\s*=(?!=)|
    \bsession\s*\[\s*:(?:user_id|uid|user|logged_in|authenticated)\s*\]\s*=(?!=)|\bsign_in\s*\(?\s*@?\w+|\blog_in\s*\(?\s*@?\w+|
    \bSignInAsync\s*\(|\bSecurityContextHolder\.getContext\s*\(\s*\)\s*\.setAuthentication\s*\(|
    \bsession\.setAttribute\s*\(\s*["'](?:user|userId|username|authenticated|loggedIn|currentUser|USER)["']|
    \bcookies\.(?:signed|encrypted)\s*\[\s*:(?:user_id|remember_token)\s*\]\s*=|HttpContext\.Session\.Set\w*\s*\(\s*"(?:UserId|User)"''')
TOKEN_ISSUE = re.compile(r'''(?ix)
    \bjwt\.(?:sign|encode)\s*\(|\bJwts\.builder\s*\(|\bJWT\.create\s*\(|\bnew\s+JwtSecurityToken\s*\(|\bCreateToken\s*\(|
    \b(?:create_access_token|create_refresh_token|generate_?(?:access_?|auth_?|jwt_?|session_?|full_?)?token|createToken|
       create_?jwt|issue_?token|issueToken|issueJwt|sign_?token|signToken|make_?token|encode_?token|build_?token|buildToken|
       generateJwt|createJwt|createAccessToken|generateAccessToken|tokenFor|JWT::encode|JwtService\.\w+)\s*\(''')
COOKIE_ISSUE = re.compile(r'(?i)(?:res\.cookie|set_cookie|setcookie|Cookies\.Append|addCookie|response\.set_cookie)\s*\([^;\n]*'
                          r'(?:token|jwt|session|auth|access)')
SCOPED = re.compile(r'(?i)(pending|temp|tmp|partial|pre_?auth|preauth|challenge|mfa|2fa|otp|ticket|interim|half|step_?up|limited|'
                    r'unverified|intermediate|totp|reset|verify|verification|refresh)')
OTP_VERIFY = re.compile(r'''(?ix)
    \b(?:pyotp\.\w+\([^)]*\)\.verify|totp\.verify|hotp\.verify|\.verify_totp|verify_?totp|verify_?otp|verify_?mfa|verify_?2fa|
       verify_?code|check_?otp|check_?totp|validate_?otp|validate_?totp|validate_?code|speakeasy\.(?:totp|hotp)\.verify\w*|
       authenticator\.(?:check|verify)|otplib\.\w+\.(?:check|verify)|totp\.(?:check|validate|Validate|ValidateCustom)|
       googleAuthenticator\.authorize\w*|gAuth\.authorize|\.authorize(?:User)?\s*\(\s*\w*[sS]ecret|TotpVerifier|
       isValidCode|verifyCode|verifyTotp|verifyOtp|validateOtp|checkCode|VerifyTotp|ValidateTwoFactorPIN|
       VerifyTwoFactorTokenAsync|TwoFactorSignInAsync|rotp\.\w+\.verify|ROTP::TOTP|verify_with_drift|google2fa->verifyKey|
       ->verifyKey\s*\(|verifyKeyNewer|->verifyCode\s*\()''')
STORED_CODE_CMP = re.compile(r'''(?ix)(?:===?|!==?|\.equals\s*\(|hash_equals\s*\(|compare_digest\s*\(|secure_compare\s*\(|
    FixedTimeEquals\s*\(|\.Equals\s*\()[^\n;]*\b\w*(?:otp_?code|otpCode|sms_?code|smsCode|email_?code|verification_?code|
    verificationCode|mfa_?code|one_?time_?code|login_?code|reset_?code|resetCode|confirm\w*_?code)\b|
    \b\w*(?:otp_?code|otpCode|sms_?code|smsCode|email_?code|verification_?code|verificationCode|mfa_?code|one_?time_?code|
    login_?code|reset_?code|resetCode)\b[^\n;]*(?:===?|!==?|\.equals\s*\(|\.Equals\s*\()''')
EXPIRY_TOKENS = re.compile(r'(?i)expir|created_?at|createdAt|sent_?at|sentAt|issued|ttl|valid_?until|validUntil|timestamp|'
                           r'minutes|isAfter|isBefore|time\.time|now\(|Date\.now|timezone\.now|Instant\.|LocalDateTime|'
                           r'DateTime\.(?:Utc)?Now|\bago\b|Time\.(?:now|current)|time\(\)|strtotime|carbon|max_?age|lifetime|'
                           r'within|older_than|stale|elapsed')
# real attempt limiting (a log line saying "login attempt" is not a limiter)
ATTEMPT_TOKENS = re.compile(r'(?i)failed\w*attempt|attempt\w*(?:count|s)\b|login_?attempts|attempts\s*(?:[+><=]|\+\+|-=|\.inc)|'
                            r'incr\w*fail|fail\w*count|failure_?count|lockout|locked_?until|lockUntil|lock_?until|isLocked|'
                            r'is_locked|rate_?limit|RateLimit|throttle|limiter|Bucket4j|max_?attempts|MAX_\w*ATTEMPTS|'
                            r'registerFailed|tooManyRequests|TOO_MANY_REQUESTS|\b429\b|slowDown|express-rate-limit|'
                            r'ThrottleRequests|EnableRateLimiting|@limiter|brute|backoff|cooldown|remaining_?tries|'
                            r'AccessFailedAsync|lockoutOnFailure\s*:\s*true|LockoutEnabled|resilience4j|limits\s*\(')
REAUTH_TOKENS = re.compile(r'(?i)password|passwd|pwd|current_?code|otp|totp|\bcode\b|verify|confirm|reauth|re_?authenticat|'
                           r'check_password|password_verify|matches\s*\(|bcrypt|authenticate|sudo|step_?up|recent_?login|'
                           r'fresh|require_password|PasswordConfirm|password\.confirm')
GUARD_ADMIN = re.compile(r'(?i)PreAuthorize|Secured|RolesAllowed|admin|Roles\s*\(|permission_required|staff_member|IsAdmin|'
                         r'role:|can:|hasRole|Authorize\s*\(\s*Roles')
DEV_BYPASS = re.compile(r'''(?x)\bif\s*\(?\s*!?\s*(?:settings\.DEBUG|DEBUG|app\.debug|current_app\.debug|config\[["']DEBUG|
    process\.env\.NODE_ENV\s*[!=]==?\s*["'](?:dev\w*|test|local)["']|env(?:ironment)?\s*===?\s*["'](?:dev\w*|test|local)["']|
    isDev\w*|IsDevelopment\s*\(\s*\)|Rails\.env\.(?:development|test)\?|app\(\)\s*->\s*environment\(\s*["']local|
    APP_ENV\s*===?\s*["'](?:dev|local)|env\.isDev\w*|environment\.(?:dev|development|test)\w*|testMode|test_mode|
    bypass\w*|skip_?(?:mfa|2fa|otp)\w*)[^\n]*\)?\s*:?\s*\{?\s*(?:\n\s*)?return\s+(?:true|True|Ok\b|next\(\))''')
FAIL_OPEN = re.compile(r'''(?sx)
    \bcatch\s*(?:\([^)]*\))?\s*\{(?:(?!\}).){0,240}?\breturn\s+(?:true|Ok\s*\(|next\s*\(|"ok"|1\s*;|done\s*\(\s*null\s*,\s*true)
  | \.catch\s*\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*(?:true|next\s*\(|\{\s*return\s+true)
  | \bexcept\b[^:\n]*:[ \t]*\n(?:[ \t]*[^\n]*\n){0,2}?[ \t]*return\s+True\b
  | \bexcept\b[^:\n]*:[ \t]*return\s+True\b
  | \brescue\b[^\n]*\n(?:[ \t]*[^\n]*\n){0,2}?[ \t]*(?:return\s+)?true\b
  | \bcatch\s*\([^)]*\)\s*\{(?:(?!\}).){0,240}?(?:valid|ok|verified|result|isValid|success)\w*\s*=\s*true
  | \bif\s+err\s*!=\s*nil\s*\{\s*(?:[^{}\n]*\n\s*){0,2}?return\s+true\b''')
FAIL_OPEN_AUTHZ = re.compile(r'''(?sx)
    \bcatch\s*(?:\([^)]*\))?\s*\{(?:(?!\}).){0,240}?(?:context\.Succeed\s*\(|\bnext\s*\(\s*\)|return\s+(?:AuthorizationResult\.Success|
       AccessDecisionVoter\.ACCESS_GRANTED|ACCESS_GRANTED|PolicyResult\.Allow|Allow\b|ALLOW\b|true\b|Ok\s*\())
  | \bif\s*\(\s*err\s*\)\s*(?:\{\s*)?(?:return\s+)?next\s*\(\s*\)
  | \bexcept\b[^:\n]*:[ \t]*\n(?:[ \t]*[^\n]*\n){0,2}?[ \t]*(?:return\s+True\b|pass\s*\n[ \t]*return\s+True)''')
SWALLOW = re.compile(r'''(?x)
    \bcatch\s*(?:\((?![^)]*\b(?:ignored?|expected|unused|_)\s*\))[^)]*\))?\s*\{\s*(?:return\s*(?:null|nil|None|\[\s*\]|""|'')?\s*;?\s*)?\}
  | \bexcept\b[^:\n]*:[ \t]*(?:\n[ \t]*)?pass\b
  | \brescue\b[^\n]*\n[ \t]*(?:nil\s*\n[ \t]*)?end\b
  | \.catch\s*\(\s*(?:\(\s*\w*\s*\)|\w+)\s*=>\s*(?:\{\s*\}|null|undefined)\s*\)''')
EMPTY_CODE_OK = re.compile(r'''(?x)\bif\s*\(?\s*(?:!|not\s+)\s*\$?\w*(?:code|otp|token|totp|pin)\w*\s*\)?\s*:?\s*\{?\s*(?:\n\s*)?
    return\s+(?:true|True)\b|\bif\s*\(?\s*\$?\w*(?:code|otp|token|totp)\w*\s*(?:===?|==|is)\s*(?:null|None|nil|undefined|["']{2})\s*\)?\s*
    :?\s*\{?\s*(?:\n\s*)?return\s+(?:true|True)\b|\bif\s*\(?\s*(?:empty|blank\?|is_null|isEmpty|IsNullOrEmpty|isBlank)\s*\(?\s*\$?\w*
    (?:code|otp|token)\w*\s*\)?\s*\)?\s*:?\s*\{?\s*(?:\n\s*)?return\s+(?:true|True)\b|\b\w*(?:code|otp)\w*\.blank\?\s*\n?\s*(?:return\s+)?true''')
FIXATION_REGEN = re.compile(r'(?i)session_regenerate_id|req\.session\.regenerate|changeSessionId|\.invalidate\s*\(|cycle_key|'
                            r'rotate_token|reset_session|session\.clear\s*\(|session\.flush|->regenerate\s*\(|migrate\s*\(|'
                            r'sessionFixation|session\.renew|regenerate_session|SignOutAsync|Session\.Abandon|renew_session_id|'
                            r'login\s*\(\s*request\s*,|login_user\s*\(|sign_in\s*\(')
AUTH_GUARD_NAME = re.compile(r'(?i)^(?:authenticate\w*|verify_?token\w*|require_?auth\w*|auth_?middleware|authMiddleware|'
                             r'doFilterInternal|doFilter|OnAuthorization|isAuthenticated|ensureAuth\w*|checkAuth\w*|'
                             r'require_?login|current_user|authenticate_user!?|load_user|user_loader|get_current_user|'
                             r'jwtAuth\w*|protect|requireUser|handle|canActivate|validate)$')
PENDING_MARK = re.compile(r'(?i)pending|2FA_PENDING|mfa_?pending|pre_?2fa|pre_?auth|partial|awaiting_?(?:otp|mfa)|otp_?pending|'
                          r'scope\s*[:=]\s*["\']mfa|purpose|mfa_?verified|two_?factor_?(?:passed|verified)|otp_?verified')
FRONT_OTP_CMP = re.compile(r'''(?i)\b\w*(?:otp|code|pin)\w*\s*(?:\.value\s*)?===?\s*(?:\w+\.)*(?:otp|expectedOtp|serverOtp|correctOtp|
    otpCode|sentOtp|generatedOtp|expected_?code|server_?code)\b|\b(?:data|response|res|json|result)\.(?:otp|code|otpCode)\s*===?''', re.X)
PREDICTABLE_TOKEN = re.compile(r'''(?i)\b\w*(?:reset|token|code|otp|nonce|activation)\w*\s*(?:[:=]|=>)\s*[^;\n]*(?:md5|sha1|sha256|
    hexdigest|digest|base64\w*|Digest::\w+\.\w+|hash)\s*\(\s*[^)\n]*(?:email|username|user\.id|user_id|\btime\b|Time\.|now\(|
    timestamp|Date|microtime|uniqid)''', re.X)


IDENTITY_SET = re.compile(r'(?i)setAuthentication\s*\(|\breq\.user\s*=(?!=)|\brequest\.user\s*=(?!=)|\bg\.user\s*=(?!=)|'
                          r'ctx\.state\.user\s*=(?!=)|c\.Set\(\s*"user|HttpContext\.User\s*=|context\.User\s*=|@current_user\s*=|'
                          r'Current\.user\s*=|login_user\s*\(|res\.locals\.user\s*=|request\.state\.user\s*=')
DECISION_OP = re.compile(r'\bif\b|\belif\b|\bunless\b|\?|&&|\|\||[=!]==?|\bcase\b|\bswitch\b|\bwhen\b|\.equals(?:IgnoreCase)?\s*\(|'
                         r'\.Equals\s*\(|\bin\s*[\[(]|includes\s*\(|\bnot\s+\w|\band\b|\bor\b')
CMP_OP = re.compile(r'===?|!==?|\.equals(?:IgnoreCase)?\s*\(|\.Equals\s*\(|hash_equals\s*\(|compare_digest\s*\(|'
                    r'secure_compare\s*\(|FixedTimeEquals\s*\(|\.eql\?|\bis\s+not\b|\bstrcmp\s*\(')
STORED_SIDE = re.compile(r'(?i)(?:\b(?:user|pending|stored|saved|expected|record|row|session|cache|redis|account|challenge|entry|'
                         r'db|otp_?record|verification|current_user|self|this|@\w+|\$_SESSION|member|customer)\w*'
                         r'(?:\.|\[\s*["\':]|->)\s*(?:get)?\w*(?:otp|code|pin|passcode)\w*)|get\w*(?:Otp|Code)\s*\(\s*\)|'
                         r'\b(?:pending|stored|saved|expected|sent)_?\w*\b')
REQ_SIDE = re.compile(r'(?i)\breq\b|request|input|submitted|\bbody\b|dto|params|form|getCode\s*\(|payload|data\[|\$_POST|'
                      r'\$_GET|\bcode\b|\botp\b|\bpin\b')
_CLIENT_KEYS = re.compile(r'(?i)^(?:x[-_])?(?:user[-_]?)?(?:(?P<mfa>mfa\w*|2fa\w*|two_?factor\w*|otp_?(?:verified|passed|ok|valid|'
                          r'done|checked|status|success)|totp_?(?:ok|verified|passed)|trusted_?device\w*|trusteddevice|'
                          r'device_?trusted|remember_?(?:device|browser)|skip_?(?:mfa|2fa|otp)|bypass\w*|step_?up\w*|mfaverified)|'
                          r'(?P<priv>role|roles|user_?role|user_?type|account_?type|is_?admin|admin|is_?staff|is_?superuser|'
                          r'superuser|permissions?|privileges?|access_?level|user_?level|is_?owner|is_?manager|is_?root|'
                          r'isadmin|userrole))$')


def _client_kind(name):
    m = _CLIENT_KEYS.match((name or '').replace('-', '_'))
    if not m:
        return None
    return 'mfa' if m.group('mfa') else 'priv'


def client_bound_vars(f):
    """[(variable, request key, 'mfa'|'priv')] bound from client-controlled data inside / at the entry of a function."""
    res = []
    params = f.params or ''
    for m in re.finditer(r'@(?:CookieValue|RequestHeader|RequestParam)\s*\(\s*(?:(?:value|name)\s*=\s*)?"([^"]+)"[^)]*\)\s*'
                         r'(?:final\s+)?[\w<>?]+\s+(\w+)', params):
        k = _client_kind(m.group(1)) or _client_kind(m.group(2))
        if k:
            res.append((m.group(2), m.group(1), k))
    for m in re.finditer(r'\[From(?:Header|Query|Form|Cookie|Route)(?:\s*\(\s*Name\s*=\s*"([^"]+)"\s*\))?\]\s*[\w<>?]+\s+(\w+)', params):
        k = _client_kind(m.group(1) or '') or _client_kind(m.group(2))
        if k:
            res.append((m.group(2), m.group(1) or m.group(2), k))
    for m in re.finditer(r'(\w+)\s*:\s*[\w\[\], .|]+?=\s*(?:fastapi\.)?(?:Header|Cookie|Query|Form|Body)\s*\(([^)]*)\)', params):
        alias = re.search(r'alias\s*=\s*["\']([^"\']+)', m.group(2))
        k = _client_kind(alias.group(1) if alias else m.group(1)) or _client_kind(m.group(1))
        if k:
            res.append((m.group(1), alias.group(1) if alias else m.group(1), k))
    body = f.body()
    for m in re.finditer(r'(?:const|let|var)\s*\{([^}]*)\}\s*=\s*req\.(?:body|query|cookies|headers|params|signedCookies)', body):
        if 'signedCookies' in m.group(0):
            continue
        for part in m.group(1).split(','):
            nm = part.split(':')[-1].split('=')[0].strip()
            src_key = part.split(':')[0].strip()
            k = _client_kind(src_key) or _client_kind(nm)
            if k and nm:
                res.append((nm, src_key, k))
    for rx in (r'(?:const|let|var|final\s+\w+|String|bool|boolean|var)\s+(\w+)\s*=\s*[^;\n]*?(?:req\.(?:body|query|cookies|headers|params)'
               r'(?:\.|\[\s*["\'])|req\.(?:get|header|cookies)\s*\(\s*["\']|getHeader\s*\(\s*"|getParameter\s*\(\s*"|'
               r'Request\.(?:Headers|Cookies|Query|Form)\s*\[\s*")([\w-]+)',
               r'^\s*(\w+)\s*=\s*request\.(?:form|args|values|json|cookies|headers|COOKIES|GET|POST|META|data|query_params)\s*'
               r'(?:\.get\s*\(\s*|\[\s*)["\'](?:HTTP_)?([\w-]+)',
               r'\$(\w+)\s*=\s*(?:\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*|\$request\s*->\s*(?:input|get|query|header|cookie|post)\s*\(\s*)["\']([\w-]+)',
               r'(\w+)(?:\s*,\s*\w+)?\s*:?=\s*(?:c\.(?:GetHeader|Query|PostForm|DefaultQuery|Cookie|Param|QueryParam|FormValue)|'
               r'r\.(?:Header\.Get|FormValue|PostFormValue|URL\.Query\(\)\.Get))\s*\(\s*"([\w-]+)',
               r'^\s*@?(\w+)\s*=\s*(?:cookies|params|request\.headers)\s*\[\s*[:"\']([\w-]+)'):
        for m in re.finditer(rx, body, re.M):
            k = _client_kind(m.group(2)) or _client_kind(m.group(1))
            if k:
                res.append((m.group(1), m.group(2), k))
    # attributes of request-bound objects: body.mfa_verified, dto.isAdmin, payload.role
    for m in re.finditer(r'\b((?:body|payload|dto|data|form|req_?body|request_?body|input|creds|credentials|login_?req|req)'
                         r'\.(\w+))\b', body):
        k = _client_kind(m.group(2))
        if k and not m.group(1).startswith('req.'):
            res.append((m.group(1), m.group(2), k))
    seen, uniq = set(), []
    for r in res:
        if r[0] not in seen:
            seen.add(r[0])
            uniq.append(r)
    return uniq


def stored_code_compare(body):
    """Offset of a line comparing a stored one-time code with the submitted one (None if absent)."""
    pos = 0
    for line in body.split('\n'):
        if CMP_OP.search(line) and re.search(r'(?i)otp|one_?time|verif\w*_?code|sms_?code|email_?code|login_?code|mfa|2fa|totp|'
                                             r'\bpin\b|passcode|reset_?code|confirm\w*_?code|activation_?code|security_?code|'
                                             r'pending\w*|two_?factor_?code', line) and STORED_SIDE.search(line) and \
                REQ_SIDE.search(line) and not OTP_VERIFY.search(line) and not EXPIRY_TOKENS.search(line) and \
                not re.search(r'(?i)status_?code|http|response|error_?code|country|zip|postal|currency|lang', line):
            return pos + (len(line) - len(line.lstrip()))
        pos += len(line) + 1
    return None


MFA_CLAIM_NAME = re.compile(r'(?i)^[\w-]*(?:mfa|2fa|two_?factor|otp|totp)[\w-]*$')
CLAIM_WRITE = re.compile(r'''\.(?:claim|withClaim|addClaims?|setClaim|put)\s*\(\s*["']([\w-]+)["']\s*,''')
CLAIM_KEY = re.compile(r'''(?:^|[{,\s(])["']?([A-Za-z_][\w-]*)["']?\s*(?::|=>|=(?!=))''')
TOKEN_READ = re.compile(r'(?i)parseClaims\w*|parseSigned\w*|getPayload\s*\(|getBody\s*\(|jwt\.(?:verify|decode)|jwtVerify|'
                        r'JWT::decode|decode_?(?:token|jwt)|verify_?(?:token|jwt)|get_jwt\b|getClaims?\s*\(|ValidateToken|'
                        r'HasClaim|FindFirst\w*\s*\(|jwt_required|get_jwt_identity|\.Claims\b')
CLAIM_READ_LINE = re.compile(r'(?i)claims?|payload|decoded|getClaim|get_jwt|req\.(?:user|auth)|request\.(?:user|auth)|'
                             r'token|jwt|HasClaim|FindFirst|principal|identity')


def mfa_claim_writes(src, funcs):
    """[(claim, line, func)] for MFA-state claims put into tokens by this file."""
    res = []
    for f in funcs:
        body, fm = f.body(), f.masked()
        builds = bool(TOKEN_ISSUE.search(body))
        if builds:
            for m in CLAIM_WRITE.finditer(body):
                if MFA_CLAIM_NAME.match(m.group(1)):
                    res.append((m.group(1), src.line_of(f.start + m.start()), f))
        for m in TOKEN_ISSUE.finditer(body):
            po = fm.find('(', m.end() - 1)
            if po < 0:
                continue
            call = body[po:match_close(fm, po) + 1]
            for k in CLAIM_KEY.finditer(call):
                if MFA_CLAIM_NAME.match(k.group(1)):
                    res.append((k.group(1), src.line_of(f.start + po + k.start(1)), f))
    return res


def mfa_unread_claims(funcs_by_src, out):
    """Report MFA-state claims that are written into tokens but never checked when tokens are read.

    The classic response-manipulation 2FA bypass: the login answers {"require2FA": true, "token": ...}; the token
    only *says* 2FA is pending and nothing on the verification side enforces it, so flipping the flag in the response
    (or just ignoring it) and replaying the token gives a full session."""
    writes = [(src, w) for src, funcs in funcs_by_src for w in mfa_claim_writes(src, funcs)]
    if not writes or not any(TOKEN_READ.search(s.code) for s, _ in funcs_by_src):
        return set()
    writer_funcs = {id(w[2]) for _, w in writes}
    unread, reported = set(), set()
    for src, (claim, line, _) in writes:
        if claim in reported:
            continue
        rx = re.compile(r'(?<![\w-])%s(?![\w-])' % re.escape(claim))
        read = False
        for s2, funcs2 in funcs_by_src:
            if not rx.search(s2.code):
                continue
            for f in funcs2:
                if id(f) in writer_funcs:
                    continue
                body = f.body()
                for ln in body.split('\n'):
                    if rx.search(ln) and (CLAIM_READ_LINE.search(ln) or TOKEN_READ.search(body)):
                        read = True
                        break
                if read:
                    break
            if read:
                break
        reported.add(claim)
        if read:
            continue
        unread.add(claim)
        out.append(finding(src.rel, line, 'mfa-claim-not-enforced', 'Token carries a 2FA-pending flag nothing enforces',
                           'The token is minted with the "%s" claim, but no filter / middleware / guard that reads tokens '
                           'ever checks it: a token issued while the second factor is still pending is accepted as a full '
                           'session. Changing "%s" to false in the login response (response manipulation) or simply '
                           'replaying the token skips 2FA. Reject tokens carrying this claim on every route except the '
                           'OTP verification endpoint, or issue a separate role-less pending ticket.' % (claim, claim),
                           'HIGH', 'MEDIUM', 308))
    return unread


def analyze_authflow(srcs, out):
    funcs_by_src = [(s, functions(s)) for s in srcs]
    unread_claims = mfa_unread_claims(funcs_by_src, out)
    proj_mfa = any(OTP_VERIFY.search(s.code) or re.search(r'(?i)totp|two_?factor|2fa|mfa|otp', s.code) for s in srcs)
    proj_pending = any(re.search(r'(?i)(?:pending|pre_?2fa|pre_?auth|partial)\w*\s*["\']?\s*[:=\]]|2FA_PENDING|mfa_?pending|'
                                 r'scope\s*[:=]\s*["\']mfa', s.code) for s in srcs)
    for src, funcs in funcs_by_src:
        file_attempts = bool(ATTEMPT_TOKENS.search(src.code))
        front = (bool(re.search(r'(?i)(?:^|/)(?:public|static|assets|www|wwwroot|frontend|client|web|resources/static|src/app)/',
                                src.low_rel)) and src.lang == 'js') or src.lang == 'php'
        if front:
            scan = src.text if src.lang == 'php' else src.code
            for m in FRONT_OTP_CMP.finditer(scan):
                if src.lang == 'php':
                    seg = scan[:m.start()]
                    if seg.rfind('<script') <= seg.rfind('</script'):
                        continue                          # only inline browser scripts of PHP pages
                out.append(finding(src.rel, scan.count('\n', 0, m.start()) + 1, 'mfa-client-side-check', 'OTP verified in browser code',
                                   'The one-time code is compared in client-side JavaScript: the expected code reaches the '
                                   'browser and the check can be skipped. Verify the code on the server only.', 'HIGH', 'HIGH', 308))
                break
        for m in PREDICTABLE_TOKEN.finditer(src.code):
            out.append(finding(src.rel, src.line_of(m.start()), 'auth-predictable-token',
                               'Security token derived from predictable values',
                               'The token is a hash / encoding of guessable inputs (e-mail, user id, time). Generate reset / '
                               'activation tokens with a CSPRNG (secrets.token_urlsafe, SecureRandom, random_bytes).',
                               'HIGH', 'MEDIUM', 338))
        for f in funcs:
            body = f.body()
            if not body.strip():
                continue
            low_name = (f.name or '').lower()
            low_cls = (f.cls or '').lower()
            ctx_text = (f.decor or '') + ' ' + src.above(f.line, 4)
            # ---- (a) full session / token issued in the same function that answers "MFA required"
            sig = MFA_SIGNAL.search(body)
            # a "handlePending2FA" helper is judged by the token it mints, not by its name
            token_factory = bool(re.search(r'(?i)^(?:generate|create|issue|build|sign|make|new|encode|mint)\w*(?:token|jwt|ticket)',
                                           f.name or ''))
            if sig and not token_factory and not OTP_VERIFY.search(body[:sig.start()]):
                hit = None
                for m in sorted(list(SESSION_ISSUE.finditer(body)) + list(COOKIE_ISSUE.finditer(body)), key=lambda x: x.start()):
                    ls, le = body.rfind('\n', 0, m.start()) + 1, body.find('\n', m.end())
                    line_txt = body[ls:le if le > 0 else len(body)]
                    if SCOPED.search(line_txt) or m.start() > sig.start():
                        continue
                    hit = m                               # keep the session write nearest to the "MFA required" answer
                if hit is None:
                    fm = f.masked()
                    for m in TOKEN_ISSUE.finditer(body):
                        ls, le = body.rfind('\n', 0, m.start()) + 1, body.find('\n', m.end())
                        line_txt = body[ls:le if le > 0 else len(body)]
                        po = fm.find('(', m.end() - 1)
                        call = body[m.start():(match_close(fm, po) + 1) if po >= 0 else m.end()]
                        # the call and the rest of its line decide the scope; "pendingToken = generateToken(..roles..)"
                        # is still a full token whatever the variable is called
                        if SCOPED.search(body[m.start():le if le > 0 else len(body)]) or SCOPED.search(call):
                            continue
                        var = re.search(r'(\w+)\s*(?::\s*[\w<>]+\s*)?=\s*[^=\n]*$', body[ls:m.start()])
                        stmt_s = max(body.rfind(';', 0, sig.start()), body.rfind('\n\n', 0, sig.start()),
                                     body.rfind('return', 0, sig.start()) - 1)
                        stmt_e = body.find(';', sig.end()) if body.find(';', sig.end()) > 0 else sig.end() + 200
                        stmt = body[stmt_s:stmt_e]
                        if (stmt_s < m.start() < min(sig.start() + 200, stmt_e)) or \
                                (var and m.start() < sig.start() and re.search(r'\b%s\b' % re.escape(var.group(1)), stmt)):
                            hit = m
                            break
                if hit is not None:
                    out.append(finding(src.rel, src.line_of(f.start + hit.start()), 'mfa-session-before-second-factor',
                                       'Full session / token issued before the second factor is verified',
                                       '%s establishes a complete authenticated session (%s) in the same flow that tells the '
                                       'client the second factor is still required: the client can ignore the OTP step and '
                                       'use the session / token directly (MFA bypass). Issue only a short-lived, purpose-'
                                       'scoped pending ticket here.' % (f.name or 'This handler', hit.group(0).strip()[:50]),
                                       'HIGH', 'MEDIUM', 308))
            verify_ctx = bool(re.search(r'(?i)(?:verify|check|validate|confirm|authorize|authenticate|login|submit)\w*'
                                        r'(?:otp|totp|mfa|2fa|two_?factor|code|token|pin|passcode)|(?:otp|totp|mfa|2fa)\w*'
                                        r'(?:verify|check|valid|confirm|login)', f.name or '')) or bool(OTP_VERIFY.search(body))
            # ---- (b) fail-open verification
            if verify_ctx:
                m = FAIL_OPEN.search(f.masked())
                if m:
                    out.append(finding(src.rel, src.line_of(f.start + m.start()), 'mfa-verification-fail-open',
                                       'OTP / token verification fails open',
                                       '%s treats an exception during verification as success: any malformed code or '
                                       'backend error passes the second factor. Return false / deny on errors.' % (f.name or 'Verification'),
                                       'HIGH', 'HIGH', 308))
                m = EMPTY_CODE_OK.search(body)
                if m:
                    out.append(finding(src.rel, src.line_of(f.start + m.start()), 'mfa-empty-code-accepted',
                                       'Missing / empty code accepted by the verification',
                                       '%s returns success when the submitted code (or the enrolled secret) is empty: '
                                       'omitting the parameter bypasses the second factor.' % (f.name or 'Verification'),
                                       'HIGH', 'HIGH', 308))
                m = DEV_BYPASS.search(body)
                if m:
                    out.append(finding(src.rel, src.line_of(f.start + m.start()), 'mfa-environment-bypass',
                                       'Verification bypassed by a debug / environment / bypass flag',
                                       'The second-factor check returns success when a debug / development / bypass flag is '
                                       'set; one misconfiguration disables MFA in production.', 'HIGH', 'MEDIUM', 308))
            # ---- (b2) fail-open authorization / authentication handlers (OWASP 2025 A10)
            authz_ctx = re.search(r'(?i)permission|authoriz|access|acl|guard|polic|evaluat|voter|canActivate|has_?perm|check_?perm|'
                                  r'is_?allowed|handle(?:Requirement)?(?:Async)?$|middleware|interceptor|verify_?token|'
                                  r'authenticat|tenant|entitle|protect', (f.name or '') + ' ' + (f.cls or ''))
            if authz_ctx and not verify_ctx:
                m = FAIL_OPEN.search(f.masked()) or FAIL_OPEN_AUTHZ.search(f.masked())
                if m:
                    out.append(finding(src.rel, src.line_of(f.start + m.start()), 'authz-fail-open',
                                       'Security check fails open on error',
                                       '%s grants access when an exception / error occurs (error handler returns allow, calls '
                                       'next() or marks the requirement as succeeded): an outage or a crafted input disables the '
                                       'check. Deny on error.' % (f.name or 'This check'), 'HIGH', 'MEDIUM', 755))
            # ---- (b3) exceptions swallowed in security-relevant code
            if re.search(r'(?i)auth|login|logon|permission|csrf|token|verify|acl|role|session|signature|password|otp|mfa|access|'
                         r'secur|crypt|tenant', (f.name or '') + ' ' + (f.cls or '') + ' ' + src.low_rel):
                m = SWALLOW.search(f.masked())
                if m:
                    out.append(finding(src.rel, src.line_of(f.start + m.start()), 'exception-swallowed-security',
                                       'Exception swallowed in security-relevant code',
                                       '%s catches an exception and silently continues (no log, no rethrow, no denial): failures '
                                       'of the security check go unnoticed and execution may proceed as if it passed.'
                                       % (f.name or 'This code'), 'MEDIUM', 'MEDIUM', 755))
            # ---- (c) 2FA disable / reset without re-authentication
            if re.search(r'(?i)(?:disable|remove|delete|reset|turn_?off|deactivate|clear|unenroll|unlink|destroy)[_/-]?'
                         r'(?:2fa|mfa|totp|otp|two[_-]?factor|authenticator|second[_-]?factor)|(?:2fa|mfa|totp|two[_-]?factor)[_/-]?'
                         r'(?:disable|remove|reset|off|delete|destroy)',
                         low_name + ' ' + ctx_text.lower() + ' ' + low_cls + ('_disable' if low_name in ('destroy', 'delete', 'disable')
                                                                               else '')) and \
                    re.search(r'(?i)disable|remove|delete|reset|off|deactivate|clear|unenroll|unlink|destroy', low_name or ctx_text) and \
                    not REAUTH_TOKENS.search(re.sub(r'(?i)two_?factor\w*|2fa\w*|mfa\w*|totp_?(?:secret|enabled)\w*|'
                                                    r'otp_?(?:secret|enabled)\w*', '', body)) and not GUARD_ADMIN.search(ctx_text):
                out.append(finding(src.rel, f.line, 'mfa-disable-without-reauth', '2FA can be disabled without re-authentication',
                                   '%s turns off / resets the second factor using only the current session: a stolen session '
                                   'or CSRF permanently removes MFA. Require the password and a current OTP.' % (f.name or 'This handler'),
                                   'MEDIUM', 'MEDIUM', 308))
            # ---- (d) password reset that logs the user in
            if re.search(r'(?i)reset|recover|forgot', low_name + ' ' + low_cls) and \
                    re.search(r'(?i)pass|pwd|complete|confirm|update|finish|do_?reset|reset$|perform|apply|submit|change|edit|'
                              r'show|create|store', low_name) and \
                    not re.search(r'(?i)generate|issue|send|request|mail|link|notify|token$|tokens?_?for|^create_?token', low_name):
                m = SESSION_ISSUE.search(body) or next((t for t in TOKEN_ISSUE.finditer(body)
                                                        if not SCOPED.search(body[body.rfind('\n', 0, t.start()):t.end() + 40])), None)
                if m:
                    out.append(finding(src.rel, src.line_of(f.start + m.start()), 'auth-reset-logs-in',
                                       'Password reset establishes an authenticated session (skips login / 2FA)',
                                       '%s signs the user in after the reset: whoever controls the reset channel gets a full '
                                       'session without the second factor. Redirect to the normal login instead.' % (f.name or 'Reset'),
                                       'MEDIUM', 'MEDIUM', 640))
                if re.search(r'(?i)find\w*\s*\([^)]*token|where\w*\s*\([^)]*token|get\w*\s*\([^)]*token|filter\w*\s*\([^)]*token|'
                             r'token\s*=\s*\?|reset_?token\s*[:=]', body) and not EXPIRY_TOKENS.search(body):
                    m2 = re.search(r'(?i)(?:find\w*|where\w*|get\w*|filter\w*)\s*\([^)\n]*token', body)
                    out.append(finding(src.rel, src.line_of(f.start + (m2.start() if m2 else 0)) if m2 else f.line,
                                       'auth-reset-token-no-expiry', 'Reset token accepted without expiry check',
                                       '%s looks up the reset token without checking its age / single use: leaked tokens stay '
                                       'valid forever.' % (f.name or 'Reset'), 'MEDIUM', 'MEDIUM', 640))
            # ---- (e) stored one-time code compared without expiry
            sc = stored_code_compare(body) if (verify_ctx or re.search(r'(?i)otp|code|verify|confirm|2fa|mfa|sms|login|pin',
                                                                       low_name)) else None
            if sc is not None and not EXPIRY_TOKENS.search(body) and not re.search(r'(?i)reset', low_name):
                out.append(finding(src.rel, src.line_of(f.start + sc), 'mfa-code-no-expiry',
                                   'Stored one-time code accepted without expiry check',
                                   '%s compares the stored one-time code but never checks when it was issued: old codes stay '
                                   'valid indefinitely, widening the brute-force window.' % (f.name or 'Verification'),
                                   'MEDIUM', 'MEDIUM', 308))
            # ---- (f) OTP verification without attempt limiting
            takes_input = re.search(r'(?i)\b(?:req|request|body|dto|form|params|input|code|otp|token|payload|data)\b|@RequestBody|'
                                    r'\$request|\[FromBody\]', (f.params or '') + ' ' + body[:400])
            if verify_ctx and takes_input and not file_attempts and not ATTEMPT_TOKENS.search(ctx_text) and \
                    re.search(r'(?i)user|account|session|principal|repo|db\.|model|find|current', body) and \
                    (OTP_VERIFY.search(body) or stored_code_compare(body) is not None):
                out.append(finding(src.rel, f.line, 'mfa-no-attempt-limit', 'OTP verification without attempt limiting',
                                   '%s verifies a user-supplied one-time code with no attempt counter, lockout or rate limit '
                                   'in this file: a 6-digit code can be brute-forced.' % (f.name or 'Verification'),
                                   'MEDIUM', 'LOW', 307))
            # ---- (g) auth guard that accepts pending-2FA sessions
            if proj_mfa and proj_pending and AUTH_GUARD_NAME.match(f.name or '') and f.name != f.cls and \
                    re.search(r'(?i)verify|decode|parse|session|jwt|token|user_id|userId', body) and \
                    not PENDING_MARK.search(body) and not (f.cls and PENDING_MARK.search(src.code)) and \
                    not re.search(r'(?i)whitelist|permitAll|authWhitelist', body) and \
                    re.search(r'(?i)jwt|token|session\[|req\.session|session\.get|user_id|claims', body):
                im = IDENTITY_SET.search(body) or re.search(r'(?i)jwt\.decode|decode_?token|verify_?token|\.parse\w*\s*\(|'
                                                            r'jwt\.verify|JWT::decode|ValidateToken', body)
                out.append(finding(src.rel, src.line_of(f.start + im.start()) if im else f.line, 'mfa-guard-accepts-pending',
                                   'Authentication guard accepts pending-2FA sessions',
                                   '%s authenticates any valid session / token without checking that the second factor was '
                                   'completed, while the application issues pending-MFA sessions / tokens: the OTP step can '
                                   'be skipped by calling protected routes directly.' % f.name, 'HIGH',
                                   'MEDIUM' if unread_claims else 'LOW', 308))
            # ---- (i) MFA / role decisions on variables bound from client-controlled data
            reported = set()
            for var, key, kind in client_bound_vars(f):
                for mm in re.finditer(r'(?m)^[^\n]*(?<![\w$.])%s\b[^\n]*$' % re.escape(var), body):
                    ln = mm.group(0)
                    if not DECISION_OP.search(ln) or re.search(r'(?<![\w$.])%s\s*(?::[^=\n]*)?=(?!=)' % re.escape(var), ln) or \
                            re.search(r'@(?:CookieValue|RequestHeader|RequestParam)|\[From\w+|Header\s*\(|Cookie\s*\(', ln):
                        continue
                    line = src.line_of(f.start + mm.start())
                    if line in reported:
                        break
                    reported.add(line)
                    mfa = kind == 'mfa'
                    item = finding(src.rel, line, 'mfa-client-controlled-decision' if mfa else 'authz-client-controlled-decision',
                                   'MFA decision based on client-controlled data' if mfa else
                                   'Authorization decision based on client-controlled data',
                                   'The decision uses "%s", which comes straight from the request (%s "%s"): the client '
                                   'sets it at will and %s.' % (var, 'parameter / header / cookie' if key else 'request field',
                                                                key or var, 'skips the second factor' if mfa else
                                                                'elevates its own privileges'), 'HIGH', 'MEDIUM', 807)
                    if mfa:
                        item['owasp'] = 'A07:2021 Identification and Authentication Failures'
                    out.append(item)
                    break
            # ---- (h) session fixation: login stores identity in the existing session
            if (re.search(r'(?i)log_?in|sign_?in|authenticat|create_session|session_create|do_?login|admin_login', low_name) or
                    (re.search(r'(?i)session|login', low_cls) and low_name in ('create', 'store', 'new_session'))) and \
                    re.search(r'(?i)\$_SESSION\s*\[|req\.session\.\w+\s*=|session\.setAttribute|session\s*\[\s*:\w+\s*\]\s*=|'
                              r'HttpContext\.Session\.Set', body) and not FIXATION_REGEN.search(body):
                m = re.search(r'(?i)\$_SESSION\s*\[|req\.session\.\w+\s*=|session\.setAttribute|session\s*\[\s*:\w+\s*\]\s*=|'
                              r'HttpContext\.Session\.Set', body)
                out.append(finding(src.rel, src.line_of(f.start + m.start()), 'auth-session-fixation',
                                   'Session identifier not regenerated at login',
                                   '%s stores the authenticated identity in the pre-login session without regenerating '
                                   'its id: a fixed session id survives authentication (session fixation).' % (f.name or 'Login'),
                                   'MEDIUM', 'MEDIUM', 384))


# =========================================================================== #
# Taint-lite: request data -> variables -> sinks inside one function (A03 / A01 / A10)
# =========================================================================== #
TAINT_SOURCE = {
    'java': re.compile(r'\b(?:getParameter(?:Values|Map)?|getHeader|getHeaders|getQueryString|getCookies|getInputStream|getReader|'
                       r'getRequestURI|getRequestURL|getPathInfo|getPart|getOriginalFilename)\s*\('),
    'js': re.compile(r'\breq\.(?:query|body|params|headers|cookies|url|originalUrl|path|files?|get\s*\()|\bctx\.(?:query|params|'
                     r'request\.body|request\.query|headers)|\brequest\.(?:query|body|params|payload)\b|\bevent\.(?:body|'
                     r'queryStringParameters|pathParameters)|\bsearchParams\.get\s*\(|location\.(?:search|hash)'),
    'py': re.compile(r'\brequest\.(?:args|form|values|json|data|files|GET|POST|FILES|cookies|headers|query_params|META|body|path|'
                     r'get_json\s*\(|query_string|stream)|\bself\.request\.(?:GET|POST|data|query_params)|\bflask\.request\.'),
    'php': re.compile(r'\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER\s*\[\s*["\'](?:HTTP_|REQUEST_URI|QUERY_STRING|PHP_SELF|PATH_INFO))|'
                      r'\$request\s*->\s*(?:input|get|query|post|all|file|header|cookie|route|json|getContent|string|integer)\s*\(|'
                      r'\brequest\s*\(\s*["\']|Request::(?:input|get|query|all)\s*\(|php://input|\$request\s*->\s*'
                      r'(?:query|request|headers|cookies|files)\s*->\s*get\s*\('),
    'cs': re.compile(r'\bRequest\.(?:Query|Form|Headers|Cookies|Body|Path|QueryString|RouteValues)|HttpContext\.Request\.'),
    'go': re.compile(r'\br\.(?:URL\.Query\(\)|FormValue|PostFormValue|Header\.Get|URL\.Path|URL\.RawQuery|Body|Form|PostForm|Cookie)|'
                     r'\bc\.(?:Query|Param|PostForm|DefaultQuery|DefaultPostForm|GetHeader|Cookie|QueryParam|FormValue|Params|'
                     r'BodyParser|Bind\w*|ShouldBind\w*|FormFile)\s*\(|\bmux\.Vars\s*\(|\bchi\.URLParam\s*\('),
    'rb': re.compile(r'\bparams\s*\[|\bparams\.(?:require|permit|fetch|dig)|\brequest\.(?:params|headers|body|query_string|url|'
                     r'raw_post|path|referer)|\bcookies\s*\['),
}
NUMERIC_CLEAN = re.compile(r'(?i)\b(?:parseInt|Integer\.parseInt|Integer\.valueOf|Long\.parseLong|Long\.valueOf|int|float|Number|'
                           r'intval|floatval|parseFloat|UUID\.fromString|uuid\.UUID|strconv\.Atoi|strconv\.ParseInt|'
                           r'Convert\.ToInt\d*|int\.Parse|long\.Parse|Guid\.Parse|to_i|to_f|Integer|bool|Boolean\.parseBoolean|'
                           r'isdigit|abs)\s*\(|\(int\)|\(float\)|\.to_i\b|\.to_f\b|\|\s*0\b')
ASSIGN_RX = {
    'java': re.compile(r'^\s*(?:final\s+)?(?:[\w<>\[\],.? ]+\s+)?(\w+)\s*(?:\+=|=(?!=))\s*(.+)$'),
    'cs': re.compile(r'^\s*(?:var\s+|[\w<>\[\],.? ]+\s+)?(\w+)\s*(?:\+=|\?\?=|=(?![=>]))\s*(.+)$'),
    'js': re.compile(r'^\s*(?:(?:const|let|var)\s+)?(\w+)\s*(?::\s*[\w<>\[\]| ]+)?\s*(?:\+=|=(?![=>]))\s*(.+)$'),
    'py': re.compile(r'^\s*(\w+)\s*(?::\s*[\w\[\], .|]+)?\s*(?:\+=|=(?!=))\s*(.+)$'),
    'php': re.compile(r'^\s*\$(\w+)\s*(?:\.=|=(?![=>]))\s*(.+)$'),
    'go': re.compile(r'^\s*(?:var\s+)?(\w+)(?:\s*,\s*\w+)*\s*(?::=|=(?!=)|\+=)\s*(.+)$'),
    'rb': re.compile(r'^\s*@?(\w+)\s*(?:\+=|<<|=(?![=~>]))\s*(.+)$'),
}
DESTRUCT_RX = re.compile(r'(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)$')
# family, cwe, severity, title, languages, sink regex, check only the first argument
SINKS = [
    ('sql', 89, 'HIGH', 'SQL query built from request data',
     'java', r'\.(?:executeQuery|executeUpdate|execute|executeLargeUpdate|addBatch|prepareStatement|prepareCall|createQuery|'
             r'createNativeQuery|createSQLQuery|queryForObject|queryForList|queryForMap|queryForRowSet|query|update|batchUpdate)\s*\(', True),
    ('sql', 89, 'HIGH', 'SQL query built from request data',
     'js', r'\.(?:query|execute|raw|whereRaw|orderByRaw|havingRaw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\(|\bsequelize\.query\s*\(', True),
    ('sql', 89, 'HIGH', 'SQL query built from request data',
     'py', r'\.(?:execute|executemany|executescript|raw|extra|exec_driver_sql)\s*\(|\btext\s*\(|\bRawSQL\s*\(', True),
    ('sql', 89, 'HIGH', 'SQL query built from request data',
     'php', r'(?:mysql_query|mysqli_query|pg_query|sqlite_query|->query|->exec|->prepare|->rawQuery|DB::(?:select|statement|raw|'
            r'unprepared|insert|update|delete)|->whereRaw|->selectRaw|->orderByRaw|->havingRaw)\s*\(', False),
    ('sql', 89, 'HIGH', 'SQL query built from request data',
     'cs', r'new\s+(?:Sql|OleDb|Odbc|MySql|Npgsql|Oracle|Sqlite|SQLite)Command\s*\(|\.CommandText\s*=|\.(?:FromSqlRaw|ExecuteSqlRaw|'
           r'ExecuteSqlRawAsync|SqlQuery|SqlQueryRaw|Query|QueryAsync|Execute|ExecuteAsync|QueryFirstOrDefault|QuerySingle)\s*(?:<[^>]+>)?\s*\(', True),
    ('sql', 89, 'HIGH', 'SQL query built from request data',
     'go', r'\.(?:Query|QueryRow|Exec|Raw|Where|Order|Select)\s*\(', True),
    ('sql', 89, 'HIGH', 'SQL query built from request data',
     'rb', r'\.(?:where|find_by_sql|execute|exec_query|select|order|group|having|joins|pluck|from|select_all|select_value)\s*\(?', True),
    ('nosql', 943, 'HIGH', 'NoSQL query built from request data',
     'java', r'new\s+BasicQuery\s*\(|BasicDBObject\.parse\s*\(|Document\.parse\s*\(|\.where\s*\(\s*"\$where', True),
    ('cmd', 78, 'HIGH', 'OS command built from request data',
     'java', r'Runtime\.getRuntime\(\)\.exec\s*\(|new\s+ProcessBuilder\s*\(|\.command\s*\(', False),
    ('cmd', 78, 'HIGH', 'OS command built from request data',
     'js', r'(?<![\w.$])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|child_process\.\w+\s*\(', True),
    ('cmd', 78, 'HIGH', 'OS command built from request data',
     'py', r'\bos\.(?:system|popen|exec\w*|spawn\w*)\s*\(|\bsubprocess\.\w+\s*\(|\bcommands\.\w+\s*\(', False),
    ('cmd', 78, 'HIGH', 'OS command built from request data',
     'php', r'(?<![\w>$:])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(', False),
    ('cmd', 78, 'HIGH', 'OS command built from request data',
     'cs', r'Process\.Start\s*\(|\.(?:FileName|Arguments)\s*=|new\s+ProcessStartInfo\s*\(', False),
    ('cmd', 78, 'HIGH', 'OS command built from request data',
     'go', r'exec\.Command(?:Context)?\s*\(', False),
    ('cmd', 78, 'HIGH', 'OS command built from request data',
     'rb', r'(?<![\w.])(?:system|exec|spawn|`|%x)|\bIO\.popen\s*\(|\bOpen3\.\w+\s*\(', False),
    ('path', 22, 'HIGH', 'File path built from request data',
     'java', r'new\s+(?:File|FileInputStream|FileOutputStream|FileReader|FileWriter|RandomAccessFile|FileSystemResource|UrlResource|'
             r'PrintWriter|ZipFile)\s*\(|\b(?:Paths\.get|Path\.of|Files\.\w+|ResourceUtils\.getFile)\s*\(|\.resolve\s*\(|'
             r'\.getResource(?:AsStream)?\s*\(', False),
    ('path', 22, 'HIGH', 'File path built from request data',
     'js', r'\b(?:fs\.)?(?:readFile|readFileSync|createReadStream|createWriteStream|writeFile|writeFileSync|appendFile|unlink|'
           r'unlinkSync|rmSync|readdir|readdirSync|stat|statSync|access|openSync|copyFile)\s*\(|res\.(?:sendFile|download|attachment)\s*\(', True),
    ('path', 22, 'HIGH', 'File path built from request data',
     'py', r'(?<![\w.])open\s*\(|\bsend_file\s*\(|\bFileResponse\s*\(|\bos\.(?:remove|unlink|rmdir|listdir|makedirs|rename|stat)\s*\(|'
           r'\bshutil\.\w+\s*\(|\bPath\s*\(|\.read_(?:text|bytes)\s*\(', True),
    ('path', 22, 'HIGH', 'File path built from request data',
     'php', r'(?<![\w>$:])(?:include|include_once|require|require_once)\b|(?<![\w>$:])(?:file_get_contents|fopen|readfile|file|unlink|'
            r'file_put_contents|copy|rename|opendir|scandir|mkdir|rmdir|highlight_file|show_source|parse_ini_file)\s*\(', True),
    ('path', 22, 'HIGH', 'File path built from request data',
     'cs', r'\bFile\.\w+\s*\(|new\s+FileStream\s*\(|\bPhysicalFile\s*\(|\bDirectory\.\w+\s*\(|new\s+StreamReader\s*\(', True),
    ('path', 22, 'HIGH', 'File path built from request data',
     'go', r'\bos\.(?:Open|OpenFile|ReadFile|WriteFile|Create|Remove|RemoveAll)\s*\(|\bioutil\.(?:ReadFile|WriteFile)\s*\(|'
           r'\bhttp\.ServeFile\s*\(|\bc\.(?:File|Attachment|SaveUploadedFile)\s*\(', False),
    ('path', 22, 'HIGH', 'File path built from request data',
     'rb', r'\b(?:File\.(?:open|read|write|readlines|new|delete|unlink|binread)|IO\.(?:read|readlines)|send_file)\s*\(?', True),
    ('ssrf', 918, 'HIGH', 'Server-side request to a URL from request data',
     'java', r'new\s+URL\s*\(|URI\.create\s*\(|new\s+URI\s*\(|\.(?:getForObject|getForEntity|postForObject|postForEntity|exchange|'
             r'patchForObject)\s*\(|WebClient\.create\s*\(|\.uri\s*\(|HttpRequest\.newBuilder\s*\(|new\s+Http(?:Get|Post|Put|Delete)\s*\(|'
             r'Jsoup\.connect\s*\(|\.url\s*\(', True),
    ('ssrf', 918, 'HIGH', 'Server-side request to a URL from request data',
     'js', r'\b(?:axios(?:\.\w+)?|fetch|got(?:\.\w+)?|needle|superagent\.\w+|request(?:\.(?:get|post))?|https?\.(?:get|request))\s*\(', True),
    ('ssrf', 918, 'HIGH', 'Server-side request to a URL from request data',
     'py', r'\b(?:requests|httpx|session|client|s)\.(?:get|post|put|delete|head|patch|request|stream)\s*\(|\burlopen\s*\(|'
           r'\burllib\.request\.Request\s*\(|\burllib3\.\w+\(|\baiohttp\.\w+|\bpycurl', True),
    ('ssrf', 918, 'HIGH', 'Server-side request to a URL from request data',
     'php', r'\bcurl_init\s*\(|CURLOPT_URL\s*,|\bfile_get_contents\s*\(|\bfsockopen\s*\(|\bget_headers\s*\(|Http::(?:get|post|send)\s*\(|'
            r'->request\s*\(\s*["\']\w+["\']\s*,', False),
    ('ssrf', 918, 'HIGH', 'Server-side request to a URL from request data',
     'cs', r'\.(?:GetAsync|PostAsync|GetStringAsync|GetStreamAsync|GetByteArrayAsync|SendAsync|DownloadString|DownloadData|OpenRead)'
           r'\s*\(|new\s+Uri\s*\(|WebRequest\.Create\s*\(', True),
    ('ssrf', 918, 'HIGH', 'Server-side request to a URL from request data',
     'go', r'\bhttp\.(?:Get|Post|Head|NewRequest(?:WithContext)?)\s*\(|\bclient\.(?:Get|Post|Head)\s*\(', False),
    ('ssrf', 918, 'HIGH', 'Server-side request to a URL from request data',
     'rb', r'\b(?:Net::HTTP\.(?:get|get_response|post_form|start|new)|URI\.open|URI\.parse|HTTParty\.(?:get|post)|Faraday\.(?:get|post|new)|'
           r'RestClient\.(?:get|post)|open)\s*\(?', True),
    ('redirect', 601, 'MEDIUM', 'Redirect to a location from request data',
     'java', r'\bsendRedirect\s*\(|"redirect:"\s*\+|new\s+RedirectView\s*\(|\.location\s*\(|setHeader\s*\(\s*"Location"\s*,', False),
    ('redirect', 601, 'MEDIUM', 'Redirect to a location from request data', 'js', r'\bres\.redirect\s*\(|\.redirect\s*\(', False),
    ('redirect', 601, 'MEDIUM', 'Redirect to a location from request data',
     'py', r'\bredirect\s*\(|\bHttpResponseRedirect\s*\(|\bRedirectResponse\s*\(', True),
    ('redirect', 601, 'MEDIUM', 'Redirect to a location from request data',
     'php', r'header\s*\(\s*["\']Location:|\bredirect\s*\(|->away\s*\(|->to\s*\(', False),
    ('redirect', 601, 'MEDIUM', 'Redirect to a location from request data', 'cs', r'(?<![\w.])Redirect\s*\(|RedirectPermanent\s*\(|'
                                                                             r'Response\.Redirect\s*\(', True),
    ('redirect', 601, 'MEDIUM', 'Redirect to a location from request data', 'go', r'\bhttp\.Redirect\s*\(|\bc\.Redirect\s*\(', False),
    ('redirect', 601, 'MEDIUM', 'Redirect to a location from request data', 'rb', r'\bredirect_to\s*\(?', True),
    ('code', 94, 'HIGH', 'Code evaluated from request data', 'js', r'(?<![\w.$])eval\s*\(|new\s+Function\s*\(|\bvm\.run\w*\s*\(', True),
    ('code', 94, 'HIGH', 'Code evaluated from request data', 'py', r'(?<![\w.])(?:eval|exec)\s*\(', True),
    ('code', 94, 'HIGH', 'Code evaluated from request data', 'php', r'(?<![\w>$:])(?:eval|assert|create_function)\s*\(', True),
    ('code', 94, 'HIGH', 'Code evaluated from request data', 'rb', r'(?<![\w.])(?:eval|instance_eval|class_eval)\s*\(?|'
                                                                  r'\.(?:send|public_send|constantize)\b', True),
    ('code', 917, 'HIGH', 'Expression language evaluated from request data', 'java', r'\.parseExpression\s*\(|Ognl\.\w+\s*\(|'
                                                                                    r'MVEL\.(?:eval|compileExpression)\s*\(|ScriptEngine\w*\.eval\s*\(|\.eval\s*\(', True),
    ('template', 1336, 'HIGH', 'Template compiled from request data', 'py', r'\brender_template_string\s*\(|\bTemplate\s*\(|'
                                                                            r'\.from_string\s*\(', True),
    ('template', 1336, 'HIGH', 'Template compiled from request data', 'js', r'\b(?:ejs|pug|jade|handlebars|Handlebars|nunjucks|_|lodash)'
                                                                            r'\.(?:render|compile|template|renderString)\s*\(', True),
    ('template', 1336, 'HIGH', 'Template compiled from request data', 'java', r'Velocity\.evaluate\s*\(|velocityEngine\.evaluate\s*\(|'
                                                                              r'new\s+Template\s*\(', False),
    ('deser', 502, 'HIGH', 'Untrusted data deserialized', 'py', r'\bpickle\.loads?\s*\(|\byaml\.(?:load|unsafe_load)\s*\(|\bmarshal\.loads\s*\(|'
                                                                r'\bjsonpickle\.decode\s*\(|\bdill\.loads?\s*\(', True),
    ('deser', 502, 'HIGH', 'Untrusted data deserialized', 'java', r'new\s+ObjectInputStream\s*\(|\.fromXML\s*\(|new\s+XMLDecoder\s*\(', True),
    ('deser', 502, 'HIGH', 'Untrusted data deserialized', 'php', r'(?<![\w>$:])unserialize\s*\(', True),
    ('deser', 502, 'HIGH', 'Untrusted data deserialized', 'js', r'\bunserialize\s*\(|\bdeserialize\s*\(', True),
    ('deser', 502, 'HIGH', 'Untrusted data deserialized', 'rb', r'\bMarshal\.load\s*\(|\bYAML\.(?:load|unsafe_load)\s*\(', True),
    ('deser', 502, 'HIGH', 'Untrusted data deserialized', 'cs', r'\.Deserialize\s*\(', True),
    ('xss', 79, 'MEDIUM', 'Request data written into the response', 'js', r'\bres\.(?:send|write|end)\s*\(|\.innerHTML\s*=|'
                                                                         r'document\.write\s*\(', True),
    ('xss', 79, 'MEDIUM', 'Request data written into the response', 'py', r'\bHttpResponse\s*\(|\bmake_response\s*\(|\bMarkup\s*\(|'
                                                                         r'\bmark_safe\s*\(|^\s*return\s+(?:f["\']|["\'][^"\']*["\']\s*(?:%|\+))', True),
    ('xss', 79, 'MEDIUM', 'Request data written into the response', 'php', r'(?<![\w>$])(?:echo|print)\b|<\?=', False),
    ('xss', 79, 'MEDIUM', 'Request data written into the response', 'java', r'getWriter\s*\(\s*\)\s*\.(?:write|print|println|append|printf)\s*\(', True),
    ('xss', 79, 'MEDIUM', 'Request data written into the response', 'cs', r'\bHtml\.Raw\s*\(|\bResponse\.Write\s*\(|\bnew\s+HtmlString\s*\(', True),
    ('xss', 79, 'MEDIUM', 'Request data written into the response', 'go', r'\bfmt\.Fprintf?\s*\(\s*w\s*,|\bw\.Write\s*\(|'
                                                                         r'\bio\.WriteString\s*\(\s*w\s*,|\btemplate\.HTML\s*\(', False),
    ('header', 113, 'MEDIUM', 'Response header set from request data', 'java js py php cs go',
     r'\.(?:setHeader|addHeader|set_header|AppendHeader|AddHeader)\s*\(|\bres\.(?:set|header)\s*\(|\bheader\s*\(\s*["\'](?!Location)', False),
    ('ldap', 90, 'HIGH', 'LDAP query built from request data', 'java cs php py',
     r'\.search\s*\(|ldap_search\s*\(|DirectorySearcher\s*\(|\.Filter\s*=|search_s\s*\(', False),
    ('xpath', 643, 'MEDIUM', 'XPath query built from request data', 'java cs php py js',
     r'\.(?:evaluate|compile|selectNodes|selectSingleNode|SelectNodes|SelectSingleNode|xpath)\s*\(', True),
    ('regex', 1333, 'MEDIUM', 'Regular expression built from request data', 'java js py php cs go',
     r'Pattern\.compile\s*\(|new\s+RegExp\s*\(|\bre\.(?:compile|match|search|fullmatch|sub|findall|split)\s*\(|'
     r'preg_(?:match|replace|split|match_all)\s*\(|new\s+Regex\s*\(|regexp\.(?:MustCompile|Compile)\s*\(', True),
    ('log', 117, 'LOW', 'Request data written to logs (log injection)', 'java js py php cs go rb',
     r'\b(?:log|logger|LOG|LOGGER|logging|console|_logger|Log)\s*\.\s*(?:info|warn|warning|error|debug|trace|fatal|critical|log|'
     r'Information|Warning|Error|Debug)\s*\(', False),
]
SINK_RX = [(fam, cwe, sev, title, set(langs.split()), re.compile(rx), first) for fam, cwe, sev, title, langs, rx, first in SINKS]
SANITIZERS = {
    'path': re.compile(r'(?i)startsWith\s*\(|startswith\s*\(|HasPrefix\s*\(|StartsWith\s*\(|commonpath|is_relative_to|relative_to\s*\(|'
                       r'safe_join|secure_filename|basename\s*\(|getName\s*\(\s*\)|FilenameUtils\.getName|Path\.GetFileName|'
                       r'path\.basename|filepath\.Base|realpath[^\n]*(?:startswith|===|==|strpos)|\broot\s*:|ALLOWED_\w*FILES|'
                       r'in_array\s*\(|\.includes\s*\(|allowlist|whitelist'),
    'redirect': re.compile(r'(?i)url_has_allowed_host_and_scheme|is_safe_url|isLocalUrl|IsLocalUrl|LocalRedirect|startsWith\s*\(\s*["\']/|'
                           r'startswith\s*\(\s*["\']/|allowed_?(?:hosts|domains|redirects|urls)|whitelist|allowlist|ALLOWED|'
                           r'SAFE_\w*|\bin\s+\w*(?:allowed|safe)\w*|indexOf\s*\(\s*["\']/|isSafe\w*|validateRedirect\w*|url_for\s*\('),
    'ssrf': re.compile(r'(?i)allow|whitelist|ALLOWED|validate_?url|is_?safe|isAllowed|is_private|is_loopback|InetAddress|getByName|'
                       r'\.hostname\s*(?:not\s+)?in|hostname\s*(?:not\s+)?in|\.host\s*(?:==|!=|in\b|\.equals)|\.Host\s*(?:==|!=)|'
                       r'trusted_?hosts?|ssrf'),
    'xss': re.compile(r'(?i)escape|encode|htmlspecialchars|htmlentities|sanitize|bleach|DOMPurify|textContent|\be\s*\(|esc_html|'
                      r'strip_tags|markupsafe|forHtml|HtmlEncoder|jsonify|json_encode|JSON\.stringify|res\.json|json\.dumps|'
                      r'JsonResponse|Content-Type["\']?\s*[:,]\s*["\']?(?:application/json|text/plain)'),
    'cmd': re.compile(r'(?i)shlex\.quote|escapeshellarg|escapeshellcmd|allowlist|whitelist|ALLOWED_'),
    'sql': re.compile(r'(?!x)x'),
    'header': re.compile(r'(?i)replace\s*\([^)]*\\r|replace\s*\([^)]*\\n|encodeURI|urlencode|quote\s*\(|isValidHeader'),
    'log': re.compile(r'(?i)replace\s*\([^)]*\\[rn]|sanitize|encodeForLog|escape|repr\s*\(|%r|json\.dumps|JSON\.stringify|%q'),
    'ldap': re.compile(r'(?i)\{0\}|new\s+Object\s*\[\s*\]|escape|encodeForLDAP|LdapEncoder|ldap_escape|filter_format|'
                       r'escape_filter_chars|LdapQueryBuilder|LdapNameBuilder|Rdn\.escapeValue'),
    'code': re.compile(r'(?i)SimpleEvaluationContext|setVariable\s*\(|ast\.literal_eval'),
}
DB_RECV = re.compile(r'(?i)jdbc|template|stmt|statement|^ps$|pst|prepared|conn|connection|^em$|entity_?manager|session|^db$|'
                     r'database|cursor|^cur$|knex|sequelize|pool|mysql|^pg$|sql|query|dbcontext|_context|context|tx|'
                     r'transaction|dataSource|client|\$?wpdb|gorm|^d$')
PRICE_NAME = re.compile(r'(?i)^(?:unit_?)?(?:price|total|subtotal|sub_?total|grand_?total|amount|discount\w*|cost|fee|charge|'
                        r'amount_?due|order_?total|final_?price)$')
QTY_NAME = re.compile(r'(?i)^(?:qty|quantity|amount|count|units|points|credits|nb|number_?of\w*)$')
LOWER_BOUND = r'(?:%s\s*(?:<=?|<)\s*(?:0|1)\b|%s\s*>=?\s*(?:0|1)\b|(?:0|1)\s*(?:>=?|<=?)\s*%s|Math\.max\s*\(|max\s*\(\s*0|' \
              r'@(?:Min|Positive|PositiveOrZero|DecimalMin)|\bgt\s*=\s*0|\bge\s*=\s*1|PositiveInt|conint|unsigned|uint|' \
              r'%s\s*<=\s*0|%s\s*<\s*0|isNegative|signum|compareTo\s*\(\s*BigDecimal\.ZERO)'


def _param_sources(f, src):
    """Function parameters that carry request data (framework-bound handler params)."""
    p = f.params or ''
    names = set()
    if src.lang == 'java':
        for m in re.finditer(r'@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|MatrixVariable|'
                             r'RequestPart|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|BeanParam)\b(?:\s*\([^)]*\))?\s*'
                             r'(?:final\s+)?[\w<>?,.\[\] ]+?\s+(\w+)\s*(?:,|$)', p):
            names.add(m.group(1))
        if re.search(r'@(?:Get|Post|Put|Delete|Patch|Request)Mapping|@(?:GET|POST|PUT|DELETE|PATCH)\b', f.decor or ''):
            for m in re.finditer(r'(?:^|,)\s*(?:final\s+)?(?:String|MultipartFile|Map<[^>]*>|[A-Z]\w*(?:Dto|DTO|Request|Form|Command|Payload))\s+(\w+)', p):
                names.add(m.group(1))
    elif src.lang == 'js':
        for m in re.finditer(r'@(?:Query|Param|Body|Headers|Req)\s*\([^)]*\)\s*(\w+)', p):
            names.add(m.group(1))
    elif src.lang == 'py':
        if re.search(r'\.(?:get|post|put|patch|delete|api_route|route)\s*\(', f.decor or '') and 'fastapi' in src.text:
            for part in split_top(p):
                part = part.strip()
                nm = re.match(r'(\w+)', part)
                if not nm or nm.group(1) in ('self', 'request', 'db', 'session', 'response', 'background_tasks'):
                    continue
                if re.search(r'Depends\s*\(|Security\s*\(|Session\b|Request\b|Response\b|BackgroundTasks', part):
                    continue
                names.add(nm.group(1))
        elif re.match(r'\s*request\b', p) and 'django' in src.text:
            for part in split_top(p)[1:]:
                nm = re.match(r'\s*\*{0,2}(\w+)', part)
                if nm and nm.group(1) not in ('args', 'kwargs'):
                    names.add(nm.group(1))
        elif re.search(r'\.route\s*\(|\.(?:get|post|put|delete)\s*\(', f.decor or ''):
            for part in split_top(p):
                nm = re.match(r'\s*(\w+)', part)
                if nm and nm.group(1) not in ('self',):
                    names.add(nm.group(1))
    elif src.lang == 'cs':
        if re.search(r'\[Http(?:Get|Post|Put|Delete|Patch)|\[Route|Controller', (f.decor or '') + ' ' + (f.cls or '')):
            for m in re.finditer(r'(?:\[From(?:Query|Route|Body|Form|Header)[^\]]*\]\s*)?(?:string|IFormFile|[A-Z]\w*(?:Dto|Request|Model|Form))\s+(\w+)', p):
                names.add(m.group(1))
    elif src.lang == 'php':
        if re.search(r'Request\s+\$request', p):
            names.add('request')
    return names


def _first_arg(line_code, line_masked, start):
    """Text of the first argument of the call whose '(' is at or before `start`."""
    i = line_masked.find('(', max(0, start - 1))
    if i < 0:
        return line_code[start:]
    depth, j = 0, i
    for j in range(i, len(line_masked)):
        ch = line_masked[j]
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
            if depth == 0:
                return line_code[i + 1:j]
        elif ch == ',' and depth == 1:
            return line_code[i + 1:j]
    return line_code[i + 1:]


def analyze_taint(srcs, out):
    for src in srcs:
        source_rx = TAINT_SOURCE.get(src.lang)
        assign_rx = ASSIGN_RX.get(src.lang)
        if not source_rx or not assign_rx:
            continue
        sinks = [s for s in SINK_RX if src.lang in s[4]]
        mlines = src.masked.split('\n')
        for f in functions(src):
            if f.end - f.start > 60000:
                continue
            tainted = {n: ('parameter', f.line) for n in _param_sources(f, src)}
            reported = set()
            body_text = f.body()
            for ln, code in f.body_lines():
                if not code.strip():
                    continue
                masked = mlines[ln - 1] if ln - 1 < len(mlines) else code

                def has_taint(text):
                    if source_rx.search(text):
                        return 'request data', ln
                    for name, origin in tainted.items():
                        if re.search(r'(?<![\w$.])\$?%s\b' % re.escape(name), text):
                            return name, origin[1]
                    return None
                # propagation
                for bm in re.finditer(r'(?:ShouldBind\w*|\bBind\w*|BodyParser|\.Decode|\.Unmarshal\s*\([^,]+,)\s*\(?\s*&(\w+)', code):
                    tainted[bm.group(1)] = ('request data', ln)
                dm = DESTRUCT_RX.search(code) if src.lang == 'js' else None
                if dm and (source_rx.search(dm.group(2)) or has_taint(dm.group(2))):
                    for part in dm.group(1).split(','):
                        nm = part.split(':')[-1].split('=')[0].strip()
                        if re.match(r'^\w+$', nm):
                            tainted[nm] = ('request data', ln)
                am = assign_rx.match(code)
                sink_on_line = any(rx.search(code) for _, _, _, _, _, rx, _ in sinks)
                # business logic: price / total / discount adopted from the client (numeric casts do not help here)
                pm = re.search(r'(?i)(?:\b(\w+)\s*(?::\s*[\w<>\[\]]+\s*)?=(?!=)\s*|["\']?(\w+)["\']?\s*:\s*(?!:)|\bset((?:Unit)?Price|Total|'
                               r'Amount|Discount\w*|Cost|Fee)\s*\(\s*|\.((?:Unit)?Price|Total|Amount|Discount)\s*=(?!=)\s*)([^;\n]*)', code)
                if pm and 'price' not in reported:
                    tgt = pm.group(1) or pm.group(2) or pm.group(3) or pm.group(4) or ''
                    rhs = pm.group(5)
                    if PRICE_NAME.match(tgt) and (source_rx.search(rhs) or re.search(
                            r'(?i)\b(?:\w+\.)?(?:get)?(?:unit_?)?(?:price|total|discount\w*|amount|cost|fee)\b', rhs) and
                            any(re.search(r'(?<![\w$.])%s\b' % re.escape(n), rhs) for n in tainted)) and \
                            not re.search(r'(?i)\b(?:product|item|catalog|db|repo|server|computed|calculate|sum|reduce|price_?list|'
                                          r'lookup|fetch|find|get_?price|priceOf|stored)\w*', rhs):
                        reported.add('price')
                        out.append(finding(src.rel, ln, 'taint-client-price', 'Price / total / discount taken from the client',
                                           'The value used as "%s" comes from the request: the client chooses what it pays. '
                                           'Compute prices and totals server-side from the catalogue.' % tgt, 'MEDIUM', 'MEDIUM', 602))
                if am and not sink_on_line:
                    lhs, rhs = am.group(1), am.group(2)
                    t = has_taint(rhs)
                    if t and not NUMERIC_CLEAN.search(rhs):
                        tainted[lhs] = (t[0], ln)
                    elif lhs in tainted and not t and '+=' not in code and '.=' not in code:
                        tainted.pop(lhs, None)
                for m in re.finditer(r'\b(\w+)\s*\.\s*(?:append|concat|push|extend|add|insert|Append|AppendFormat|write)\s*\(', code):
                    if has_taint(code[m.end():]) and m.group(1) not in tainted:
                        tainted[m.group(1)] = ('request data', ln)
                if am and sink_on_line:
                    t = has_taint(am.group(2))
                    if t and not NUMERIC_CLEAN.search(am.group(2)):
                        tainted[am.group(1)] = (t[0], ln)
                # sinks
                for fam, cwe, sev, title, langs, rx, first in sinks:
                    if fam in reported:
                        continue
                    sm = rx.search(code)
                    if not sm:
                        continue
                    arg = _first_arg(code, masked, sm.end()) if first else code[sm.start():]
                    t = has_taint(arg)
                    if not t:
                        continue
                    if fam == 'sql' and src.lang in ('java', 'cs', 'js', 'go', 'rb'):
                        rcv = re.search(r'([\w$]+)\s*$', code[:sm.start()])
                        if rcv and not DB_RECV.search(rcv.group(1)) and not re.search(r'(?i)\b(?:select|insert|update|delete|where)\b',
                                                                                       arg):
                            continue                      # service.update(dto) is not a SQL API
                    if fam == 'sql' and src.lang in ('java', 'js', 'py', 'cs', 'go', 'rb') and t[0] != 'request data' and \
                            re.fullmatch(r'\s*\w+\s*', arg) is None and not re.search(r'[+%]|\$\{|\{\w|format|f["\']|concat|#\{', arg):
                        continue
                    if fam == 'sql' and src.lang == 'php' and not re.search(r'\.\s*\$|"[^"]*\$\w|\{\$|\$_', arg) and \
                            re.search(r'\?|:\w+', arg):
                        continue
                    if fam == 'cmd' and src.lang == 'py' and re.search(r'subprocess\.\w+\s*\(\s*\[', code) and 'shell=True' not in code:
                        continue
                    if fam == 'cmd' and src.lang == 'js' and re.search(r'(?:execFile|spawn)\w*\s*\(\s*["\']', code) and 'shell' not in code:
                        continue
                    if fam == 'cmd' and src.lang in ('java', 'go', 'cs') and \
                            re.search(r'(?:ProcessBuilder|exec\.Command(?:Context)?|exec)\s*\(\s*(?:\w+\s*,\s*)?(?:new\s+String\s*\[\s*\]\s*\{\s*|'
                                      r'List\.of\s*\(\s*|Arrays\.asList\s*\(\s*)?"(?!(?:/bin/)?(?:sh|bash|zsh|cmd|cmd\.exe|powershell|pwsh)"'
                                      r')[^"]+"\s*,', code):
                        continue                          # argv form with a fixed program: no shell interpretation
                    if fam == 'log' and re.search(r'\.\w+\s*\(\s*\{', code):
                        continue                          # structured logging (fields are escaped by the logger)
                    san = SANITIZERS.get(fam)
                    if san and (san.search(code) or san.search(body_text)):
                        continue
                    if fam == 'xss' and src.lang == 'js' and re.search(r'res\.send\s*\(\s*\{|res\.send\s*\(\s*\w+\s*\)', code) and \
                            t[0] == 'request data':
                        pass
                    reported.add(fam)
                    via = ('directly' if t[0] == 'request data' and t[1] == ln else
                           'via "%s" (%s, line %d)' % (t[0], 'handler parameter' if t[0] in tainted and tainted.get(t[0], ('',))[0] ==
                                                       'parameter' else 'assigned from request data', t[1]))
                    out.append(finding(src.rel, ln, 'taint-%s' % fam, title,
                                       'Request-controlled data reaches %s %s without validation / encoding.' % (
                                           sm.group(0).strip(' (')[:40], via), sev, 'MEDIUM', cwe))
            # quantities / amounts from the client used without a lower bound (negative values)
            cands = list(tainted)
            for v in list(tainted):
                for am2 in re.finditer(r'(?<![\w$.])%s\s*\.\s*((?:get)?(\w+))(\s*\(\s*\))?' % re.escape(v), body_text):
                    leaf2 = re.sub(r'^get', '', am2.group(2)) if am2.group(3) else am2.group(2)
                    if QTY_NAME.match(leaf2):
                        cands.append(v + '.' + am2.group(1) + ('()' if am2.group(3) else ''))
            for name in cands:
                leaf = re.sub(r'^get|\(\)$', '', name.split('.')[-1])
                if not QTY_NAME.match(leaf):
                    continue
                n = re.escape(name)
                uses = [m for m in re.finditer(r'(?m)^[^\n]*(?<![\w$.])%s\b[^\n]*$' % n, body_text)]
                arith = [m for m in uses if re.search(r'(?<![\w$.])%s\b\s*[*\-+/]|[*\-+/]=?\s*%s\b|balance|stock|inventory|'
                                                      r'total|credit|debit|withdraw|transfer' % (n, n), m.group(0))]
                if not arith or re.search(LOWER_BOUND % ((n,) * 5), body_text):
                    continue
                out.append(finding(src.rel, src.line_of(f.start + arith[0].start()), 'taint-unbounded-quantity',
                                   'Client-supplied quantity / amount used without a lower bound',
                                   '"%s" comes from the request and is used in a calculation without rejecting zero / '
                                   'negative values: negative quantities or amounts invert the operation (credits, '
                                   'stealing balance).' % name, 'MEDIUM', 'MEDIUM', 840))
                break


# =========================================================================== #
# Offline dependency checks (OWASP A06:2021 / A03:2025)
# =========================================================================== #
def vtuple(v):
    nums = re.findall(r'\d+', (v or '').split('-')[0].split('+')[0])
    return tuple(int(x) for x in nums[:4]) if nums else None


def _lt(v, ref):
    a, b = vtuple(v), vtuple(ref)
    if a is None or b is None:
        return False
    n = max(len(a), len(b))
    return a + (0,) * (n - len(a)) < b + (0,) * (n - len(b))


def _between(v, lo, hi_excl):
    return not _lt(v, lo) and _lt(v, hi_excl)


def _log4j(v):
    if _lt(v, '2.0') or not _lt(v, '2.17.1'):
        return None
    if _between(v, '2.12.4', '2.13') or _between(v, '2.3.2', '2.4'):
        return None
    if _lt(v, '2.15.0') and not _between(v, '2.12.2', '2.13') and not _between(v, '2.3.1', '2.4'):
        return 'CRITICAL', 'Log4Shell remote code execution (CVE-2021-44228); upgrade to >= 2.17.1'
    return 'HIGH', 'Log4j 2 JNDI / DoS issues (CVE-2021-45046, CVE-2021-45105, CVE-2021-44832); upgrade to >= 2.17.1'


# (ecosystem, package (lower-case, exact), check(version) -> (severity, message) | None)
KNOWN_VULNS = [
    ('maven', 'org.apache.logging.log4j:log4j-core', _log4j),
    ('maven', 'log4j:log4j', lambda v: ('HIGH', 'Log4j 1.x is end-of-life with known RCE / deserialization flaws '
                                               '(CVE-2019-17571, CVE-2022-23305, CVE-2022-23307); migrate to Log4j 2 / Logback')),
    ('maven', 'org.springframework:spring-beans|org.springframework:spring-webmvc|org.springframework:spring-webflux|'
              'org.springframework:spring-core',
     lambda v: ('CRITICAL', 'Spring4Shell remote code execution (CVE-2022-22965); upgrade to 5.3.18+ / 5.2.20+')
     if _between(v, '5.3.0', '5.3.18') or _between(v, '5.2.0', '5.2.20') else None),
    ('maven', 'org.springframework.cloud:spring-cloud-function-context',
     lambda v: ('CRITICAL', 'SpEL injection RCE in routing (CVE-2022-22963); upgrade to 3.1.7+ / 3.2.3+')
     if _between(v, '3.1.0', '3.1.7') or _between(v, '3.2.0', '3.2.3') else None),
    ('maven', 'org.apache.commons:commons-text',
     lambda v: ('CRITICAL', 'Text4Shell interpolation RCE (CVE-2022-42889); upgrade to >= 1.10.0')
     if _between(v, '1.5', '1.10.0') else None),
    ('maven', 'commons-collections:commons-collections',
     lambda v: ('HIGH', 'InvokerTransformer deserialization gadget (CVE-2015-7501); upgrade to >= 3.2.2')
     if _lt(v, '3.2.2') else None),
    ('maven', 'com.alibaba:fastjson', lambda v: ('CRITICAL', 'autoType deserialization RCE (CVE-2022-25845); upgrade to >= 1.2.83 '
                                                             'or fastjson2') if _lt(v, '1.2.83') else None),
    ('maven', 'org.apache.struts:struts2-core',
     lambda v: ('CRITICAL', 'file upload path traversal to RCE (CVE-2023-50164) and many older RCEs; upgrade to 2.5.33+ / 6.3.0.2+')
     if _lt(v, '2.5.33') or _between(v, '6.0.0', '6.3.0.2') else None),
    ('maven', 'org.yaml:snakeyaml', lambda v: ('HIGH', 'unsafe default constructor RCE (CVE-2022-1471); upgrade to >= 2.0')
     if _lt(v, '2.0') else None),
    ('maven', 'com.thoughtworks.xstream:xstream', lambda v: ('HIGH', 'multiple deserialization RCEs (CVE-2021-39139 and others); '
                                                                     'upgrade to >= 1.4.20') if _lt(v, '1.4.20') else None),
    ('maven', 'com.fasterxml.jackson.core:jackson-databind',
     lambda v: ('HIGH', 'polymorphic deserialization gadget CVEs (e.g. CVE-2019-12384, CVE-2020-36518); upgrade to >= 2.12.7.1')
     if _lt(v, '2.10.0') else (('MEDIUM', 'deeply nested JSON DoS (CVE-2020-36518, CVE-2022-42003); upgrade to >= 2.13.4.2')
                               if _lt(v, '2.12.7.1') else None)),
    ('maven', 'com.h2database:h2', lambda v: ('CRITICAL', 'H2 console JNDI remote code execution (CVE-2021-42392, CVE-2022-23221); '
                                                          'upgrade to >= 2.1.210') if _lt(v, '2.1.210') else None),
    ('maven', 'ch.qos.logback:logback-classic|ch.qos.logback:logback-core',
     lambda v: ('MEDIUM', 'JNDI lookup via configuration (CVE-2021-42550); upgrade to >= 1.2.9') if _lt(v, '1.2.9') else None),
    ('npm', 'lodash', lambda v: ('HIGH', 'prototype pollution / command injection (CVE-2019-10744, CVE-2020-8203, CVE-2021-23337); '
                                         'upgrade to >= 4.17.21') if _lt(v, '4.17.21') else None),
    ('npm', 'minimist', lambda v: ('MEDIUM', 'prototype pollution (CVE-2021-44906); upgrade to >= 1.2.6') if _lt(v, '1.2.6') else None),
    ('npm', 'jquery', lambda v: ('MEDIUM', 'XSS in htmlPrefilter (CVE-2020-11022, CVE-2020-11023); upgrade to >= 3.5.0')
     if _lt(v, '3.5.0') else None),
    ('npm', 'handlebars', lambda v: ('HIGH', 'template compilation RCE / prototype pollution (CVE-2021-23369, CVE-2021-23383); '
                                             'upgrade to >= 4.7.7') if _lt(v, '4.7.7') else None),
    ('npm', 'axios', lambda v: ('HIGH', 'SSRF via redirects (CVE-2020-28168); upgrade') if _lt(v, '0.21.1') else
     (('MEDIUM', 'XSRF-TOKEN leak (CVE-2023-45857); upgrade to >= 1.6.0') if _between(v, '0.8.1', '1.6.0') else None)),
    ('npm', 'jsonwebtoken', lambda v: ('MEDIUM', 'insecure key / algorithm handling (CVE-2022-23539, CVE-2022-23540, '
                                                 'CVE-2022-23541); upgrade to >= 9.0.0') if _lt(v, '9.0.0') else None),
    ('npm', 'ejs', lambda v: ('CRITICAL', 'server-side template injection RCE (CVE-2022-29078); upgrade to >= 3.1.7')
     if _lt(v, '3.1.7') else None),
    ('npm', 'node-serialize', lambda v: ('CRITICAL', 'arbitrary code execution through IIFE deserialization (CVE-2017-5941); '
                                                     'remove the package')),
    ('npm', 'vm2', lambda v: ('CRITICAL', 'sandbox escapes (CVE-2023-37466, CVE-2023-37903); project discontinued, remove it')),
    ('npm', 'express', lambda v: ('MEDIUM', 'qs prototype pollution DoS (CVE-2022-24999) and open redirect (CVE-2024-29041); '
                                            'upgrade to >= 4.19.2') if _lt(v, '4.19.2') else None),
    ('npm', 'moment', lambda v: ('MEDIUM', 'ReDoS / path traversal (CVE-2022-31129, CVE-2022-24785); upgrade to >= 2.29.4')
     if _lt(v, '2.29.4') else None),
    ('npm', 'serialize-javascript', lambda v: ('HIGH', 'code injection (CVE-2020-7660); upgrade to >= 3.1.0')
     if _lt(v, '3.1.0') else None),
    ('npm', 'shell-quote', lambda v: ('CRITICAL', 'command injection (CVE-2021-42740); upgrade to >= 1.7.3')
     if _lt(v, '1.7.3') else None),
    ('npm', 'underscore', lambda v: ('HIGH', 'arbitrary code execution in template (CVE-2021-23358); upgrade to >= 1.12.1')
     if _between(v, '1.3.2', '1.12.1') else None),
    ('npm', 'marked', lambda v: ('MEDIUM', 'ReDoS (CVE-2022-21680, CVE-2022-21681); upgrade to >= 4.0.10')
     if _lt(v, '4.0.10') else None),
    ('pypi', 'pyyaml', lambda v: ('CRITICAL', 'full_load / FullLoader arbitrary code execution (CVE-2020-1747, CVE-2020-14343); '
                                              'upgrade to >= 5.4') if _lt(v, '5.4') else None),
    ('pypi', 'django', lambda v: ('HIGH', 'end-of-life release line with known SQL injection / DoS CVEs; upgrade to a supported '
                                          'LTS (4.2+)') if _lt(v, '3.2') else None),
    ('pypi', 'jinja2', lambda v: ('MEDIUM', 'ReDoS (CVE-2020-28493) / sandbox escape (CVE-2019-10906); upgrade to >= 2.11.3')
     if _lt(v, '2.11.3') else None),
    ('pypi', 'requests', lambda v: ('MEDIUM', 'Proxy-Authorization header leak (CVE-2023-32681); upgrade to >= 2.31.0')
     if _lt(v, '2.31.0') else None),
    ('pypi', 'urllib3', lambda v: ('MEDIUM', 'ReDoS / header leak on redirect (CVE-2021-33503, CVE-2023-43804); upgrade to >= 1.26.18')
     if _lt(v, '1.26.18') else None),
    ('pypi', 'flask', lambda v: ('MEDIUM', 'session cookie disclosure behind caching proxies (CVE-2023-30861); upgrade to >= 2.2.5')
     if _lt(v, '2.2.5') else None),
    ('pypi', 'werkzeug', lambda v: ('MEDIUM', 'debugger RCE when the host is attacker-controlled (CVE-2024-34069) and DoS CVEs; '
                                              'upgrade to >= 3.0.3') if _lt(v, '3.0.3') else None),
    ('pypi', 'pillow', lambda v: ('HIGH', 'ImageMath.eval arbitrary code execution (CVE-2022-22817) and parser CVEs; upgrade to >= 9.0.1')
     if _lt(v, '9.0.1') else None),
    ('rubygems', 'nokogiri', lambda v: ('HIGH', 'vulnerable bundled libxml2 / libxslt and command injection (CVE-2019-5477, '
                                                'CVE-2022-29181); upgrade to >= 1.13.6') if _lt(v, '1.13.6') else None),
    ('rubygems', 'rails', lambda v: ('HIGH', 'end-of-life Rails line with known CVEs; upgrade to a supported release')
     if _lt(v, '6.1') else None),
    ('go', 'github.com/dgrijalva/jwt-go', lambda v: ('HIGH', 'unmaintained; audience check bypass (CVE-2020-26160); '
                                                              'migrate to github.com/golang-jwt/jwt/v5')),
    ('nuget', 'newtonsoft.json', lambda v: ('MEDIUM', 'deeply nested JSON DoS (CVE-2024-21907); upgrade to >= 13.0.1')
     if _lt(v, '13.0.1') else None),
]
VULN_INDEX = defaultdict(list)
for _eco, _names, _fn in KNOWN_VULNS:
    for _n in _names.split('|'):
        VULN_INDEX[(_eco, _n.lower())].append(_fn)


def _manifest_deps(rel, text):
    """[(ecosystem, name, version, line, pinned)] declared in a manifest / lock file."""
    low = os.path.basename(rel).lower()
    deps = []

    def line_of(pattern, start=0):
        m = re.search(pattern, text[start:], re.M)
        return text.count('\n', 0, start + m.start()) + 1 if m else 1

    if low == 'pom.xml':
        props = dict(re.findall(r'<([\w.-]+)>\s*([^<\s]+)\s*</\1>', (re.search(r'<properties>([\s\S]*?)</properties>', text) or
                                                                     re.match('', '')).group(1) if re.search('<properties>', text) else ''))
        for m in re.finditer(r'<(?:dependency|plugin)>([\s\S]*?)</(?:dependency|plugin)>', text):
            blk = m.group(1)
            g = re.search(r'<groupId>\s*([^<]+?)\s*</groupId>', blk)
            a = re.search(r'<artifactId>\s*([^<]+?)\s*</artifactId>', blk)
            v = re.search(r'<version>\s*([^<]+?)\s*</version>', blk)
            if not (g and a and v):
                continue
            ver = v.group(1)
            pm = re.match(r'\$\{([^}]+)\}', ver)
            if pm:
                ver = props.get(pm.group(1), '')
            deps.append(('maven', '%s:%s' % (g.group(1), a.group(1)), ver, text.count('\n', 0, m.start() + blk.find('<version>')) + 1, True))
    elif low in ('build.gradle', 'build.gradle.kts'):
        for m in re.finditer(r'["\']([\w.-]+):([\w.-]+):([\w.+-]+)["\']', text):
            deps.append(('maven', '%s:%s' % (m.group(1), m.group(2)), m.group(3), text.count('\n', 0, m.start()) + 1, True))
    elif low == 'package.json':
        try:
            data = json.loads(text)
        except ValueError:
            return deps
        for sec in ('dependencies', 'devDependencies', 'optionalDependencies', 'peerDependencies'):
            for name, spec in (data.get(sec) or {}).items():
                if not isinstance(spec, str):
                    continue
                pinned = bool(re.match(r'^\s*v?\d', spec))
                deps.append(('npm', name, re.sub(r'^[\^~>=<v\s]+', '', spec), line_of(r'"%s"\s*:' % re.escape(name)), pinned))
    elif low in ('package-lock.json', 'npm-shrinkwrap.json'):
        try:
            data = json.loads(text)
        except ValueError:
            return deps
        pk = data.get('packages') or {}
        for path, info in pk.items():
            if path.startswith('node_modules/') and isinstance(info, dict) and info.get('version'):
                name = path.split('node_modules/')[-1]
                deps.append(('npm', name, info['version'], 0, True))
        if not pk:
            for name, info in (data.get('dependencies') or {}).items():
                if isinstance(info, dict) and info.get('version'):
                    deps.append(('npm', name, info['version'], 0, True))
    elif low.startswith('requirements') or low.endswith('.txt'):
        for i, line in enumerate(text.split('\n'), 1):
            m = re.match(r'^\s*([A-Za-z0-9_.-]+)\s*(?:\[[^\]]*\])?\s*(==|>=|~=|<=|>|<|===)\s*([\w.]+)', line)
            if m:
                deps.append(('pypi', m.group(1), m.group(3), i, m.group(2) in ('==', '===')))
    elif low == 'gemfile.lock':
        for i, line in enumerate(text.split('\n'), 1):
            m = re.match(r'^ {4}([\w.-]+) \(([\d.]+)', line)
            if m:
                deps.append(('rubygems', m.group(1), m.group(2), i, True))
    elif low == 'gemfile':
        for i, line in enumerate(text.split('\n'), 1):
            m = re.match(r'''^\s*gem\s+["']([\w.-]+)["']\s*,\s*["'](?:=\s*|~>\s*)?([\d.]+)["']''', line)
            if m:
                deps.append(('rubygems', m.group(1), m.group(2), i, True))
    elif low == 'go.mod':
        for i, line in enumerate(text.split('\n'), 1):
            m = re.match(r'^\s*(?:require\s+)?([\w.\-]+/[\w./\-]+)\s+v([\w.\-+]+)', line)
            if m:
                deps.append(('go', m.group(1), m.group(2), i, True))
    elif low.endswith(('.csproj', '.vbproj', '.fsproj')) or low == 'directory.packages.props':
        for m in re.finditer(r'<Package(?:Reference|Version)\s+Include="([^"]+)"\s+Version="([^"]+)"', text):
            deps.append(('nuget', m.group(1), m.group(2), text.count('\n', 0, m.start()) + 1, True))
    elif low == 'composer.lock':
        try:
            data = json.loads(text)
        except ValueError:
            return deps
        for p in (data.get('packages') or []) + (data.get('packages-dev') or []):
            deps.append(('composer', p.get('name', ''), p.get('version', ''), 0, True))
    return deps


def analyze_deps(root, configs, out):
    seen = set()
    for rec in configs:
        if rec.get('config') not in ('manifest', 'lock'):
            continue
        path = os.path.join(root, rec['path'])
        try:
            with open(path, 'rb') as f:
                text = f.read().decode('utf-8', 'replace')
        except OSError:
            continue
        for eco, name, ver, line, pinned in _manifest_deps(rec['path'], text):
            for fn in VULN_INDEX.get((eco, name.lower()), ()):
                res = fn(ver)
                if not res:
                    continue
                key = (eco, name.lower(), ver)
                if key in seen:
                    continue
                seen.add(key)
                if not line:
                    m = re.search(r'"(?:node_modules/)?%s"' % re.escape(name), text)
                    line = text.count('\n', 0, m.start()) + 1 if m else 1
                sev, msg = res
                out.append(finding(rec['path'], line, 'deps-known-vulnerable', 'Known vulnerable dependency: %s %s' % (name, ver),
                                   '%s %s: %s.%s' % (name, ver, msg, '' if pinned else
                                                     ' The version range starts at a vulnerable release; check the lock file.'),
                                   sev if pinned else ('MEDIUM' if sev in ('CRITICAL', 'HIGH') else sev),
                                   'HIGH' if pinned else 'LOW', 1104))


# =========================================================================== #
# Entry point
# =========================================================================== #
def load_sources(root, records, max_bytes=2 * 1024 * 1024):
    srcs = []
    for r in records:
        lang = LANG_OF_EXT.get(r['ext'])
        if not lang:
            continue
        path = os.path.join(root, r['path'])
        try:
            if os.path.getsize(path) > max_bytes:
                continue
            with open(path, 'rb') as f:
                text = f.read().decode('utf-8', 'replace')
        except OSError:
            continue
        srcs.append(Src(r['path'], text, '\n'.join(AS.code_view(text, r['kind'], r['grammar'])), lang))
    return srcs


ANALYZERS = [
    ('authz', lambda by_lang, srcs, root, extra, out: analyze_authz(by_lang, out)),
    ('authflow', lambda by_lang, srcs, root, extra, out: analyze_authflow(srcs, out)),
    ('taint', lambda by_lang, srcs, root, extra, out: analyze_taint(srcs, out)),
    ('deps', lambda by_lang, srcs, root, extra, out: analyze_deps(root, extra.get('configs') or [], out)),
]


def analyze(root, records, extra=None):
    """Run every structural analyzer. Returns (findings, errors)."""
    srcs = load_sources(root, records)
    by_lang = defaultdict(list)
    for s in srcs:
        by_lang[s.lang].append(s)
    out, errors = [], []
    for name, fn in ANALYZERS:
        try:
            fn(by_lang, srcs, root, extra or {}, out)
        except Exception as ex:                       # an analyzer bug must never kill the scan
            import traceback
            errors.append('%s: %s: %s' % (name, type(ex).__name__, ex))
            if os.environ.get('CODIT_DEBUG'):
                traceback.print_exc()
    seen, uniq = set(), []
    for f in out:
        k = (f['path'], f['line'], f['rule'])
        if k not in seen:
            seen.add(k)
            uniq.append(f)
    return uniq, errors
