#!/usr/bin/env python3
"""Regression runner for the labeled fixture corpora under tests/fixtures/.

Every immediate subdirectory of a corpus (tests/fixtures/<corpus>/<project>/) is scanned as an
independent project with codit.py. Source files carry markers in comments:

    codit-expect: CWE-862[,CWE-639]  reason     -> a finding of that CWE family must be reported
    codit-safe:   CWE-862            reason     -> no finding of that CWE family may be reported

A marker applies to its own line when that line contains code, otherwise to the next code line.
A finding matches when it is in the same file, within +/-WINDOW lines and of the same CWE family.

    python tests/run_fixtures.py                       all corpora, builtin engine only
    python tests/run_fixtures.py a01_access_control    one corpus (or corpus/project)
    python tests/run_fixtures.py --tools builtin,semgrep --show-hits --json out.json
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIXTURES = os.path.join(HERE, 'fixtures')
sys.path.insert(0, ROOT)
import codit  # noqa: E402

MARK = re.compile(r'codit-(expect|safe)\s*:\s*((?:CWE-\d+\s*,?\s*)+)(.*)', re.I)
COMMENT_ONLY = re.compile(r'^\s*(//|#|/\*|\*|<!--|\{\{!--|--|;|\'|%)')
# CWE families that describe the same weakness from different angles
GROUPS = [
    {862, 863, 639, 284, 285, 425, 566, 1220},
    {308, 287, 304, 306, 288},
    {807, 565, 784, 302},
    {916, 328, 759, 760, 256, 257, 261},
    {338, 330, 331},
    {798, 321, 259, 547},
    {200, 209, 497, 215},
    {489, 11, 215},
    {755, 390, 391, 396, 397, 636, 248, 754, 703},
    {1104, 937, 1035, 1395, 1357},
    {829, 494, 353},
    {602, 840, 841},
    {697, 1025, 595, 208},
    {16, 1021, 693},
]


def family(cwe):
    k = codit.kb_key(cwe) or cwe
    fam = {k, cwe}
    for g in GROUPS:
        if k in g or cwe in g:
            fam |= g
    return fam


def markers(project):
    out = []
    for dp, dn, fns in os.walk(project):
        for fn in fns:
            if fn.lower().endswith('.md'):
                continue
            path = os.path.join(dp, fn)
            try:
                lines = open(path, encoding='utf-8', errors='replace').read().split('\n')
            except OSError:
                continue
            rel = os.path.relpath(path, project).replace(os.sep, '/')
            for i, line in enumerate(lines):
                m = MARK.search(line)
                if not m:
                    continue
                cwes = [int(x) for x in re.findall(r'CWE-(\d+)', m.group(2))]
                before = line[:m.start()]
                target = i + 1
                code_before = re.sub(r'(//|#|/\*|<!--|\{\{!--|--|\'|;)\s*$', '', before).strip()
                if not code_before or COMMENT_ONLY.match(before):
                    j = i + 1
                    while j < len(lines) and (not lines[j].strip() or (COMMENT_ONLY.match(lines[j]) and not MARK.search(lines[j]))):
                        j += 1
                    target = j + 1
                out.append(dict(kind=m.group(1).lower(), cwes=cwes, file=rel, line=target, mline=i + 1,
                                why=m.group(3).strip(' -*/>')[:120]))
    return out


def run_codit(project, tools, extra):
    out = tempfile.mkdtemp(prefix='codit_fx_')
    cmd = [sys.executable, os.path.join(ROOT, 'codit.py'), project, '--out', out, '--no-color', '--min-severity', 'LOW',
           '--console-limit', '0', '--tools', tools] + extra
    env = dict(os.environ, PYTHONIOENCODING='utf-8')
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    try:
        with open(os.path.join(out, 'findings.json'), encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        sys.stderr.write(p.stdout.decode('utf-8', 'replace')[-2000:] + p.stderr.decode('utf-8', 'replace')[-3000:])
        data = None
    shutil.rmtree(out, ignore_errors=True)
    return data


def evaluate(project, data, window):
    ms = markers(project)
    finds = data['findings'] if data else []
    res = dict(expect=0, hit=0, safe=0, fp=0, misses=[], fps=[], hits=[], unlabeled=0)
    by_file = defaultdict(list)
    for f in finds:
        by_file[f['file']].append(f)
    used = set()
    for mk in ms:
        fam = set()
        for c in mk['cwes']:
            fam |= family(c)
        near = [f for f in by_file.get(mk['file'], [])
                if abs(f['line'] - mk['line']) <= window and f['cwe'] and (family(f['cwe']) & fam)]
        if mk['kind'] == 'expect':
            res['expect'] += 1
            if near:
                res['hit'] += 1
                res['hits'].append((mk, near[0]))
                used.update(id(f) for f in near)
            else:
                res['misses'].append(mk)
        else:
            res['safe'] += 1
            bad = [f for f in near if abs(f['line'] - mk['line']) <= max(1, window - 1)]
            if bad:
                res['fp'] += 1
                res['fps'].append((mk, bad[0]))
    res['unlabeled'] = len([f for f in finds if id(f) not in used])
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('only', nargs='*', help='corpus or corpus/project names to run')
    ap.add_argument('--tools', default='builtin')
    ap.add_argument('--window', type=int, default=3)
    ap.add_argument('--show-hits', action='store_true')
    ap.add_argument('--quiet', action='store_true', help='summary table only')
    ap.add_argument('--json', help='write detailed results to this file')
    ap.add_argument('--codit-arg', action='append', default=[], help='extra argument passed to codit.py')
    args = ap.parse_args()
    projects = []
    for corpus in sorted(os.listdir(FIXTURES)):
        cdir = os.path.join(FIXTURES, corpus)
        if not os.path.isdir(cdir):
            continue
        for proj in sorted(os.listdir(cdir)):
            pdir = os.path.join(cdir, proj)
            if not os.path.isdir(pdir):
                continue
            name = corpus + '/' + proj
            if args.only and not any(name == o or name.startswith(o.rstrip('/') + '/') for o in args.only):
                continue
            projects.append((name, pdir))
    tot = defaultdict(int)
    report = {}
    print('%-46s %8s %8s %6s %6s' % ('project', 'recall', 'hits', 'FP', 'extra'))
    for name, pdir in projects:
        data = run_codit(pdir, args.tools, args.codit_arg)
        r = evaluate(pdir, data, args.window)
        report[name] = r
        for k in ('expect', 'hit', 'safe', 'fp', 'unlabeled'):
            tot[k] += r[k]
        rec = (100.0 * r['hit'] / r['expect']) if r['expect'] else 100.0
        print('%-46s %7.0f%% %4d/%-4d %6s %6d' % (name, rec, r['hit'], r['expect'], '%d/%d' % (r['fp'], r['safe']), r['unlabeled']))
        if not args.quiet:
            for mk in r['misses']:
                print('    MISS %s:%d CWE-%s  %s' % (mk['file'], mk['line'], ',CWE-'.join(map(str, mk['cwes'])), mk['why']))
            for mk, f in r['fps']:
                print('    FP   %s:%d CWE-%s  safe: %s  <- [%s] %s' % (mk['file'], mk['line'], f['cwe'], mk['why'][:60],
                                                                     ','.join(f['rules'])[:60], f['title'][:60]))
            if args.show_hits:
                for mk, f in r['hits']:
                    print('    hit  %s:%d CWE-%s <- %s' % (mk['file'], mk['line'], f['cwe'], ','.join(f['rules'])[:70]))
    rec = 100.0 * tot['hit'] / tot['expect'] if tot['expect'] else 0
    prec = 100.0 * (tot['safe'] - tot['fp']) / tot['safe'] if tot['safe'] else 100
    print('-' * 80)
    print('TOTAL recall %.1f%% (%d/%d expected)   safe cases clean %.1f%% (%d FP / %d safe)   %d unlabeled findings'
          % (rec, tot['hit'], tot['expect'], prec, tot['fp'], tot['safe'], tot['unlabeled']))
    if args.json:
        with open(args.json, 'w', encoding='utf-8') as f:
            json.dump({k: dict(v, misses=v['misses'], fps=[(a, b['rules']) for a, b in v['fps']],
                               hits=[(a, b['rules']) for a, b in v['hits']]) for k, v in report.items()}, f, indent=1)
    return 0 if tot['fp'] == 0 and tot['hit'] == tot['expect'] else 1


if __name__ == '__main__':
    sys.exit(main())
