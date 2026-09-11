#!/usr/bin/env python3
"""triage.py - paste-safe summarizer for sweep.py --sp output and enum-entra summaries.

Never prints secret values: everything after '::' (the snippet) is dropped,
hosts are redacted by default, and hits are ranked so the gold floats to the top.

Usage:
  python3 triage.py sweep-sp-20260911-155500.txt
  python3 triage.py ~/enum-entra-*/_summary.txt
  python3 triage.py file.txt --keep-domains     # only if you want full URLs
"""
import collections
import os
import re
import sys

keep_domains = "--keep-domains" in sys.argv

# --mask @file (one word per line) or --mask word1,word2 - blanked everywhere,
# case-insensitive. Use a file so the words stay out of shell/auditd cmdlines.
args = []
MASKS = []
i = 1
while i < len(sys.argv):
    a = sys.argv[i]
    if a == "--mask" and i + 1 < len(sys.argv):
        v = sys.argv[i + 1]
        if v.startswith("@"):
            MASKS = [w.strip() for w in open(v[1:], encoding="utf-8") if w.strip()]
        else:
            MASKS = [w.strip() for w in v.split(",") if w.strip()]
        i += 2
        continue
    if not a.startswith("--"):
        args.append(a)
    i += 1


def emit(*args):
    s = " ".join(str(a) for a in args)
    for w in MASKS:
        s = re.sub(re.escape(w), "[X]", s, flags=re.I)
    print(s)


if not args:
    sys.exit(__doc__)


def redact_url(u):
    if keep_domains:
        return u
    m = re.match(r"https://([^/]+)(/.*)?", u)
    if not m:
        return "[url]"
    return "[host]" + (m.group(2) or "")


def triage_sweep(path, lines):
    content = collections.defaultdict(set)
    sphit, spdoc, errs = [], [], []
    for l in lines:
        if l.startswith("[CONTENT]"):
            m = re.match(r"\[CONTENT\] (\S+) \| (?:needle|pattern)=(\S+)", l)
            if m:
                content[redact_url(m.group(1))].add(m.group(2))
        elif l.startswith("[SP-HIT]"):
            m = re.match(r"\[SP-HIT\] (\S+) \| query=(.+?) name=(.+?) size=(\d+) modified=(\S+)", l)
            if m:
                sphit.append((m.group(3), int(m.group(4)), m.group(2), redact_url(m.group(1))))
        elif l.startswith("[SP-DOC]"):
            m = re.match(r"\[SP-DOC\] (\S+) \| query=(.+?) name=(.+?) size=(\d+) modified=(\S+)", l)
            if m:
                spdoc.append((m.group(3), int(m.group(4)), m.group(2), redact_url(m.group(1))))
        elif l.startswith("[SP-ERR]"):
            errs.append(l[:160])

    emit("== sweep-sp triage:", os.path.basename(path))
    emit("files-with-content-hits=%d  sp-hits=%d  sp-docs=%d  errors=%d"
          % (len(content), len(sphit), len(spdoc), len(errs)))

    emit("\n-- content hits (ranked by distinct needles) --")
    for url, needles in sorted(content.items(), key=lambda kv: -len(kv[1])):
        emit("%3d needles  %s  [%s]" % (len(needles), url, ", ".join(sorted(needles))))

    emit("\n-- secret-lane files (not downloaded / oversized) --")
    for name, size, query, url in sphit:
        emit("%10d B  %-40s query=%s" % (size, name[:40], query))

    emit("\n-- discovery docs (backup/warehouse) --")
    for name, size, query, url in spdoc:
        emit("%10d B  %-50s query=%s" % (size, name[:50], query))

    if errs:
        emit("\n-- errors --")
        for e in errs[:10]:
            emit(e)


def triage_enum(path, lines):
    emit("== enum-entra triage:", os.path.basename(path))
    for l in lines:
        # status lines and display names only; drop anything that looks token-y
        if re.search(r"eyJ[A-Za-z0-9_-]{10,}", l):
            emit("[redacted line - looked like a token]")
        else:
            emit(l)


for path in args:
    lines = open(path, encoding="utf-8", errors="replace").read().splitlines()
    if any(l.startswith("[SP-") or l.startswith("[CONTENT]") for l in lines):
        triage_sweep(path, lines)
    else:
        triage_enum(path, lines)
