#!/usr/bin/env python3
"""Keep the hand-written website in docs/ consistent, then validate it.

The pages are plain HTML, edited by hand. What every page repeats is rewritten
here from one page list, between marker comments:

    <!-- nav -->...<!-- /nav -->              top bar (Home, Docs, GitHub, release badge)
    <!-- sidebar -->...<!-- /sidebar -->      docs menu, current page marked active
    <!-- breadcrumb -->...<!-- /breadcrumb -->
    <!-- pager -->...<!-- /pager -->          previous / next, in sidebar order
    <!-- footer -->...<!-- /footer -->

It also regenerates docs/docs/search-index.js (from every h1, h2[id], h3[id])
and docs/sitemap.xml, and fails on broken links, missing anchors, duplicate
ids, headings without ids, unbalanced tags and <pre> inside a .callout.

Run from the repository root after any website change:

    python3 scripts/site.py

The release badge carries the newest version in docs/docs/changelog.html as
its fallback text; site.js refreshes it from the GitHub API in the browser.
"""
import datetime
import html
import json
import os
import re
import subprocess
import sys
from urllib.parse import urlsplit

SITE = "docs"
DOCS = os.path.join(SITE, "docs")
BASE_URL = "https://bcollard.github.io/homepki/"
REPO = "https://github.com/bcollard/homepki"

# Sidebar groups, in order. The pager follows this order as one chain.
GROUPS = [
    ("Introduction", [
        ("index.html", "Overview"),
        ("getting-started.html", "Getting started"),
        ("comparison.html", "vs. other tools"),
        ("faq.html", "FAQ"),
    ]),
    ("Issuing certificates", [
        ("hierarchy.html", "Certificate hierarchy"),
        ("leaf-certificates.html", "Server and client certificates"),
        ("signing-csrs.html", "Signing external CSRs"),
        ("listing.html", "Listing and verification"),
        ("using-certificates.html", "Using the certificates"),
    ]),
    ("Security", [
        ("name-constraints.html", "Name constraints"),
        ("revocation.html", "Revocation"),
        ("trust.html", "Trusting the root CA"),
    ]),
    ("Reference", [
        ("cli-reference.html", "CLI reference"),
        ("go-package.html", "Go package"),
        ("agent-skill.html", "Agent Skill"),
        ("changelog.html", "Changelog"),
    ]),
]
PAGES = [p for _, items in GROUPS for p in items]

problems = []


def latest_release():
    """The newest version in changelog.html. Taken from the changelog rather
    than git tags so the site can be regenerated before the tag exists: the
    release commit then already carries the right badge."""
    src = open(os.path.join(DOCS, "changelog.html"), encoding="utf-8").read()
    m = re.search(r'<h2 id="v[^"]*">(v\d+\.\d+\.\d+)', src)
    if not m:
        problems.append("changelog.html: no <h2> starting with vX.Y.Z")
        return "releases"
    return m.group(1)


def nav(prefix, search):
    """prefix is the path from the page to docs/ ("" for the home page, "../" in docs/docs/)."""
    box = ""
    if search:
        box = (
            '  <div class="nav-search">\n'
            '    <input type="search" id="docsSearch" placeholder="Search docs…" aria-label="Search documentation" autocomplete="off">\n'
            '    <kbd class="nav-search-kbd">⌘K</kbd>\n'
            '    <ul class="docs-search-results" id="docsSearchResults" hidden></ul>\n'
            '  </div>\n'
        )
    return (
        '<nav class="nav">\n'
        f'  <a class="brand" href="{prefix or "./"}" aria-label="homepki home">\n'
        f'    <img src="{prefix}mark.svg" width="28" height="28" alt="">\n'
        '    <strong>homepki</strong>\n'
        '  </a>\n'
        f'{box}'
        '  <div class="nav-right">\n'
        f'    <a class="nav-home" href="{prefix or "./"}">Home</a>\n'
        f'    <a class="nav-docs" href="{prefix}docs/">Docs</a>\n'
        f'    <a class="nav-github" href="{REPO}">GitHub</a>\n'
        f'    <a class="nav-version" id="navVersion" href="{REPO}/releases/latest" title="Latest release">{TAG}</a>\n'
        '    <button class="theme-toggle" id="themeToggle" type="button" aria-label="Toggle colour theme">'
        '<span class="sun">☀</span><span class="moon">☾</span><span class="auto">◐</span></button>\n'
        '  </div>\n'
        '</nav>'
    )


def sidebar(current):
    groups = []
    for name, items in GROUPS:
        links = []
        for page, title in items:
            active = ' class="active" aria-current="page"' if page == current else ""
            href = "./" if page == "index.html" else page
            links.append(f'          <li><a href="{href}"{active}>{html.escape(title)}</a></li>')
        groups.append(
            '      <div class="docs-nav-group">\n'
            f'        <h5>{html.escape(name)}</h5>\n'
            '        <ul class="docs-nav">\n' + "\n".join(links) + "\n"
            '        </ul>\n'
            '      </div>'
        )
    return (
        '<details class="docs-sidebar" id="docsSidebar">\n'
        '    <summary>Documentation menu</summary>\n'
        '    <div class="docs-nav-inner">\n' + "\n".join(groups) + "\n"
        '    </div>\n'
        '  </details>'
    )


def breadcrumb(current, title):
    if current == "index.html":
        return '<p class="breadcrumb"><a href="../">Home</a> › Docs</p>'
    return f'<p class="breadcrumb"><a href="../">Home</a> › <a href="./">Docs</a> › {html.escape(title)}</p>'


def pager(i):
    parts = []
    if i > 0:
        page, title = PAGES[i - 1]
        href = "./" if page == "index.html" else page
        parts.append(f'        <a href="{href}"><span class="dir">← Previous</span><span class="ttl">{html.escape(title)}</span></a>')
    if i + 1 < len(PAGES):
        page, title = PAGES[i + 1]
        parts.append(f'        <a class="next" href="{page}"><span class="dir">Next →</span><span class="ttl">{html.escape(title)}</span></a>')
    return '<div class="doc-pager">\n' + "\n".join(parts) + '\n      </div>'


def footer(prefix):
    return (
        '<footer class="footer">\n'
        '  <div class="container">\n'
        f'    <p>MIT licensed · <a href="{REPO}">Source</a> · <a href="{REPO}/releases">Releases</a> · '
        f'<a href="{REPO}/issues">Issues</a> · Built by <a href="https://github.com/bcollard">Baptiste Collard</a></p>\n'
        '  </div>\n'
        '</footer>'
    )


def replace_block(src, name, content, path):
    pat = re.compile(rf"<!-- {name} -->.*?<!-- /{name} -->", re.S)
    if not pat.search(src):
        problems.append(f"{path}: missing <!-- {name} --> marker")
        return src
    return pat.sub(lambda _: f"<!-- {name} -->{content}<!-- /{name} -->", src)


def sync():
    home = os.path.join(SITE, "index.html")
    src = open(home, encoding="utf-8").read()
    src = replace_block(src, "nav", nav("", False), home)
    src = replace_block(src, "footer", footer(""), home)
    write_if_changed(home, src)

    for extra in ["404.html"]:
        path = os.path.join(SITE, extra)
        if os.path.exists(path):
            src = open(path, encoding="utf-8").read()
            # 404.html is served at any depth, so it links by absolute path
            src = replace_block(src, "nav", nav("/homepki/", False), path)
            src = replace_block(src, "footer", footer("/homepki/"), path)
            write_if_changed(path, src)

    for i, (page, title) in enumerate(PAGES):
        path = os.path.join(DOCS, page)
        if not os.path.exists(path):
            problems.append(f"{path}: listed in GROUPS but missing")
            continue
        src = open(path, encoding="utf-8").read()
        src = replace_block(src, "nav", nav("../", True), path)
        src = replace_block(src, "sidebar", sidebar(page), path)
        src = replace_block(src, "breadcrumb", breadcrumb(page, title), path)
        src = replace_block(src, "pager", pager(i), path)
        src = replace_block(src, "footer", footer("../"), path)
        write_if_changed(path, src)

    listed = {p for p, _ in PAGES}
    for f in sorted(os.listdir(DOCS)):
        if f.endswith(".html") and f not in listed:
            problems.append(f"{DOCS}/{f}: not listed in GROUPS")


def write_if_changed(path, src):
    if open(path, encoding="utf-8").read() != src:
        open(path, "w", encoding="utf-8").write(src)
        print("updated", path)


TAG_RE = re.compile(r"<[^>]+>")


def clean(raw):
    return re.sub(r"\s+", " ", html.unescape(TAG_RE.sub("", raw))).strip()


def search_index():
    entries = []
    for page, _ in PAGES:
        if not os.path.exists(os.path.join(DOCS, page)):
            continue  # reported by sync()
        src = open(os.path.join(DOCS, page), encoding="utf-8").read()
        m = re.search(r'<article class="docs-prose">(.*?)</article>', src, re.S)
        body = m.group(1) if m else src
        h1 = re.search(r"<h1[^>]*>(.*?)</h1>", body, re.S)
        title = clean(h1.group(1)) if h1 else page
        href = "./" if page == "index.html" else page
        entries.append({"page": href, "anchor": "", "title": title, "section": "", "text": title})
        section = ""
        for level, hid, raw in re.findall(r'<(h2|h3)\s+id="([^"]+)"[^>]*>(.*?)</\1>', body, re.S):
            text = clean(raw)
            if level == "h2":
                section = text
            entries.append({"page": href, "anchor": hid, "title": title,
                            "section": "" if level == "h2" else section, "text": text})
    js = "window.HOMEPKI_DOCS_INDEX = " + json.dumps(entries, ensure_ascii=False, indent=1) + ";\n"
    path = os.path.join(DOCS, "search-index.js")
    if not os.path.exists(path) or open(path, encoding="utf-8").read() != js:
        open(path, "w", encoding="utf-8").write(js)
        print(f"updated {path} ({len(entries)} entries)")


def lastmod(path):
    dirty = subprocess.run(["git", "status", "--porcelain", "--", path], capture_output=True, text=True).stdout.strip()
    if not dirty:
        out = subprocess.run(["git", "log", "-1", "--format=%cs", "--", path], capture_output=True, text=True).stdout.strip()
        if out:
            return out
    return datetime.date.today().isoformat()


def sitemap():
    urls = [(BASE_URL, os.path.join(SITE, "index.html"), "1.0")]
    for page, _ in PAGES:
        loc = BASE_URL + "docs/" + ("" if page == "index.html" else page)
        urls.append((loc, os.path.join(DOCS, page), "0.9" if page == "index.html" else "0.7"))
    body = "".join(
        f"  <url>\n    <loc>{loc}</loc>\n    <lastmod>{lastmod(p)}</lastmod>\n    <priority>{prio}</priority>\n  </url>\n"
        for loc, p, prio in urls
    )
    xml = '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + body + "</urlset>\n"
    path = os.path.join(SITE, "sitemap.xml")
    if open(path, encoding="utf-8").read() != xml:
        open(path, "w", encoding="utf-8").write(xml)
        print("updated", path)


def validate():
    pages = [os.path.join(SITE, "index.html")] + [os.path.join(DOCS, p) for p, _ in PAGES]
    ids = {}
    for p in pages:
        if os.path.exists(p):
            ids[os.path.normpath(p)] = re.findall(r'\sid="([^"]+)"', open(p, encoding="utf-8").read())
    for p in pages:
        if not os.path.exists(p):
            continue
        src = open(p, encoding="utf-8").read()
        mine = ids[os.path.normpath(p)]
        for d in sorted({x for x in mine if mine.count(x) > 1}):
            problems.append(f"{p}: duplicate id {d!r}")
        for m in re.finditer(r"<(h2|h3)(\s[^>]*)?>", src):
            if 'id="' not in (m.group(2) or "") and "docs-card" not in src[max(0, m.start() - 80):m.start()]:
                if p != os.path.join(SITE, "index.html"):
                    problems.append(f"{p}: <{m.group(1)}> without id near {clean(src[m.end():m.end()+60])!r}")
        for href in re.findall(r'(?:href|src)="([^"]+)"', src):
            u = urlsplit(href)
            if u.scheme or href.startswith("//") or href.startswith("mailto:"):
                continue
            target = os.path.normpath(os.path.join(os.path.dirname(p), u.path)) if u.path else os.path.normpath(p)
            if os.path.isdir(target):
                target = os.path.join(target, "index.html")
            if not os.path.exists(target):
                problems.append(f"{p}: broken link {href}")
            elif u.fragment and u.fragment not in ids.get(os.path.normpath(target), [u.fragment]):
                problems.append(f"{p}: missing anchor {href}")
        for tag in ["div", "ul", "ol", "table", "tbody", "thead", "tr", "pre", "code", "nav", "details", "article", "section", "p", "a"]:
            opened = len(re.findall(rf"<{tag}[\s>]", src))
            closed = len(re.findall(rf"</{tag}>", src))
            if opened != closed:
                problems.append(f"{p}: <{tag}> opened {opened}, closed {closed}")
        for m in re.findall(r'<div class="callout[^"]*">.*?</div>', src, re.S):
            if "<pre" in m:
                problems.append(f"{p}: <pre> inside a callout")
        for m in re.findall(r'<script type="application/ld\+json">(.*?)</script>', src, re.S):
            try:
                json.loads(m)
            except ValueError as e:
                problems.append(f"{p}: invalid JSON-LD: {e}")


if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    TAG = latest_release()
    sync()
    search_index()
    sitemap()
    validate()
    if problems:
        print("\n".join(problems), file=sys.stderr)
        sys.exit(1)
    print(f"ok: {len(PAGES) + 1} pages, release badge {TAG}")
