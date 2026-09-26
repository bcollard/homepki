/* homepki site behaviour, shared by every page. No dependencies.
   Each block is independent and returns early when its elements are absent. */

/* theme toggle: auto -> light -> dark -> auto. The stored choice is applied
   by an inline snippet in <head> so the page never flashes the wrong theme. */
(function () {
  var root = document.documentElement;
  var btn = document.getElementById('themeToggle');
  if (!btn) return;
  btn.addEventListener('click', function () {
    var cur = root.getAttribute('data-theme') || 'auto';
    var next = cur === 'auto' ? 'light' : cur === 'light' ? 'dark' : 'auto';
    root.setAttribute('data-theme', next);
    btn.title = 'Theme: ' + next;
    try {
      if (next === 'auto') localStorage.removeItem('homepki-theme');
      else localStorage.setItem('homepki-theme', next);
    } catch (e) {}
  });
  btn.title = 'Theme: ' + (root.getAttribute('data-theme') || 'auto');
})();

/* latest release in the nav. The page ships the version current when it was
   generated; this refreshes it from the GitHub API, cached for an hour so
   browsing the docs costs one request (the API allows 60 per hour per IP). */
(function () {
  var el = document.getElementById('navVersion');
  if (!el || !window.fetch) return;
  var KEY = 'homepki-release', TTL = 3600 * 1000;
  function show(tag) { if (tag) { el.textContent = tag; el.title = 'Latest release: ' + tag; } }
  try {
    var cached = JSON.parse(sessionStorage.getItem(KEY) || 'null');
    if (cached && Date.now() - cached.at < TTL) { show(cached.tag); return; }
  } catch (e) {}
  fetch('https://api.github.com/repos/bcollard/homepki/releases/latest', { headers: { Accept: 'application/vnd.github+json' } })
    .then(function (r) { return r.ok ? r.json() : null; })
    .then(function (d) {
      if (!d || !d.tag_name) return;
      show(d.tag_name);
      try { sessionStorage.setItem(KEY, JSON.stringify({ tag: d.tag_name, at: Date.now() })); } catch (e) {}
    })
    .catch(function () {});
})();

/* docs sidebar: open on desktop, collapsed behind "Documentation menu" on phones */
(function () {
  var sb = document.getElementById('docsSidebar');
  if (sb && window.matchMedia('(min-width: 881px)').matches) sb.open = true;
})();

/* heading anchors: hover link icon on every h2/h3 with an id, click copies the URL */
(function () {
  var ICON = '<svg viewBox="0 0 16 16" width="14" height="14" aria-hidden="true"><path fill="currentColor" d="M7.775 3.275a.75.75 0 0 0 1.06 1.06l1.25-1.25a2 2 0 1 1 2.83 2.83l-2.5 2.5a2 2 0 0 1-2.83 0 .75.75 0 0 0-1.06 1.06 3.5 3.5 0 0 0 4.95 0l2.5-2.5a3.5 3.5 0 0 0-4.95-4.95l-1.25 1.25Zm-1.06 9.45a.75.75 0 0 0-1.06-1.06l-1.25 1.25a2 2 0 1 1-2.83-2.83l2.5-2.5a2 2 0 0 1 2.83 0 .75.75 0 0 0 1.06-1.06 3.5 3.5 0 0 0-4.95 0l-2.5 2.5a3.5 3.5 0 1 0 4.95 4.95l1.25-1.25Z"/></svg>';
  document.querySelectorAll('.docs-prose h2[id], .docs-prose h3[id]').forEach(function (h) {
    var a = document.createElement('a');
    a.className = 'anchor-link';
    a.href = '#' + h.id;
    a.setAttribute('aria-label', 'Copy link to this section');
    a.innerHTML = ICON;
    a.addEventListener('click', function (e) {
      e.preventDefault();
      var url = location.origin + location.pathname + '#' + h.id;
      if (history.replaceState) history.replaceState(null, '', '#' + h.id);
      var done = function () {
        a.classList.add('copied');
        setTimeout(function () { a.classList.remove('copied'); }, 1400);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(url).then(done, done);
      else done();
    });
    h.appendChild(a);
  });
})();

/* docs search over the prebuilt heading index (docs/search-index.js).
   Entry pages are relative to docs/docs/, which is where the search box lives. */
(function () {
  var input = document.getElementById('docsSearch');
  var list = document.getElementById('docsSearchResults');
  if (!input || !list) return;
  var index = window.HOMEPKI_DOCS_INDEX || [];
  var active = -1;

  function links() { return Array.prototype.slice.call(list.querySelectorAll('a')); }
  function close() { list.hidden = true; list.innerHTML = ''; active = -1; }
  function setActive(i) {
    var ls = links();
    if (!ls.length) return;
    if (ls[active]) ls[active].classList.remove('active');
    active = (i + ls.length) % ls.length;
    ls[active].classList.add('active');
    ls[active].scrollIntoView({ block: 'nearest' });
  }
  /* punctuation is ignored, so "pkcs12" finds "PKCS#12" and "force" finds "--force" */
  function norm(s) { return s.toLowerCase().replace(/[^a-z0-9\s]+/g, ''); }
  function score(e, words) {
    var t = norm(e.text), hay = norm(e.text + ' ' + e.title + ' ' + e.section);
    for (var i = 0; i < words.length; i++) if (hay.indexOf(words[i]) === -1) return -1;
    return (t.indexOf(words[0]) === 0 ? 0 : t.indexOf(words[0]) !== -1 ? 1 : 2) + (e.anchor ? 0.5 : 0);
  }
  function search() {
    var q = norm(input.value).trim();
    if (!q) { close(); return; }
    var words = q.split(/\s+/);
    var hits = index
      .map(function (e) { return { e: e, s: score(e, words) }; })
      .filter(function (h) { return h.s >= 0; })
      .sort(function (a, b) { return a.s - b.s; })
      .slice(0, 8);
    list.innerHTML = '';
    active = -1;
    if (!hits.length) {
      list.innerHTML = '<li class="r-none">No matching section</li>';
      list.hidden = false;
      return;
    }
    hits.forEach(function (h) {
      var m = h.e, li = document.createElement('li'), a = document.createElement('a');
      a.href = m.page + (m.anchor ? '#' + m.anchor : '');
      a.innerHTML = '<span class="r-title"></span><span class="r-path"></span>';
      a.querySelector('.r-title').textContent = m.text;
      a.querySelector('.r-path').textContent = !m.anchor ? 'Page' : (m.section && m.section !== m.text ? m.title + ' › ' + m.section : m.title);
      li.appendChild(a);
      list.appendChild(li);
    });
    list.hidden = false;
  }
  input.addEventListener('input', search);
  input.addEventListener('focus', search);
  input.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { input.value = ''; close(); input.blur(); return; }
    if (e.key === 'ArrowDown' && !list.hidden) { e.preventDefault(); setActive(active + 1); return; }
    if (e.key === 'ArrowUp' && !list.hidden) { e.preventDefault(); setActive(active - 1); return; }
    if (e.key === 'Enter') {
      var ls = links(), t = ls[active] || ls[0];
      if (t) { e.preventDefault(); location.href = t.getAttribute('href'); }
    }
  });
  document.addEventListener('click', function (e) { if (e.target !== input && !list.contains(e.target)) list.hidden = true; });
  document.addEventListener('keydown', function (e) {
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); input.focus(); input.select(); }
  });
})();

/* copy buttons: <button class="copy-btn" data-copy="text"> */
(function () {
  document.querySelectorAll('.copy-btn[data-copy]').forEach(function (b) {
    b.addEventListener('click', function () {
      var reset = function () { setTimeout(function () { b.textContent = 'Copy'; }, 1400); };
      if (!navigator.clipboard) return;
      navigator.clipboard.writeText(b.getAttribute('data-copy')).then(function () { b.textContent = 'Copied'; reset(); });
    });
  });
})();
