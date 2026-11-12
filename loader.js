// Login i dešifriranje šifrirane kopije web_app (AES-256-GCM, ključ iz PBKDF2-SHA256).
// Isti kod koristi i node test (deploy/test_pages.mjs); UI se pokreće samo u browseru.
(function () {
  const subtle = globalThis.crypto.subtle;
  const b64d = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  const b64e = u => btoa(String.fromCharCode(...new Uint8Array(u)));

  async function deriveKey(user, pass, meta) {
    const material = new TextEncoder().encode(String(user).trim().toLowerCase() + ':' + pass);
    const base = await subtle.importKey('raw', material, 'PBKDF2', false, ['deriveKey']);
    return subtle.deriveKey({ name: 'PBKDF2', hash: 'SHA-256', salt: b64d(meta.salt), iterations: meta.iter },
      base, { name: 'AES-GCM', length: 256 }, true, ['decrypt']);
  }
  async function gunzip(bytes) {
    const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  }
  // blob = 12 B IV + šifrat (s GCM oznakom); sadržaj je gzip
  async function decryptBlob(key, buf) {
    const u = new Uint8Array(buf);
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: u.slice(0, 12) }, key, u.slice(12));
    return gunzip(new Uint8Array(plain));
  }
  const api = { deriveKey, decryptBlob, b64d, b64e };
  globalThis.RTUCrypt = api;
  if (typeof document === 'undefined') return;

  const BASE = location.pathname.replace(/[^/]*$/, '');
  const SKEY = 'rtu_pages_key';
  const txt = u => new TextDecoder().decode(u);
  const $ = s => document.querySelector(s);

  async function fetchBlob(id) {
    const r = await fetch('enc/' + id + '.bin', { cache: 'no-store' });
    if (!r.ok) throw Error('enc/' + id + ': ' + r.status);
    return r.arrayBuffer();
  }

  async function open(key) {
    const manifest = JSON.parse(txt(await decryptBlob(key, await fetchBlob('m'))));
    const cache = new Map();
    const get = p => {
      if (!cache.has(p)) cache.set(p, fetchBlob(manifest.files[p].id).then(b => decryptBlob(key, b)));
      return cache.get(p);
    };
    const pathOf = href => {
      const u = new URL(href, location.href);
      if (u.origin !== location.origin || !u.pathname.startsWith(BASE)) return null;
      const p = decodeURIComponent(u.pathname.slice(BASE.length));
      return manifest.files[p] ? p : null;
    };
    const origFetch = window.fetch.bind(window);
    window.fetch = async (input, init) => {
      const p = pathOf(typeof input === 'string' ? input : input.url);
      if (!p) return origFetch(input, init);
      return new Response(await get(p), { status: 200, headers: { 'Content-Type': manifest.files[p].type } });
    };
    // poveznice na assets/* (Excel, CSV, HTML izvještaj) otvaraju se iz dešifrirane kopije
    document.addEventListener('click', e => {
      const a = e.target.closest && e.target.closest('a[href]');
      const p = a && pathOf(a.getAttribute('href'));
      if (!p) return;
      e.preventDefault();
      const type = manifest.files[p].type, isHtml = type.startsWith('text/html');
      const win = isHtml ? window.open('', '_blank') : null;
      get(p).then(bytes => {
        const url = URL.createObjectURL(new Blob([bytes], { type }));
        if (win) win.location = url;
        else { const d = document.createElement('a'); d.href = url; d.download = p.split('/').pop(); d.click(); }
        setTimeout(() => URL.revokeObjectURL(url), 60000);
      });
    }, true);

    const doc = new DOMParser().parseFromString(txt(await get('index.html')), 'text/html');
    document.title = doc.title;
    for (const l of doc.querySelectorAll('link[rel=stylesheet]')) {
      const p = pathOf(l.getAttribute('href'));
      if (p) { const s = document.createElement('style'); s.textContent = txt(await get(p)); document.head.appendChild(s); }
      l.remove();
    }
    document.head.querySelectorAll('style[data-login]').forEach(s => s.remove());
    const scripts = [...doc.querySelectorAll('script')];
    scripts.forEach(s => s.remove());
    const codes = await Promise.all(scripts.map(s => get(pathOf(s.getAttribute('src')))));
    document.body.className = '';
    document.body.innerHTML = doc.body.innerHTML;
    const out = document.createElement('button');
    out.textContent = 'Odjava';
    out.style.cssText = 'position:fixed;right:12px;bottom:12px;z-index:9999;font:12px system-ui;padding:6px 10px;border:1px solid #ccc;background:#fff;border-radius:6px;cursor:pointer';
    out.onclick = () => { sessionStorage.removeItem(SKEY); location.reload(); };
    document.body.appendChild(out);
    codes.forEach((c, i) => {
      const el = document.createElement('script');
      el.textContent = txt(c) + '\n//# sourceURL=' + scripts[i].getAttribute('src');
      document.body.appendChild(el);
    });
  }

  async function loadMeta() { return (await fetch('enc/meta.json', { cache: 'no-store' })).json(); }

  async function start() {
    const meta = await loadMeta();
    const saved = sessionStorage.getItem(SKEY);
    if (saved) {
      try {
        const key = await subtle.importKey('raw', b64d(saved), { name: 'AES-GCM' }, false, ['decrypt']);
        return await open(key);
      } catch (e) { sessionStorage.removeItem(SKEY); }
    }
    $('#login').hidden = false;
    $('#user').focus();
    $('#login').onsubmit = async ev => {
      ev.preventDefault();
      const btn = $('#go'), msg = $('#msg');
      btn.disabled = true; msg.textContent = 'Provjeravam…';
      let key;
      try {
        key = await deriveKey($('#user').value, $('#pass').value, meta);
        await decryptBlob(key, await fetchBlob('m'));
      } catch (e) {
        msg.textContent = 'Pogrešno korisničko ime ili lozinka.'; btn.disabled = false; return;
      }
      try { sessionStorage.setItem(SKEY, b64e(await subtle.exportKey('raw', key))); } catch (e) {}
      msg.textContent = 'Učitavam podatke…';
      try { await open(key); }
      catch (e) { console.error(e); msg.textContent = 'Podaci se nisu učitali: ' + e.message; btn.disabled = false; }
    };
  }
  start().catch(e => { console.error(e); document.body.textContent = 'Stranica se nije učitala: ' + e.message; });
})();
