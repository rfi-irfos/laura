/*
 * LAURA kit generator — everything runs client-side. No account, no upload
 * of anything personal: the only thing that leaves the browser is the
 * finished .zip, straight to the user's own downloads.
 */
(function () {
  // Fly.io backend base URL. Empty string = beacon disabled (local/dev preview).
  var BEACON_BASE = window.LAURA_BEACON_BASE || '';

  var PRESETS = [
    { id: 'nsfw', label: 'NSFW' },
    { id: 'privat', label: 'Privat' },
    { id: 'personlich', label: 'Persönlich' },
  ];

  var state = { preset: 'nsfw', custom: '' };

  function folderName() {
    if (state.preset === 'custom') {
      var c = (state.custom || '').trim();
      return c || 'Privat';
    }
    var p = PRESETS.find(function (p) { return p.id === state.preset; });
    return p ? p.label : 'Privat';
  }

  function uuid() {
    if (crypto && crypto.randomUUID) return crypto.randomUUID();
    // fallback for older browsers
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = (Math.random() * 16) | 0, v = c === 'x' ? r : (r & 0x3 | 0x8);
      return v.toString(16);
    });
  }

  function drawDecoyImage(seed) {
    var canvas = document.createElement('canvas');
    canvas.width = 480; canvas.height = 640;
    var ctx = canvas.getContext('2d');
    var hues = [(seed * 47) % 360, (seed * 47 + 40) % 360];
    var g = ctx.createLinearGradient(0, 0, canvas.width, canvas.height);
    g.addColorStop(0, 'hsl(' + hues[0] + ',70%,55%)');
    g.addColorStop(1, 'hsl(' + hues[1] + ',70%,35%)');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    ctx.fillStyle = 'rgba(255,255,255,0.15)';
    for (var i = 0; i < 6; i++) {
      ctx.beginPath();
      ctx.arc(Math.random() * canvas.width, Math.random() * canvas.height, 40 + Math.random() * 90, 0, Math.PI * 2);
      ctx.fill();
    }
    return new Promise(function (resolve) {
      canvas.toBlob(function (blob) {
        blob.arrayBuffer().then(function (buf) { resolve(new Uint8Array(buf)); });
      }, 'image/jpeg', 0.7);
    });
  }

  async function fetchTemplate() {
    var res = await fetch('kit-template/album.html');
    if (!res.ok) throw new Error('template fetch failed: ' + res.status);
    return res.text();
  }

  async function buildKit() {
    var kitId = uuid();
    var folder = folderName().replace(/[\\/:*?"<>|]/g, '').trim() || 'Privat';

    var templateText = await fetchTemplate();
    var albumHtml = templateText
      .replace('__KIT_ID__', kitId)
      .replace('__BEACON_BASE__', BEACON_BASE);

    var files = [
      { name: folder + '/album.html', data: new TextEncoder().encode(albumHtml) },
    ];

    var imageCount = 5;
    for (var i = 0; i < imageCount; i++) {
      var data = await drawDecoyImage(i + kitId.charCodeAt(i % kitId.length));
      var num = String(1000 + i);
      files.push({ name: folder + '/IMG_' + num + '.jpg', data: data });
    }

    var zipBlob = MiniZip.buildZip(files);
    return { kitId: kitId, folder: folder, zipBlob: zipBlob };
  }

  // Cross-platform download. iOS Safari silently ignores `download` on
  // blob: URLs and does not save on a synthetic click, so we feature-detect
  // and fall back to opening the blob in a new tab (where the user taps the
  // share/save sheet). On every other OS the anchor-download path is used.
  function downloadBlob(blob, filename) {
    var url = URL.createObjectURL(blob);

    var supportsAnchorDownload = (function () {
      var a = document.createElement('a');
      return typeof a.download !== 'undefined' &&
        typeof URL.createObjectURL === 'function';
    })();

    if (supportsAnchorDownload && !isIOS()) {
      var a = document.createElement('a');
      a.href = url; a.download = filename;
      // Some mobile Chromiums ignore .click(); dispatch a real MouseEvent.
      document.body.appendChild(a);
      if (typeof a.click === 'function') a.click();
      else {
        var evt = document.createEvent('MouseEvents');
        evt.initMouseEvent('click', true, true, window, 0, 0, 0, 0, 0, false, false, false, false, 0, null);
        a.dispatchEvent(evt);
      }
      a.remove();
      setTimeout(function () { URL.revokeObjectURL(url); }, 4000);
      return;
    }

    // iOS fallback: open the blob so the user can save/share it manually.
    var win = window.open(url, '_blank');
    if (!win) {
      // Popup blocked — point the current tab at it instead.
      window.location.href = url;
    }
    showIosSaveHint();
    // Keep the object URL alive; iOS needs it present to save.
  }

  function isIOS() {
    var ua = (navigator.userAgent || '').toLowerCase();
    return /ipad|iphone|ipod/.test(ua) ||
      // iPadOS 13+ reports as Mac but exposes touch points.
      (/macintosh/.test(ua) && navigator.maxTouchPoints > 1);
  }

  function showIosSaveHint() {
    var box = document.getElementById('result');
    if (!box) return;
    var hint = document.getElementById('iosHint');
    if (!hint) {
      hint = document.createElement('div');
      hint.id = 'iosHint';
      hint.className = 'ios-hint';
      hint.innerHTML = 'iOS erkannt: tippe oben auf <strong>↗ teilen / sichern</strong> ' +
        'und wähle <strong>"Datei speichern"</strong>, um das zip zu speichern.';
      box.appendChild(hint);
    }
    hint.hidden = false;
  }

  function renderResult(kitId, folder) {
    var box = document.getElementById('result');
    box.hidden = false;
    document.getElementById('resultCode').textContent = kitId;
    var lookupUrl = BEACON_BASE ? (BEACON_BASE + '/lookup/' + kitId) : '(kein backend konfiguriert)';
    var link = document.getElementById('resultLink');
    link.textContent = lookupUrl;
    if (BEACON_BASE) link.href = lookupUrl;
    document.getElementById('resultFolder').textContent = folder;
    var hint = document.getElementById('iosHint');
    if (hint) hint.hidden = true;
    box.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }

  function initPresets() {
    var row = document.getElementById('presetRow');
    PRESETS.forEach(function (p) {
      var btn = document.createElement('button');
      btn.className = 'btn preset-btn';
      btn.textContent = p.label;
      btn.dataset.preset = p.id;
      if (p.id === state.preset) btn.classList.add('active');
      btn.addEventListener('click', function () {
        state.preset = p.id;
        document.querySelectorAll('.preset-btn').forEach(function (b) { b.classList.remove('active'); });
        btn.classList.add('active');
        document.getElementById('customName').value = '';
      });
      row.appendChild(btn);
    });
    document.getElementById('customName').addEventListener('input', function (e) {
      state.custom = e.target.value;
      if (e.target.value.trim()) {
        state.preset = 'custom';
        document.querySelectorAll('.preset-btn').forEach(function (b) { b.classList.remove('active'); });
      }
    });
  }

  function init() {
    initPresets();
    document.getElementById('generateBtn').addEventListener('click', async function () {
      var btn = this;
      btn.disabled = true;
      btn.textContent = 'erstelle kit …';
      try {
        var kit = await buildKit();
        downloadBlob(kit.zipBlob, 'laura-kit.zip');
        renderResult(kit.kitId, kit.folder);
      } catch (err) {
        console.error(err);
        alert('kit-erstellung fehlgeschlagen: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.textContent = 'kit erstellen & herunterladen';
      }
    });
  }

  document.addEventListener('DOMContentLoaded', init);
})();
