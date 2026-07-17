/*
 * Minimal, dependency-free ZIP writer — STORE only (no compression).
 * Good enough for a handful of small files bundled client-side. Avoids
 * pulling in a third-party zip library for a privacy tool that should be
 * auditable in one read.
 */
(function (global) {
  var CRC_TABLE = (function () {
    var table = new Uint32Array(256);
    for (var n = 0; n < 256; n++) {
      var c = n;
      for (var k = 0; k < 8; k++) {
        c = (c & 1) ? (0xEDB88320 ^ (c >>> 1)) : (c >>> 1);
      }
      table[n] = c >>> 0;
    }
    return table;
  })();

  function crc32(bytes) {
    var crc = 0xFFFFFFFF;
    for (var i = 0; i < bytes.length; i++) {
      crc = CRC_TABLE[(crc ^ bytes[i]) & 0xFF] ^ (crc >>> 8);
    }
    return (crc ^ 0xFFFFFFFF) >>> 0;
  }

  function dosDateTime(date) {
    var time = ((date.getHours() & 0x1F) << 11) | ((date.getMinutes() & 0x3F) << 5) | ((date.getSeconds() >> 1) & 0x1F);
    var day = (((date.getFullYear() - 1980) & 0x7F) << 9) | (((date.getMonth() + 1) & 0xF) << 5) | (date.getDate() & 0x1F);
    return { time: time & 0xFFFF, date: day & 0xFFFF };
  }

  function utf8(str) { return new TextEncoder().encode(str); }

  function u16(v) { return [v & 0xFF, (v >>> 8) & 0xFF]; }
  function u32(v) { return [v & 0xFF, (v >>> 8) & 0xFF, (v >>> 16) & 0xFF, (v >>> 24) & 0xFF]; }

  function concatBytes(chunks) {
    var total = chunks.reduce(function (n, c) { return n + c.length; }, 0);
    var out = new Uint8Array(total);
    var offset = 0;
    chunks.forEach(function (c) { out.set(c, offset); offset += c.length; });
    return out;
  }

  /**
   * @param {Array<{name: string, data: Uint8Array}>} files
   * @returns {Blob}
   */
  function buildZip(files) {
    var now = new Date();
    var dt = dosDateTime(now);
    var localParts = [];
    var centralParts = [];
    var offset = 0;

    files.forEach(function (f) {
      var nameBytes = utf8(f.name);
      var data = f.data;
      var crc = crc32(data);
      var size = data.length;

      var localHeader = new Uint8Array([
        0x50, 0x4B, 0x03, 0x04,
        ...u16(20), ...u16(0), ...u16(0),
        ...u16(dt.time), ...u16(dt.date),
        ...u32(crc), ...u32(size), ...u32(size),
        ...u16(nameBytes.length), ...u16(0),
      ]);
      var local = concatBytes([localHeader, nameBytes, data]);
      localParts.push(local);

      var centralHeader = new Uint8Array([
        0x50, 0x4B, 0x01, 0x02,
        ...u16(20), ...u16(20), ...u16(0), ...u16(0),
        ...u16(dt.time), ...u16(dt.date),
        ...u32(crc), ...u32(size), ...u32(size),
        ...u16(nameBytes.length), ...u16(0), ...u16(0),
        ...u16(0), ...u16(0), ...u32(0),
        ...u32(offset),
      ]);
      centralParts.push(concatBytes([centralHeader, nameBytes]));

      offset += local.length;
    });

    var centralDir = concatBytes(centralParts);
    var localDir = concatBytes(localParts);

    var eocd = new Uint8Array([
      0x50, 0x4B, 0x05, 0x06,
      ...u16(0), ...u16(0),
      ...u16(files.length), ...u16(files.length),
      ...u32(centralDir.length), ...u32(localDir.length),
      ...u16(0),
    ]);

    return new Blob([localDir, centralDir, eocd], { type: 'application/zip' });
  }

  global.MiniZip = { buildZip: buildZip, crc32: crc32 };
})(window);
