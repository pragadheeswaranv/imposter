'use strict';
/*
  Import a folder of MP3 files as one album.
  Reads tags for title, artist, music director (composer), album, track number and embedded cover.
  Removes "- Masstamilan" from names.

  Usage:
    node scripts/import-folder.js <folder> <server-url> <admin-key> [album name]
  Example:
    node scripts/import-folder.js ./Jailer-2 https://imposter.onrender.com "my-key" "Jailer 2"
*/
const fs = require('fs');
const path = require('path');
const { parseFile } = require('music-metadata');

const [, , folder, serverUrl, adminKey, albumArg] = process.argv;
if (!folder || !serverUrl || !adminKey) {
  console.error('Usage: node scripts/import-folder.js <folder> <server-url> <admin-key> [album name]');
  process.exit(1);
}
const AUDIO = ['.mp3'];
const clean = s => String(s || '').replace(/\s*-\s*mass\s*tamilan\b/ig, '').replace(/\s+/g, ' ').trim();
const common = arr => {
  const m = {}; arr.forEach(x => { if (x) m[x] = (m[x] || 0) + 1; });
  return Object.keys(m).sort((a, b) => m[b] - m[a])[0] || '';
};
const first = s => String(s || '').split(',')[0].trim();

async function api(method, url, body, isForm) {
  const headers = { 'x-admin-key': adminKey };
  if (!isForm && body) headers['content-type'] = 'application/json';
  const r = await fetch(serverUrl + url, { method, headers, body: isForm ? body : (body ? JSON.stringify(body) : undefined) });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`${method} ${url}: ${j.error || r.status}`);
  return j;
}
async function uploadFile(buf, name, mime) {
  const f = new FormData();
  f.append('file', new Blob([buf], { type: mime }), name);
  return api('POST', '/api/upload', f, true);
}

(async () => {
  const files = fs.readdirSync(folder).filter(f => AUDIO.includes(path.extname(f).toLowerCase())).sort();
  if (!files.length) { console.error('No audio files found in', folder); process.exit(1); }

  const tracks = [];
  for (const name of files) {
    const full = path.join(folder, name);
    const meta = await parseFile(full, { duration: false, skipCovers: false }).catch(() => null);
    const c = (meta && meta.common) || {};
    tracks.push({
      file: full, name,
      ext: path.extname(name).slice(1).toLowerCase(),
      title: clean(c.title) || clean(path.basename(name, path.extname(name))),
      artist: clean((c.artists && c.artists.join(', ')) || c.artist),
      md: clean(c.composer && c.composer.join(', ')),
      album: clean(c.album),
      trackNo: c.track && c.track.no ? c.track.no : 0,
      picture: c.picture && c.picture[0] ? c.picture[0] : null,
    });
  }
  tracks.sort((a, b) => (a.trackNo - b.trackNo) || a.name.localeCompare(b.name, undefined, { numeric: true }));

  const albumName = clean(albumArg) || common(tracks.map(t => t.album)) || clean(path.basename(folder));
  const albumArtist = common(tracks.map(t => first(t.artist))) || 'Various artists';
  const albumMd = common(tracks.map(t => first(t.md)));
  const pic = tracks.find(t => t.picture);

  let cover = null;
  if (pic) {
    const ext = pic.picture.format.includes('png') ? 'png' : 'jpg';
    const up = await uploadFile(pic.picture.data, `cover.${ext}`, pic.picture.format);
    cover = up;
  }
  const album = await api('POST', '/api/albums', {
    title: albumName, artist: albumArtist, md: albumMd,
    cover: cover ? cover.url : null, coverId: cover ? cover.id : null,
  });
  console.log(`Album "${albumName}" created (${tracks.length} tracks)`);

  for (const t of tracks) {
    const audio = await uploadFile(fs.readFileSync(t.file), t.name, 'audio/mpeg');
    await api('POST', '/api/tracks', {
      title: t.title, artist: t.artist || albumArtist, md: t.md || albumMd, genre: 'Pop',
      albumId: album.id, trackNo: t.trackNo || 0,
      audio: audio.url, audioId: audio.id,
      bpm: 100, root: 57, scale: 'min', wave: 'triangle', g: 0, e: '🎵',
    });
    console.log(`  + ${t.trackNo || ''} ${t.title}`);
  }
  console.log('Done.');
})().catch(e => { console.error('Import failed:', e.message); process.exit(1); });
