# Imposter

Music streaming app. One Node.js server serves the listener app, the Studio (admin) and the API.
MP3 tracks and cover images are stored in PostgreSQL. Changes sync live to every open browser
through server-sent events.

## Run locally

    npm install
    export DATABASE_URL=postgres://user:pass@localhost:5432/imposter
    export ADMIN_KEY=choose-a-long-secret
    npm start

Open http://localhost:3000. Open http://localhost:3000/#studio to manage music (enter the admin key).

## Publish tracks

Tracks are published as MP3 files. In the Studio, upload one MP3 (details are read from its tags) or a ZIP/folder of MP3s as an album.

## Player features

- Queue: "+ Queue" adds a track to the end, "Next" plays it after the current track. Reorder, play or remove items on the Now Playing page.
- Smart shuffle (S): no repeats until the list is used up, avoids playing the same artist or album back to back, and favours liked songs and songs not played recently.
- Repeat off / all / one (R), previous (restarts the track after 3 seconds), seek, volume.
- Likes (L) with a Liked filter, recently played history, sleep timer (15, 30, 60 minutes or end of track).
- Keyboard: space play/pause, ←/→ seek 5 s (shift for 30 s), ↑/↓ volume, N/P next and previous.
- Lock-screen and headphone controls through the Media Session API.
- Resumes the last track and position after reloading the page (paused, no autoplay).

## Import an album folder

    npm run import -- ./path/to/album https://your-app.onrender.com "your-admin-key" "Album name"

Reads tags (title, artist, music director, track number, cover art) and removes "- Masstamilan".

## Deploy on Render

1. Push this folder to a GitHub repository.
2. In Render: New → Blueprint → select the repository. This creates the web service and the database.
3. In the web service's Environment settings, set ADMIN_KEY to a long secret (12+ characters).
4. Open the service URL. Studio is at /#studio.

Notes:
- Free Render databases expire after 30 days and free web services sleep when idle. Upgrade the
  plans before using this for real listeners.
- Audio is stored in the database. The free database holds about 1 GB, enough for a few hundred
  albums. Larger libraries should move audio to object storage such as Cloudflare R2.
- Set PGSSL=true only if your database connection requires SSL.

## API

| Method | Path | Who | What |
|---|---|---|---|
| GET | /api/tracks, /api/albums | everyone | list |
| POST / PATCH / DELETE | /api/tracks, /api/albums | admin | create, edit, delete |
| POST | /api/upload | admin | upload an audio or image file |
| GET | /files/:id | everyone | stream a file (supports seeking) |
| DELETE | /api/files/:id | admin | delete a file |
| GET | /api/events | everyone | live change events (SSE) |
| GET / PUT / DELETE | /api/subs/:clientId | listener | subscription plan |
| GET | /api/me | everyone | whether the admin key is valid |
