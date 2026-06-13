# YouTube Metadata Helper — Server Edition

A Node.js/Express server that uses the **YouTube Data API v3** with real OAuth 2.0 authentication. No scraping, no proxies — just the official API.

---

## Setup

### 1. Install dependencies

```bash
npm install
```

### 2. Create a Google Cloud project & credentials

1. Go to [console.cloud.google.com](https://console.cloud.google.com)
2. Create a new project (or use an existing one)
3. Enable the **YouTube Data API v3**:
   - APIs & Services → Library → search "YouTube Data API v3" → Enable
4. Create OAuth 2.0 credentials:
   - APIs & Services → Credentials → Create Credentials → OAuth client ID
   - Application type: **Web application**
   - Authorized redirect URIs: add `http://localhost:3000/auth/callback`
   - Copy the **Client ID** and **Client Secret**

### 3. Configure environment

```bash
cp .env.example .env
```

Edit `.env` and fill in:

```
GOOGLE_CLIENT_ID=your_client_id_here
GOOGLE_CLIENT_SECRET=your_client_secret_here
REDIRECT_URI=http://localhost:3000/auth/callback
SESSION_SECRET=some-random-long-string
PORT=3000
```

### 4. Run

```bash
node server.js
```

Open [http://localhost:3000](http://localhost:3000)

---

## How it works

1. User clicks "Sign in with Google" → OAuth 2.0 flow via Google
2. After consent, tokens are stored in the server session
3. `/api/search?q=...` — calls `youtube.search.list` with the authenticated client
4. `/api/video/:id` — calls `youtube.videos.list` to get title, description, tags, and stats
5. User edits metadata and copies it to YouTube Studio

## Scopes requested

- `youtube.readonly` — for searching and reading video metadata
- `youtube.upload` — included in case you extend this to upload later
- `youtube.force-ssl` — required by some YouTube API operations

## Deploying to production

- Set `REDIRECT_URI` to your public domain: `https://yourdomain.com/auth/callback`
- Register that URI in Google Cloud Console under your OAuth client
- Set `SESSION_SECRET` to a long random string
- Use a proper session store (e.g. `connect-redis`) instead of the default in-memory store
