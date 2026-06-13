require('dotenv').config();
const express = require('express');
const session = require('express-session');
const { google } = require('googleapis');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: process.env.SESSION_SECRET || 'yt-metadata-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

// ─── Multer — store uploads in /tmp ────────────────────────────────────────────
const upload = multer({
  dest: '/tmp/yt-uploads/',
  limits: { fileSize: 10 * 1024 * 1024 * 1024 }, // 10 GB max
});

// Make sure upload dir exists
fs.mkdirSync('/tmp/yt-uploads/', { recursive: true });

// ─── OAuth2 Client ─────────────────────────────────────────────────────────────
function getOAuth2Client() {
  return new google.auth.OAuth2(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    process.env.REDIRECT_URI || `http://localhost:${process.env.PORT || 3000}/auth/callback`
  );
}

function getAuthedClient(req) {
  const oauth2Client = getOAuth2Client();
  oauth2Client.setCredentials(req.session.tokens);
  oauth2Client.on('tokens', (tokens) => {
    req.session.tokens = { ...req.session.tokens, ...tokens };
  });
  return oauth2Client;
}

// ─── Auth Routes ───────────────────────────────────────────────────────────────
app.get('/auth/login', (req, res) => {
  const oauth2Client = getOAuth2Client();
  const scopes = [
    'https://www.googleapis.com/auth/youtube.readonly',
    'https://www.googleapis.com/auth/youtube.upload',
    'https://www.googleapis.com/auth/youtube.force-ssl',
  ];
  const url = oauth2Client.generateAuthUrl({
    access_type: 'offline',
    scope: scopes,
    prompt: 'consent',
  });
  res.redirect(url);
});

app.get('/auth/callback', async (req, res) => {
  const { code, error } = req.query;
  if (error) return res.redirect('/?auth_error=' + encodeURIComponent(error));
  try {
    const oauth2Client = getOAuth2Client();
    const { tokens } = await oauth2Client.getToken(code);
    req.session.tokens = tokens;
    res.redirect('/?auth=success');
  } catch (err) {
    console.error('Token exchange error:', err.message);
    res.redirect('/?auth_error=token_exchange_failed');
  }
});

app.get('/auth/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.get('/auth/status', (req, res) => {
  res.json({ authenticated: !!req.session.tokens });
});

// ─── API: Search Videos ────────────────────────────────────────────────────────
app.get('/api/search', async (req, res) => {
  const { q } = req.query;
  if (!q) return res.status(400).json({ error: 'Missing query' });
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const youtube = google.youtube({ version: 'v3', auth: getAuthedClient(req) });
    const response = await youtube.search.list({
      part: ['snippet'],
      q,
      type: ['video'],
      maxResults: 5,
      order: 'relevance',
    });

    const videos = response.data.items.map(item => ({
      videoId: item.id.videoId,
      title: item.snippet.title,
      channelTitle: item.snippet.channelTitle,
      thumbnail: item.snippet.thumbnails?.medium?.url,
      publishedAt: item.snippet.publishedAt,
    }));

    res.json({ videos });
  } catch (err) {
    console.error('Search error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── API: Get Video Metadata ───────────────────────────────────────────────────
app.get('/api/video/:videoId', async (req, res) => {
  const { videoId } = req.params;
  if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });

  try {
    const youtube = google.youtube({ version: 'v3', auth: getAuthedClient(req) });
    const response = await youtube.videos.list({
      part: ['snippet', 'statistics', 'contentDetails'],
      id: [videoId],
    });

    if (!response.data.items?.length) return res.status(404).json({ error: 'Video not found' });

    const video = response.data.items[0];
    const snippet = video.snippet;

    res.json({
      videoId,
      title: snippet.title,
      description: snippet.description,
      tags: snippet.tags || [],
      channelTitle: snippet.channelTitle,
      publishedAt: snippet.publishedAt,
      thumbnail: snippet.thumbnails?.maxres?.url || snippet.thumbnails?.high?.url,
      statistics: video.statistics,
      categoryId: snippet.categoryId,
    });
  } catch (err) {
    console.error('Video fetch error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// ─── API: Upload Video ─────────────────────────────────────────────────────────
app.post('/api/upload',
  upload.fields([
    { name: 'video', maxCount: 1 },
    { name: 'thumbnail', maxCount: 1 }
  ]),
  async (req, res) => {
    if (!req.session.tokens) return res.status(401).json({ error: 'Not authenticated' });

    const videoFile = req.files?.video?.[0];
    const thumbnailFile = req.files?.thumbnail?.[0];

    if (!videoFile) return res.status(400).json({ error: 'No video file provided' });

    const { title, description, tags, privacyStatus, categoryId } = req.body;

    // Set up SSE for progress streaming
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.flushHeaders();

    const send = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

    try {
      const youtube = google.youtube({ version: 'v3', auth: getAuthedClient(req) });

      send({ stage: 'uploading', message: 'Uploading video to YouTube…', progress: 0 });

      const videoSize = fs.statSync(videoFile.path).size;
      let uploadedBytes = 0;

      const response = await youtube.videos.insert({
        part: ['snippet', 'status'],
        requestBody: {
          snippet: {
            title: title || 'My Video',
            description: description || '',
            tags: tags ? tags.split(',').map(t => t.trim()).filter(Boolean) : [],
            categoryId: categoryId || '22', // People & Blogs default
          },
          status: {
            privacyStatus: privacyStatus || 'private',
          },
        },
        media: {
          body: fs.createReadStream(videoFile.path),
        },
      }, {
        onUploadProgress: (evt) => {
          uploadedBytes = evt.bytesRead || 0;
          const pct = videoSize > 0 ? Math.round((uploadedBytes / videoSize) * 100) : 0;
          send({ stage: 'uploading', message: `Uploading… ${pct}%`, progress: pct });
        },
      });

      const uploadedVideoId = response.data.id;
      send({ stage: 'uploaded', message: 'Video uploaded!', progress: 100, videoId: uploadedVideoId });

      // Upload thumbnail if provided
      if (thumbnailFile && uploadedVideoId) {
        send({ stage: 'thumbnail', message: 'Setting thumbnail…', progress: 100 });
        try {
          await youtube.thumbnails.set({
            videoId: uploadedVideoId,
            media: {
              mimeType: thumbnailFile.mimetype,
              body: fs.createReadStream(thumbnailFile.path),
            },
          });
          send({ stage: 'thumbnail', message: 'Thumbnail set!', progress: 100 });
        } catch (thumbErr) {
          console.error('Thumbnail error:', thumbErr.message);
          send({ stage: 'thumbnail_warn', message: 'Video uploaded, but thumbnail failed: ' + thumbErr.message });
        }
      }

      send({
        stage: 'done',
        message: 'All done!',
        videoId: uploadedVideoId,
        url: `https://www.youtube.com/watch?v=${uploadedVideoId}`,
        studioUrl: `https://studio.youtube.com/video/${uploadedVideoId}/edit`,
      });

    } catch (err) {
      console.error('Upload error:', err.message);
      send({ stage: 'error', message: err.message });
    } finally {
      // Clean up temp files
      try { fs.unlinkSync(videoFile.path); } catch {}
      if (thumbnailFile) { try { fs.unlinkSync(thumbnailFile.path); } catch {} }
      res.end();
    }
  }
);

// ─── Start ─────────────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});